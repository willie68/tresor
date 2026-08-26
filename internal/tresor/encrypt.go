package tresor

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/willie68/gowillie68/pkg/fileutils"
)

func Encrypt(opts EncryptOptions) error {
	mode := strings.ToLower(strings.TrimSpace(opts.IfExists))
	if mode == "" {
		mode = "sync"
	}
	if mode != "sync" && mode != "append" {
		return fmt.Errorf("invalid if-exists mode %q (use: sync|append)", opts.IfExists)
	}

	_, statErr := os.Stat(opts.ContainerPath)
	exists := statErr == nil
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return fmt.Errorf("check container file: %w", statErr)
	}

	progressf(opts.ProgressWriter, "encrypt: mode=%s container=%q", mode, opts.ContainerPath)

	if !exists || mode == "sync" {
		return encryptSync(opts)
	}

	return encryptAppend(opts)
}

// removeSources securely removes the source paths based on encryption options
func removeSources(opts EncryptOptions, roots []string) error {
	if !opts.RemoveSources {
		return nil
	}

	for _, root := range roots {
		var removeErr error
		if opts.SecureRemove {
			removeErr = fileutils.SecureRemoveAll(root, fileutils.WithQuickMode(false), fileutils.WithPasses(3))
		} else {
			removeErr = fileutils.SecureRemoveAll(root, fileutils.WithQuickMode(true))
		}
		if removeErr != nil {
			return fmt.Errorf("remove source %q: %w", root, removeErr)
		}
	}
	return nil
}

func encryptSync(opts EncryptOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}
	if len(opts.Inputs) == 0 {
		return errors.New("at least one input path is required")
	}

	roots, err := normalizeInputRoots(opts.Inputs)
	if err != nil {
		return err
	}

	// Create container header once (shared across all containers)
	hdr := containerHeader{
		Magic:       headerMagic,
		Version:     containerVersion,
		KDFMemoryKB: kdfMemoryKB,
		KDFTime:     kdfIterations,
		KDFThreads:  kdfParallelism,
	}
	if _, err := rand.Read(hdr.Salt[:]); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	aead, err := buildAEAD(opts.Password, hdr)
	if err != nil {
		return err
	}

	cw := newContainerWriter(opts.ContainerPath, opts.MaxContainerSize)
	defer cw.cleanup()

	// Initialize first container (don't increment index, start at 0)
	f, err := cw.ensureContainerOpen()
	if err != nil {
		return err
	}
	if err := writeHeader(f, hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	cw.currentSize = int64(headerSize)

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	index := archiveIndex{ChunkSize: chunkSize}
	seen := make(map[string]struct{})
	encryptedFiles := 0

	for _, root := range roots {
		progressf(opts.ProgressWriter, "encrypt: scanning root %q", root)
		walkErr := encryptSyncWalkDirMulti(root, cwd, cw, hdr, aead, &index, seen, opts.ProgressWriter, &encryptedFiles)
		if walkErr != nil {
			return walkErr
		}
	}

	// Write index to main container (never gets split)
	mainFile := cw.files[0]
	if mainFile == nil {
		var err error
		mainFile, err = cw.ensureContainerOpen()
		if err != nil {
			return err
		}
	}
	if err := writeContainerIndex(mainFile, aead, index); err != nil {
		return err
	}

	if err := cw.close(); err != nil {
		return fmt.Errorf("close containers: %w", err)
	}

	if err := cw.finalize(); err != nil {
		return err
	}

	if err := removeSources(opts, roots); err != nil {
		return err
	}

	progressf(opts.ProgressWriter, "encrypt: done (%d files)", encryptedFiles)

	return nil
}

func encryptSyncWalkDir(root, cwd string, out *os.File, aead cipher.AEAD, index *archiveIndex, seen map[string]struct{}, pw io.Writer, fileCount *int) error {
	return filepath.WalkDir(root, func(pathFs string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return encryptSyncProcessEntry(pathFs, d, cwd, out, aead, index, seen, pw, fileCount)
	})
}

func encryptSyncProcessEntry(pathFs string, d fs.DirEntry, cwd string, out *os.File, aead cipher.AEAD, index *archiveIndex, seen map[string]struct{}, pw io.Writer, fileCount *int) error {
	absPath, err := filepath.Abs(pathFs)
	if err != nil {
		return err
	}

	if _, ok := seen[absPath]; ok {
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	seen[absPath] = struct{}{}

	relPath, err := filepath.Rel(cwd, absPath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
		return fmt.Errorf("path %q is outside working directory", pathFs)
	}
	relPath = filepath.ToSlash(relPath)

	info, err := d.Info()
	if err != nil {
		return err
	}

	if d.IsDir() {
		index.Entries = append(index.Entries, archiveEntry{Path: relPath, Mode: uint32(info.Mode().Perm()), Type: entryTypeDir, ModTime: info.ModTime().Unix()})
		return nil
	}

	if !d.Type().IsRegular() {
		return nil
	}

	return encryptSyncProcessFile(absPath, relPath, info, out, aead, index, pw, fileCount)
}

func encryptSyncProcessFile(absPath, relPath string, info fs.FileInfo, out *os.File, aead cipher.AEAD, index *archiveIndex, pw io.Writer, fileCount *int) error {
	progressf(pw, "encrypt: processing %s", relPath)

	payload, err := preparePayload(absPath)
	if err != nil {
		return err
	}
	defer payload.cleanup()

	offset, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	dataLen, chunkCount, nonceSeed, err := encryptFileData(out, payload.reader, aead)
	if err != nil {
		return err
	}

	index.Entries = append(index.Entries, archiveEntry{
		Path:       relPath,
		Mode:       uint32(info.Mode().Perm()),
		Type:       entryTypeFile,
		Size:       payload.originalSize,
		ModTime:    info.ModTime().Unix(),
		StoredSize: payload.storedSize,
		Compressed: payload.compressed,
		DataOffset: uint64(offset),
		DataLength: dataLen,
		ChunkCount: chunkCount,
		NonceSeed:  nonceSeed,
	})
	*fileCount++
	return nil
}

// encryptSyncWalkDirMulti walks directory tree for multi-container encryption
func encryptSyncWalkDirMulti(root, cwd string, cw *containerWriter, hdr containerHeader, aead cipher.AEAD, index *archiveIndex, seen map[string]struct{}, pw io.Writer, fileCount *int) error {
	return filepath.WalkDir(root, func(pathFs string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return encryptSyncProcessEntryMulti(pathFs, d, cwd, cw, hdr, aead, index, seen, pw, fileCount)
	})
}

// encryptSyncProcessEntryMulti processes a single file/dir for multi-container encryption
func encryptSyncProcessEntryMulti(pathFs string, d fs.DirEntry, cwd string, cw *containerWriter, hdr containerHeader, aead cipher.AEAD, index *archiveIndex, seen map[string]struct{}, pw io.Writer, fileCount *int) error {
	absPath, err := filepath.Abs(pathFs)
	if err != nil {
		return err
	}

	if _, ok := seen[absPath]; ok {
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	seen[absPath] = struct{}{}

	relPath, err := filepath.Rel(cwd, absPath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
		return fmt.Errorf("path %q is outside working directory", pathFs)
	}
	relPath = filepath.ToSlash(relPath)

	info, err := d.Info()
	if err != nil {
		return err
	}

	if d.IsDir() {
		index.Entries = append(index.Entries, archiveEntry{Path: relPath, Mode: uint32(info.Mode().Perm()), Type: entryTypeDir, ModTime: info.ModTime().Unix()})
		return nil
	}

	if !d.Type().IsRegular() {
		return nil
	}

	return encryptSyncProcessFileMulti(absPath, relPath, info, cw, hdr, aead, index, pw, fileCount)
}

// encryptSyncProcessFileMulti encrypts a single file with multi-container support
func encryptSyncProcessFileMulti(absPath, relPath string, info fs.FileInfo, cw *containerWriter, hdr containerHeader, aead cipher.AEAD, index *archiveIndex, pw io.Writer, fileCount *int) error {
	progressf(pw, "encrypt: processing %s", relPath)

	payload, err := preparePayload(absPath)
	if err != nil {
		return err
	}
	defer payload.cleanup()

	// Estimate encrypted size: each chunk is (chunkSize + 16-byte AEAD tag)
	estimatedEncryptedSize := ((payload.storedSize + int64(chunkSize) - 1) / int64(chunkSize)) * (int64(chunkSize) + 16)

	// If this file doesn't fit in current container, switch to next
	if cw.maxSize > 0 && cw.currentSize+estimatedEncryptedSize > cw.maxSize {
		// Only switch if not empty, to avoid wasting containers
		if cw.currentSize > int64(headerSize) {
			if err := cw.switchToNextContainer(hdr); err != nil {
				return err
			}
		}
	}

	// Get current position before writing
	offset, err := cw.getCurrentOffset()
	if err != nil {
		return err
	}

	// Encrypt file data (stays in current container)
	dataLen, chunkCount, nonceSeed, err := encryptFileDataMulti(payload.reader, cw, hdr, aead)
	if err != nil {
		return err
	}

	index.Entries = append(index.Entries, archiveEntry{
		Path:           relPath,
		Mode:           uint32(info.Mode().Perm()),
		Type:           entryTypeFile,
		Size:           payload.originalSize,
		ModTime:        info.ModTime().Unix(),
		StoredSize:     payload.storedSize,
		Compressed:     payload.compressed,
		DataOffset:     uint64(offset),
		DataLength:     dataLen,
		ChunkCount:     chunkCount,
		NonceSeed:      nonceSeed,
		ContainerIndex: cw.currentIndex,
	})
	*fileCount++
	return nil
}

// encryptFileDataMulti writes encrypted file data to current container
// File stays in current container - caller handles container switching
func encryptFileDataMulti(in io.Reader, cw *containerWriter, hdr containerHeader, aead cipher.AEAD) (uint64, uint32, [8]byte, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 0, 0, [8]byte{}, err
	}

	buf := make([]byte, chunkSize)
	var chunkCount uint32
	var totalCipher uint64

	for {
		n, readErr := io.ReadFull(in, buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return 0, 0, [8]byte{}, fmt.Errorf("read payload: %w", readErr)
		}

		if n < int(chunkSize) {
			for i := n; i < int(chunkSize); i++ {
				buf[i] = 0
			}
		}

		nonce := chunkNonce(seed, chunkCount)
		ciphertext := aead.Seal(nil, nonce[:], buf, nil)

		// Write chunk to current container
		if err := cw.write(ciphertext); err != nil {
			return 0, 0, [8]byte{}, err
		}
		totalCipher += uint64(len(ciphertext))
		chunkCount++

		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	return totalCipher, chunkCount, seed, nil
}

func encryptAppend(opts EncryptOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}
	if len(opts.Inputs) == 0 {
		return errors.New("at least one input path is required")
	}

	roots, err := normalizeInputRoots(opts.Inputs)
	if err != nil {
		return err
	}

	hdr, index, footer, err := readContainerIndex(opts.ContainerPath, opts.Password)
	if err != nil {
		return err
	}

	aead, err := buildAEAD(opts.Password, hdr)
	if err != nil {
		return err
	}

	tmpPath := opts.ContainerPath + ".tmp"
	_ = os.Remove(tmpPath)

	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

	if err := writeHeader(out, hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	if err := copyExistingPayload(opts.ContainerPath, out, footer); err != nil {
		return err
	}

	entries := make([]archiveEntry, len(index.Entries))
	copy(entries, index.Entries)
	entryPos := make(map[string]int, len(entries))
	for i := range entries {
		entryPos[entries[i].Path] = i
	}

	if opts.OnFileConflict == nil {
		opts.OnFileConflict = promptFileConflict
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	stats := struct {
		added    int
		replaced int
		ignored  int
	}{}

	seen := make(map[string]struct{})
	for _, root := range roots {
		progressf(opts.ProgressWriter, "encrypt append: scanning root %q", root)
		walkErr := encryptAppendWalkDir(root, cwd, out, aead, &entries, entryPos, opts.OnFileConflict, opts.ProgressWriter, seen, &stats)
		if walkErr != nil {
			return walkErr
		}
	}

	finalIndex := archiveIndex{ChunkSize: chunkSize, Entries: entries}
	if err := writeContainerIndex(out, aead, finalIndex); err != nil {
		return err
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close container: %w", err)
	}
	if err := os.Rename(tmpPath, opts.ContainerPath); err != nil {
		return fmt.Errorf("finalize container: %w", err)
	}

	if err := removeSources(opts, roots); err != nil {
		return err
	}

	progressf(opts.ProgressWriter, "encrypt append: done (added=%d replaced=%d ignored=%d)", stats.added, stats.replaced, stats.ignored)

	return nil
}

func copyExistingPayload(containerPath string, out *os.File, footer containerFooter) error {
	in, err := os.Open(containerPath)
	if err != nil {
		return fmt.Errorf("open existing container: %w", err)
	}
	defer func() {
		_ = in.Close()
	}()

	if _, err := in.Seek(headerSize, io.SeekStart); err != nil {
		return fmt.Errorf("seek existing payload: %w", err)
	}
	if _, err := io.CopyN(out, in, int64(footer.IndexOffset)-headerSize); err != nil {
		return fmt.Errorf("copy existing payload: %w", err)
	}
	return nil
}

func encryptAppendWalkDir(root, cwd string, out *os.File, aead cipher.AEAD, entries *[]archiveEntry, entryPos map[string]int, conflictHandler FileConflictHandler, pw io.Writer, seen map[string]struct{}, stats *struct {
	added    int
	replaced int
	ignored  int
}) error {
	return filepath.WalkDir(root, func(pathFs string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		return encryptAppendProcessEntry(pathFs, d, cwd, out, aead, entries, entryPos, conflictHandler, pw, seen, stats)
	})
}

func encryptAppendProcessEntry(pathFs string, d fs.DirEntry, cwd string, out *os.File, aead cipher.AEAD, entries *[]archiveEntry, entryPos map[string]int, conflictHandler FileConflictHandler, pw io.Writer, seen map[string]struct{}, stats *struct {
	added    int
	replaced int
	ignored  int
}) error {
	absPath, err := filepath.Abs(pathFs)
	if err != nil {
		return err
	}

	if _, ok := seen[absPath]; ok {
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	seen[absPath] = struct{}{}

	relPath, err := filepath.Rel(cwd, absPath)
	if err != nil {
		return err
	}
	if strings.HasPrefix(relPath, "..") || filepath.IsAbs(relPath) {
		return fmt.Errorf("path %q is outside working directory", pathFs)
	}
	relPath = filepath.ToSlash(relPath)

	info, err := d.Info()
	if err != nil {
		return err
	}

	if d.IsDir() {
		if _, exists := entryPos[relPath]; !exists {
			entryPos[relPath] = len(*entries)
			*entries = append(*entries, archiveEntry{Path: relPath, Mode: uint32(info.Mode().Perm()), Type: entryTypeDir})
		}
		return nil
	}

	if !d.Type().IsRegular() {
		return nil
	}

	return encryptAppendProcessFile(absPath, relPath, info, out, aead, entries, entryPos, conflictHandler, pw, stats)
}

func encryptAppendProcessFile(absPath, relPath string, info fs.FileInfo, out *os.File, aead cipher.AEAD, entries *[]archiveEntry, entryPos map[string]int, conflictHandler FileConflictHandler, pw io.Writer, stats *struct {
	added    int
	replaced int
	ignored  int
}) error {
	targetPath := relPath
	replaced := false
	if _, exists := entryPos[targetPath]; exists {
		action, err := conflictHandler(targetPath)
		if err != nil {
			return err
		}
		switch action {
		case ConflictIgnore:
			stats.ignored++
			progressf(pw, "encrypt append: ignore existing %s", targetPath)
			return nil
		case ConflictOverwrite:
			replaced = true
			progressf(pw, "encrypt append: overwrite %s", targetPath)
		case ConflictRename:
			targetPath = nextArchiveRenamedPath(targetPath, entryPos)
			progressf(pw, "encrypt append: conflict rename %q -> %q", relPath, targetPath)
		default:
			return fmt.Errorf("unknown conflict action for %q", targetPath)
		}
	}

	progressf(pw, "encrypt append: processing %s", targetPath)

	payload, err := preparePayload(absPath)
	if err != nil {
		return err
	}
	defer payload.cleanup()

	offset, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	dataLen, chunkCount, nonceSeed, err := encryptFileData(out, payload.reader, aead)
	if err != nil {
		return err
	}

	entry := archiveEntry{
		Path:       targetPath,
		Mode:       uint32(info.Mode().Perm()),
		Type:       entryTypeFile,
		Size:       payload.originalSize,
		ModTime:    info.ModTime().Unix(),
		StoredSize: payload.storedSize,
		Compressed: payload.compressed,
		DataOffset: uint64(offset),
		DataLength: dataLen,
		ChunkCount: chunkCount,
		NonceSeed:  nonceSeed,
	}

	if pos, exists := entryPos[targetPath]; exists {
		(*entries)[pos] = entry
		if replaced {
			stats.replaced++
		}
	} else {
		entryPos[targetPath] = len(*entries)
		*entries = append(*entries, entry)
		stats.added++
	}

	return nil
}

func encryptFileData(out *os.File, in io.Reader, aead cipher.AEAD) (uint64, uint32, [8]byte, error) {
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return 0, 0, [8]byte{}, err
	}

	buf := make([]byte, chunkSize)
	var chunkCount uint32
	var totalCipher uint64

	for {
		n, readErr := io.ReadFull(in, buf)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return 0, 0, [8]byte{}, fmt.Errorf("read payload: %w", readErr)
		}

		if n < int(chunkSize) {
			for i := n; i < int(chunkSize); i++ {
				buf[i] = 0
			}
		}

		nonce := chunkNonce(seed, chunkCount)
		ciphertext := aead.Seal(nil, nonce[:], buf, nil)
		written, err := out.Write(ciphertext)
		if err != nil {
			return 0, 0, [8]byte{}, fmt.Errorf("write encrypted chunk: %w", err)
		}
		totalCipher += uint64(written)
		chunkCount++

		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	return totalCipher, chunkCount, seed, nil
}
