package tresor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	headerMagic      uint32 = 0xA16F3D27
	footerMagic      uint32 = 0x7C9E21B4
	containerVersion uint16 = 1
	kdfMemoryKB      uint32 = 64 * 1024
	kdfIterations    uint32 = 3
	kdfParallelism   uint8  = 2
	keySize                 = 32
	saltSize                = 16
	chunkSize        uint32 = 64 * 1024
	aeadTagSize             = 16
	headerSize              = 31
)

const (
	entryTypeDir  uint8 = 1
	entryTypeFile uint8 = 2
)

type EncryptOptions struct {
	Password       string
	ContainerPath  string
	Inputs         []string
	RemoveSources  bool
	IfExists       string
	OnFileConflict FileConflictHandler
	ProgressWriter io.Writer
}

type DecryptOptions struct {
	Password        string
	ContainerPath   string
	RemoveContainer bool
	OnFileConflict  FileConflictHandler
	ProgressWriter  io.Writer
}

type ListOptions struct {
	Password      string
	ContainerPath string
}

type ListedEntry struct {
	Path  string
	IsDir bool
	Size  int64
}

type FileConflictAction int

const (
	ConflictIgnore FileConflictAction = iota + 1
	ConflictOverwrite
	ConflictRename
)

type FileConflictHandler func(targetPath string) (FileConflictAction, error)

type containerHeader struct {
	Magic       uint32
	Version     uint16
	KDFMemoryKB uint32
	KDFTime     uint32
	KDFThreads  uint8
	Salt        [saltSize]byte
}

type containerFooter struct {
	Magic       uint32
	IndexOffset uint64
	IndexLength uint64
	IndexNonce  [12]byte
}

type archiveIndex struct {
	ChunkSize uint32         `json:"chunk_size"`
	Entries   []archiveEntry `json:"entries"`
}

type archiveEntry struct {
	Path       string  `json:"path"`
	Mode       uint32  `json:"mode"`
	Type       uint8   `json:"type"`
	Size       int64   `json:"size"`
	StoredSize int64   `json:"stored_size,omitempty"`
	Compressed bool    `json:"compressed,omitempty"`
	DataOffset uint64  `json:"data_offset,omitempty"`
	DataLength uint64  `json:"data_length,omitempty"`
	ChunkCount uint32  `json:"chunk_count,omitempty"`
	NonceSeed  [8]byte `json:"nonce_seed,omitempty"`
}

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

	tmpPath := opts.ContainerPath + ".tmp"
	_ = os.Remove(tmpPath)

	out, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create container: %w", err)
	}
	defer func() {
		_ = out.Close()
	}()

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

	if err := writeHeader(out, hdr); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	aead, err := buildAEAD(opts.Password, hdr)
	if err != nil {
		return err
	}

	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	index := archiveIndex{ChunkSize: chunkSize}
	seen := make(map[string]struct{})
	encryptedFiles := 0

	for _, root := range roots {
		progressf(opts.ProgressWriter, "encrypt: scanning root %q", root)
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			absPath, err := filepath.Abs(path)
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
				return fmt.Errorf("path %q is outside working directory", path)
			}
			relPath = filepath.ToSlash(relPath)

			info, err := d.Info()
			if err != nil {
				return err
			}

			entry := archiveEntry{
				Path: relPath,
				Mode: uint32(info.Mode().Perm()),
			}

			if d.IsDir() {
				entry.Type = entryTypeDir
				index.Entries = append(index.Entries, entry)
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			progressf(opts.ProgressWriter, "encrypt: processing %s", relPath)

			payloadPath, originalSize, storedSize, compressed, cleanup, err := preparePayload(absPath)
			if err != nil {
				return err
			}
			defer cleanup()

			offset, err := out.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}

			dataLen, chunkCount, nonceSeed, err := encryptFileData(out, payloadPath, aead)
			if err != nil {
				return err
			}

			entry.Type = entryTypeFile
			entry.Size = originalSize
			entry.StoredSize = storedSize
			entry.Compressed = compressed
			entry.DataOffset = uint64(offset)
			entry.DataLength = dataLen
			entry.ChunkCount = chunkCount
			entry.NonceSeed = nonceSeed
			index.Entries = append(index.Entries, entry)
			encryptedFiles++
			return nil
		})
		if err != nil {
			return fmt.Errorf("walk path %q: %w", root, err)
		}
	}

	indexBytes, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}

	var indexNonce [12]byte
	if _, err := rand.Read(indexNonce[:]); err != nil {
		return fmt.Errorf("generate index nonce: %w", err)
	}

	indexCipher := aead.Seal(nil, indexNonce[:], indexBytes, nil)
	indexOffset, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := out.Write(indexCipher); err != nil {
		return fmt.Errorf("write index ciphertext: %w", err)
	}

	footer := containerFooter{
		Magic:       footerMagic,
		IndexOffset: uint64(indexOffset),
		IndexLength: uint64(len(indexCipher)),
		IndexNonce:  indexNonce,
	}
	if err := writeFooter(out, footer); err != nil {
		return fmt.Errorf("write footer: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close container: %w", err)
	}

	if err := os.Rename(tmpPath, opts.ContainerPath); err != nil {
		return fmt.Errorf("finalize container: %w", err)
	}

	if opts.RemoveSources {
		for _, root := range roots {
			if err := os.RemoveAll(root); err != nil {
				return fmt.Errorf("remove source %q: %w", root, err)
			}
		}
	}

	progressf(opts.ProgressWriter, "encrypt: done (%d files)", encryptedFiles)

	return nil
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

	in, err := os.Open(opts.ContainerPath)
	if err != nil {
		return fmt.Errorf("open existing container: %w", err)
	}
	inOpen := true
	defer func() {
		if inOpen {
			_ = in.Close()
		}
	}()

	if _, err := in.Seek(headerSize, io.SeekStart); err != nil {
		return fmt.Errorf("seek existing payload: %w", err)
	}
	if _, err := io.CopyN(out, in, int64(footer.IndexOffset)-headerSize); err != nil {
		return fmt.Errorf("copy existing payload: %w", err)
	}
	if err := in.Close(); err != nil {
		return fmt.Errorf("close existing container: %w", err)
	}
	inOpen = false

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
	seen := make(map[string]struct{})
	addedFiles := 0
	replacedFiles := 0
	ignoredFiles := 0

	for _, root := range roots {
		progressf(opts.ProgressWriter, "encrypt append: scanning root %q", root)
		err := filepath.WalkDir(root, func(pathFs string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

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
					entry := archiveEntry{Path: relPath, Mode: uint32(info.Mode().Perm()), Type: entryTypeDir}
					entryPos[relPath] = len(entries)
					entries = append(entries, entry)
				}
				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			targetPath := relPath
			replaced := false
			if _, exists := entryPos[targetPath]; exists {
				action, err := opts.OnFileConflict(targetPath)
				if err != nil {
					return err
				}
				switch action {
				case ConflictIgnore:
					ignoredFiles++
					progressf(opts.ProgressWriter, "encrypt append: ignore existing %s", targetPath)
					return nil
				case ConflictOverwrite:
					// Keep target path.
					replaced = true
					progressf(opts.ProgressWriter, "encrypt append: overwrite %s", targetPath)
				case ConflictRename:
					targetPath = nextArchiveRenamedPath(targetPath, entryPos)
					progressf(opts.ProgressWriter, "encrypt append: conflict rename %q -> %q", relPath, targetPath)
				default:
					return fmt.Errorf("unknown conflict action for %q", targetPath)
				}
			}

			progressf(opts.ProgressWriter, "encrypt append: processing %s", targetPath)

			payloadPath, originalSize, storedSize, compressed, cleanup, err := preparePayload(absPath)
			if err != nil {
				return err
			}
			defer cleanup()

			offset, err := out.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}

			dataLen, chunkCount, nonceSeed, err := encryptFileData(out, payloadPath, aead)
			if err != nil {
				return err
			}

			entry := archiveEntry{
				Path:       targetPath,
				Mode:       uint32(info.Mode().Perm()),
				Type:       entryTypeFile,
				Size:       originalSize,
				StoredSize: storedSize,
				Compressed: compressed,
				DataOffset: uint64(offset),
				DataLength: dataLen,
				ChunkCount: chunkCount,
				NonceSeed:  nonceSeed,
			}

			if pos, exists := entryPos[targetPath]; exists {
				entries[pos] = entry
				if replaced {
					replacedFiles++
				}
			} else {
				entryPos[targetPath] = len(entries)
				entries = append(entries, entry)
				addedFiles++
			}

			return nil
		})
		if err != nil {
			return fmt.Errorf("walk path %q: %w", root, err)
		}
	}

	finalIndex := archiveIndex{ChunkSize: chunkSize, Entries: entries}
	indexBytes, err := json.Marshal(finalIndex)
	if err != nil {
		return fmt.Errorf("marshal index: %w", err)
	}

	var indexNonce [12]byte
	if _, err := rand.Read(indexNonce[:]); err != nil {
		return fmt.Errorf("generate index nonce: %w", err)
	}

	indexCipher := aead.Seal(nil, indexNonce[:], indexBytes, nil)
	indexOffset, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	if _, err := out.Write(indexCipher); err != nil {
		return fmt.Errorf("write index ciphertext: %w", err)
	}

	newFooter := containerFooter{
		Magic:       footerMagic,
		IndexOffset: uint64(indexOffset),
		IndexLength: uint64(len(indexCipher)),
		IndexNonce:  indexNonce,
	}
	if err := writeFooter(out, newFooter); err != nil {
		return fmt.Errorf("write footer: %w", err)
	}

	if err := out.Close(); err != nil {
		return fmt.Errorf("close container: %w", err)
	}
	if err := os.Rename(tmpPath, opts.ContainerPath); err != nil {
		return fmt.Errorf("finalize container: %w", err)
	}

	if opts.RemoveSources {
		for _, root := range roots {
			if err := os.RemoveAll(root); err != nil {
				return fmt.Errorf("remove source %q: %w", root, err)
			}
		}
	}

	progressf(opts.ProgressWriter, "encrypt append: done (added=%d replaced=%d ignored=%d)", addedFiles, replacedFiles, ignoredFiles)

	return nil
}

func readContainerIndex(containerPath, password string) (containerHeader, archiveIndex, containerFooter, error) {
	in, err := os.Open(containerPath)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, fmt.Errorf("open container: %w", err)
	}
	defer func() {
		_ = in.Close()
	}()

	hdr, err := readHeader(in)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
	}
	aead, err := buildAEAD(password, hdr)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
	}
	footer, err := readFooter(in)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
	}

	if _, err := in.Seek(int64(footer.IndexOffset), io.SeekStart); err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, fmt.Errorf("seek index: %w", err)
	}
	indexCipher := make([]byte, footer.IndexLength)
	if _, err := io.ReadFull(in, indexCipher); err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, fmt.Errorf("read index ciphertext: %w", err)
	}
	indexPlain, err := aead.Open(nil, footer.IndexNonce[:], indexCipher, nil)
	if err != nil {
		if isAuthFailure(err) {
			return containerHeader{}, archiveIndex{}, containerFooter{}, errors.New("invalid password or corrupted container")
		}
		return containerHeader{}, archiveIndex{}, containerFooter{}, fmt.Errorf("decrypt index: %w", err)
	}

	var index archiveIndex
	if err := json.Unmarshal(indexPlain, &index); err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, fmt.Errorf("unmarshal index: %w", err)
	}
	if index.ChunkSize == 0 {
		return containerHeader{}, archiveIndex{}, containerFooter{}, errors.New("invalid chunk size in index")
	}

	return hdr, index, footer, nil
}

func nextArchiveRenamedPath(targetPath string, existing map[string]int) string {
	dir := path.Dir(targetPath)
	base := path.Base(targetPath)
	ext := path.Ext(base)
	name := strings.TrimSuffix(base, ext)
	for i := 1; ; i++ {
		candidateBase := fmt.Sprintf("%s (%04d)%s", name, i, ext)
		candidate := candidateBase
		if dir != "." {
			candidate = dir + "/" + candidateBase
		}
		if _, ok := existing[candidate]; !ok {
			return candidate
		}
	}
}

func Decrypt(opts DecryptOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}

	progressf(opts.ProgressWriter, "decrypt: container=%q", opts.ContainerPath)

	in, err := os.Open(opts.ContainerPath)
	if err != nil {
		return fmt.Errorf("open container: %w", err)
	}
	containerOpen := true
	defer func() {
		if containerOpen {
			_ = in.Close()
		}
	}()

	hdr, err := readHeader(in)
	if err != nil {
		return err
	}
	aead, err := buildAEAD(opts.Password, hdr)
	if err != nil {
		return err
	}

	footer, err := readFooter(in)
	if err != nil {
		return err
	}

	if _, err := in.Seek(int64(footer.IndexOffset), io.SeekStart); err != nil {
		return fmt.Errorf("seek index: %w", err)
	}
	indexCipher := make([]byte, footer.IndexLength)
	if _, err := io.ReadFull(in, indexCipher); err != nil {
		return fmt.Errorf("read index ciphertext: %w", err)
	}

	indexPlain, err := aead.Open(nil, footer.IndexNonce[:], indexCipher, nil)
	if err != nil {
		if isAuthFailure(err) {
			return errors.New("invalid password or corrupted container")
		}
		return fmt.Errorf("decrypt index: %w", err)
	}

	var index archiveIndex
	if err := json.Unmarshal(indexPlain, &index); err != nil {
		return fmt.Errorf("unmarshal index: %w", err)
	}
	if index.ChunkSize == 0 {
		return errors.New("invalid chunk size in index")
	}

	decryptedFiles := 0
	skippedFiles := 0

	for _, entry := range index.Entries {
		target, err := safeOutputPath(entry.Path)
		if err != nil {
			return err
		}
		switch entry.Type {
		case entryTypeDir:
			if err := os.MkdirAll(target, fs.FileMode(entry.Mode)); err != nil {
				return fmt.Errorf("create directory %q: %w", target, err)
			}
		case entryTypeFile:
			resolvedTarget, skip, err := resolveFileConflictTarget(target, opts.OnFileConflict)
			if err != nil {
				return err
			}
			if skip {
				skippedFiles++
				progressf(opts.ProgressWriter, "decrypt: ignore existing %s", target)
				continue
			}
			progressf(opts.ProgressWriter, "decrypt: restoring %s", resolvedTarget)
			if err := decryptFileEntry(in, aead, index.ChunkSize, resolvedTarget, entry); err != nil {
				return err
			}
			decryptedFiles++
		default:
			return fmt.Errorf("unknown entry type %d for %q", entry.Type, entry.Path)
		}
	}

	if err := in.Close(); err != nil {
		return fmt.Errorf("close container file: %w", err)
	}
	containerOpen = false

	if opts.RemoveContainer {
		if err := os.Remove(opts.ContainerPath); err != nil {
			return fmt.Errorf("remove container file: %w", err)
		}
	}

	progressf(opts.ProgressWriter, "decrypt: done (restored=%d skipped=%d)", decryptedFiles, skippedFiles)

	return nil
}

func List(opts ListOptions) ([]ListedEntry, error) {
	if opts.Password == "" {
		return nil, errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return nil, errors.New("container file is required")
	}

	_, index, _, err := readContainerIndex(opts.ContainerPath, opts.Password)
	if err != nil {
		return nil, err
	}

	entries := make([]ListedEntry, 0, len(index.Entries))
	for _, entry := range index.Entries {
		cleanPath, err := safeOutputPath(entry.Path)
		if err != nil {
			return nil, err
		}
		absPath, err := filepath.Abs(cleanPath)
		if err != nil {
			return nil, fmt.Errorf("resolve absolute path for %q: %w", entry.Path, err)
		}

		listed := ListedEntry{
			Path:  absPath,
			IsDir: entry.Type == entryTypeDir,
			Size:  entry.Size,
		}
		entries = append(entries, listed)
	}

	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Path) < strings.ToLower(entries[j].Path)
	})

	return entries, nil
}

func normalizeInputRoots(inputs []string) ([]string, error) {
	roots := make([]string, 0, len(inputs))
	seen := make(map[string]struct{})
	for _, in := range inputs {
		if strings.TrimSpace(in) == "" {
			continue
		}
		absPath, err := filepath.Abs(in)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(absPath); err != nil {
			return nil, fmt.Errorf("stat input %q: %w", in, err)
		}
		if _, ok := seen[absPath]; ok {
			continue
		}
		seen[absPath] = struct{}{}
		roots = append(roots, absPath)
	}
	if len(roots) == 0 {
		return nil, errors.New("no valid input paths provided")
	}
	return roots, nil
}

func safeOutputPath(storedPath string) (string, error) {
	if strings.TrimSpace(storedPath) == "" {
		return "", errors.New("invalid empty path in container")
	}
	target := filepath.FromSlash(storedPath)
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("invalid absolute path in container: %q", storedPath)
	}
	clean := filepath.Clean(target)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("invalid path traversal in container: %q", storedPath)
	}
	return clean, nil
}

func resolveFileConflictTarget(target string, handler FileConflictHandler) (resolved string, skip bool, err error) {
	if _, statErr := os.Stat(target); statErr != nil {
		if errors.Is(statErr, os.ErrNotExist) {
			return target, false, nil
		}
		return "", false, fmt.Errorf("check target %q: %w", target, statErr)
	}

	if handler == nil {
		handler = promptFileConflict
	}

	action, err := handler(target)
	if err != nil {
		return "", false, err
	}

	switch action {
	case ConflictIgnore:
		return "", true, nil
	case ConflictOverwrite:
		info, err := os.Stat(target)
		if err != nil {
			return "", false, fmt.Errorf("stat existing target %q: %w", target, err)
		}
		if info.IsDir() {
			return "", false, fmt.Errorf("cannot overwrite directory with file: %q", target)
		}
		return target, false, nil
	case ConflictRename:
		resolvedTarget, skip, err := nextAvailableRenamedName(target)
		if err != nil {
			return "", false, err
		}
		fmt.Fprintf(os.Stderr, "conflict rename: %q -> %q\n", target, resolvedTarget)
		return resolvedTarget, skip, nil
	default:
		return "", false, fmt.Errorf("unknown conflict action for %q", target)
	}
}

func promptFileConflict(target string) (FileConflictAction, error) {
	if !isInteractiveTerminal() {
		return 0, fmt.Errorf("target file exists %q and no interactive terminal is available", target)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprintf(os.Stderr, "file %q already exists. [i]gnore/[o]verwrite/[r]ename: ", target)
		line, err := reader.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("read conflict choice: %w", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "i", "ignore":
			return ConflictIgnore, nil
		case "o", "overwrite":
			return ConflictOverwrite, nil
		case "r", "rename", "c", "change":
			return ConflictRename, nil
		default:
			fmt.Fprintln(os.Stderr, "please enter i, o, or r")
		}
	}
}

func nextAvailableRenamedName(target string) (string, bool, error) {
	dir := filepath.Dir(target)
	base := filepath.Base(target)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)

	for i := 1; ; i++ {
		candidateBase := fmt.Sprintf("%s (%04d)%s", name, i, ext)
		candidate := filepath.Join(dir, candidateBase)
		_, err := os.Stat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			return candidate, false, nil
		}
		if err != nil {
			return "", false, fmt.Errorf("check candidate path %q: %w", candidate, err)
		}
	}
}

func isInteractiveTerminal() bool {
	stdinInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	stdoutInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stdinInfo.Mode()&os.ModeCharDevice) != 0 && (stdoutInfo.Mode()&os.ModeCharDevice) != 0
}

func encryptFileData(out *os.File, sourcePath string, aead cipher.AEAD) (uint64, uint32, [8]byte, error) {
	in, err := os.Open(sourcePath)
	if err != nil {
		return 0, 0, [8]byte{}, fmt.Errorf("open %q: %w", sourcePath, err)
	}
	defer func() {
		_ = in.Close()
	}()

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
			return 0, 0, [8]byte{}, fmt.Errorf("read %q: %w", sourcePath, readErr)
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

func decryptFileEntry(in *os.File, aead cipher.AEAD, chunkSizeFromIndex uint32, target string, entry archiveEntry) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for %q: %w", target, err)
	}

	storedSize := entry.StoredSize
	if storedSize == 0 {
		storedSize = entry.Size
	}
	if storedSize < 0 {
		return fmt.Errorf("invalid stored size for %q", target)
	}

	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(entry.Mode))
	if err != nil {
		return fmt.Errorf("create file %q: %w", target, err)
	}
	defer func() {
		_ = out.Close()
	}()

	if _, err := in.Seek(int64(entry.DataOffset), io.SeekStart); err != nil {
		return fmt.Errorf("seek data for %q: %w", target, err)
	}

	encChunkSize := int(chunkSizeFromIndex) + aeadTagSize
	cipherChunk := make([]byte, encChunkSize)
	var restoredStored int64

	var writeDest io.Writer = out
	var tmp *os.File
	if entry.Compressed {
		tmp, err = os.CreateTemp("", "tresor-decrypt-*")
		if err != nil {
			return fmt.Errorf("create temp file for compressed restore: %w", err)
		}
		defer func() {
			name := tmp.Name()
			_ = tmp.Close()
			_ = os.Remove(name)
		}()
		writeDest = tmp
	}

	for i := uint32(0); i < entry.ChunkCount; i++ {
		if _, err := io.ReadFull(in, cipherChunk); err != nil {
			return fmt.Errorf("read encrypted chunk %d for %q: %w", i, target, err)
		}
		nonce := chunkNonce(entry.NonceSeed, i)
		plain, err := aead.Open(nil, nonce[:], cipherChunk, nil)
		if err != nil {
			if isAuthFailure(err) {
				return errors.New("invalid password or corrupted container")
			}
			return fmt.Errorf("decrypt chunk %d for %q: %w", i, target, err)
		}

		remaining := storedSize - restoredStored
		if remaining <= 0 {
			break
		}

		writeLen := int64(len(plain))
		if remaining < writeLen {
			writeLen = remaining
		}

		if _, err := writeDest.Write(plain[:writeLen]); err != nil {
			return fmt.Errorf("write restored chunk for %q: %w", target, err)
		}
		restoredStored += writeLen
	}

	if restoredStored != storedSize {
		return fmt.Errorf("restored stored size mismatch for %q: got %d want %d", target, restoredStored, storedSize)
	}

	if entry.Compressed {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("seek temp file for %q: %w", target, err)
		}
		zr, err := gzip.NewReader(tmp)
		if err != nil {
			return fmt.Errorf("create gzip reader for %q: %w", target, err)
		}
		written, err := io.Copy(out, zr)
		closeErr := zr.Close()
		if err != nil {
			return fmt.Errorf("decompress restored data for %q: %w", target, err)
		}
		if closeErr != nil {
			return fmt.Errorf("finalize gzip stream for %q: %w", target, closeErr)
		}
		if written != entry.Size {
			return fmt.Errorf("restored original size mismatch for %q: got %d want %d", target, written, entry.Size)
		}
	} else if restoredStored != entry.Size {
		return fmt.Errorf("restored size mismatch for %q: got %d want %d", target, restoredStored, entry.Size)
	}

	return nil
}

func isAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "message authentication failed")
}

func progressf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format+"\n", args...)
}

func preparePayload(sourcePath string) (payloadPath string, originalSize int64, storedSize int64, compressed bool, cleanup func(), err error) {
	cleanup = func() {}
	info, err := os.Stat(sourcePath)
	if err != nil {
		return "", 0, 0, false, cleanup, fmt.Errorf("stat %q: %w", sourcePath, err)
	}
	originalSize = info.Size()
	storedSize = originalSize

	in, err := os.Open(sourcePath)
	if err != nil {
		return "", 0, 0, false, cleanup, fmt.Errorf("open %q: %w", sourcePath, err)
	}
	defer func() {
		_ = in.Close()
	}()

	tmp, err := os.CreateTemp("", "tresor-compress-*")
	if err != nil {
		return "", 0, 0, false, cleanup, fmt.Errorf("create temp compression file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup = func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	zw, err := gzip.NewWriterLevel(tmp, gzip.BestSpeed)
	if err != nil {
		cleanup()
		return "", 0, 0, false, func() {}, fmt.Errorf("create gzip writer: %w", err)
	}

	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		cleanup()
		return "", 0, 0, false, func() {}, fmt.Errorf("compress %q: %w", sourcePath, err)
	}
	if err := zw.Close(); err != nil {
		cleanup()
		return "", 0, 0, false, func() {}, fmt.Errorf("finalize compression for %q: %w", sourcePath, err)
	}

	compressedInfo, err := tmp.Stat()
	if err != nil {
		cleanup()
		return "", 0, 0, false, func() {}, fmt.Errorf("stat compressed data for %q: %w", sourcePath, err)
	}

	if compressedInfo.Size() >= originalSize {
		cleanup()
		return sourcePath, originalSize, originalSize, false, func() {}, nil
	}

	if err := tmp.Close(); err != nil {
		cleanup()
		return "", 0, 0, false, func() {}, fmt.Errorf("close compressed temp for %q: %w", sourcePath, err)
	}

	cleanup = func() {
		_ = os.Remove(tmpName)
	}
	return tmpName, originalSize, compressedInfo.Size(), true, cleanup, nil
}

func buildAEAD(password string, hdr containerHeader) (cipher.AEAD, error) {
	key := argon2.IDKey([]byte(password), hdr.Salt[:], hdr.KDFTime, hdr.KDFMemoryKB, hdr.KDFThreads, keySize)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead, nil
}

func chunkNonce(seed [8]byte, chunk uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:8], seed[:])
	binary.LittleEndian.PutUint32(nonce[8:], chunk)
	return nonce
}

func writeHeader(w io.Writer, hdr containerHeader) error {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, hdr.Magic); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, hdr.Version); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, hdr.KDFMemoryKB); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, hdr.KDFTime); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, hdr.KDFThreads); err != nil {
		return err
	}
	if _, err := buf.Write(hdr.Salt[:]); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func readHeader(r io.Reader) (containerHeader, error) {
	var hdr containerHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr.Magic); err != nil {
		return containerHeader{}, fmt.Errorf("read header magic: %w", err)
	}
	if hdr.Magic != headerMagic {
		return containerHeader{}, errors.New("invalid container magic")
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.Version); err != nil {
		return containerHeader{}, fmt.Errorf("read version: %w", err)
	}
	if hdr.Version != containerVersion {
		return containerHeader{}, fmt.Errorf("unsupported container version: %d", hdr.Version)
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.KDFMemoryKB); err != nil {
		return containerHeader{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.KDFTime); err != nil {
		return containerHeader{}, err
	}
	if err := binary.Read(r, binary.LittleEndian, &hdr.KDFThreads); err != nil {
		return containerHeader{}, err
	}
	if _, err := io.ReadFull(r, hdr.Salt[:]); err != nil {
		return containerHeader{}, fmt.Errorf("read salt: %w", err)
	}
	return hdr, nil
}

func writeFooter(w io.Writer, f containerFooter) error {
	buf := &bytes.Buffer{}
	if err := binary.Write(buf, binary.LittleEndian, f.Magic); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, f.IndexOffset); err != nil {
		return err
	}
	if err := binary.Write(buf, binary.LittleEndian, f.IndexLength); err != nil {
		return err
	}
	if _, err := buf.Write(f.IndexNonce[:]); err != nil {
		return err
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func readFooter(in *os.File) (containerFooter, error) {
	footerSize := int64(4 + 8 + 8 + 12)
	stat, err := in.Stat()
	if err != nil {
		return containerFooter{}, fmt.Errorf("stat container: %w", err)
	}
	if stat.Size() < footerSize {
		return containerFooter{}, errors.New("container is too small")
	}
	if _, err := in.Seek(-footerSize, io.SeekEnd); err != nil {
		return containerFooter{}, fmt.Errorf("seek footer: %w", err)
	}

	var f containerFooter
	if err := binary.Read(in, binary.LittleEndian, &f.Magic); err != nil {
		return containerFooter{}, fmt.Errorf("read footer magic: %w", err)
	}
	if f.Magic != footerMagic {
		return containerFooter{}, errors.New("invalid footer magic")
	}
	if err := binary.Read(in, binary.LittleEndian, &f.IndexOffset); err != nil {
		return containerFooter{}, err
	}
	if err := binary.Read(in, binary.LittleEndian, &f.IndexLength); err != nil {
		return containerFooter{}, err
	}
	if _, err := io.ReadFull(in, f.IndexNonce[:]); err != nil {
		return containerFooter{}, fmt.Errorf("read footer nonce: %w", err)
	}
	if f.IndexLength == 0 {
		return containerFooter{}, errors.New("invalid index length")
	}
	indexEnd := int64(f.IndexOffset) + int64(f.IndexLength)
	if indexEnd > stat.Size()-footerSize {
		return containerFooter{}, errors.New("invalid index bounds")
	}
	if indexEnd != stat.Size()-footerSize {
		return containerFooter{}, errors.New("unexpected trailing data before footer")
	}
	return f, nil
}
