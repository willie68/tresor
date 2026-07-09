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
	"time"

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
	Path    string
	IsDir   bool
	Size    int64
	ModTime int64
}

type ExtractOptions struct {
	Password       string
	ContainerPath  string
	ExtractPath    string
	ForceDirs      bool
	OnFileConflict FileConflictHandler
	ProgressWriter io.Writer
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

const footerSize int64 = 4 + 8 + 8 + 12

type archiveIndex struct {
	ChunkSize uint32         `json:"chunk_size"`
	Entries   []archiveEntry `json:"entries"`
}

type archiveEntry struct {
	Path       string  `json:"path"`
	Mode       uint32  `json:"mode"`
	Type       uint8   `json:"type"`
	Size       int64   `json:"size"`
	ModTime    int64   `json:"mod_time,omitempty"`
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
		walkErr := encryptSyncWalkDir(root, cwd, out, aead, &index, seen, opts.ProgressWriter, &encryptedFiles)
		if walkErr != nil {
			return walkErr
		}
	}

	if err := writeContainerIndex(out, aead, index); err != nil {
		return err
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

	index.Entries = append(index.Entries, archiveEntry{
		Path:       relPath,
		Mode:       uint32(info.Mode().Perm()),
		Type:       entryTypeFile,
		Size:       originalSize,
		ModTime:    info.ModTime().Unix(),
		StoredSize: storedSize,
		Compressed: compressed,
		DataOffset: uint64(offset),
		DataLength: dataLen,
		ChunkCount: chunkCount,
		NonceSeed:  nonceSeed,
	})
	*fileCount++
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

	if opts.RemoveSources {
		for _, root := range roots {
			if err := os.RemoveAll(root); err != nil {
				return fmt.Errorf("remove source %q: %w", root, err)
			}
		}
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
		ModTime:    info.ModTime().Unix(),
		StoredSize: storedSize,
		Compressed: compressed,
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

func writeContainerIndex(out *os.File, aead cipher.AEAD, index archiveIndex) error {
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

	return nil
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

	if opts.OnFileConflict == nil {
		opts.OnFileConflict = promptFileConflict
	}

	stats := struct {
		decrypted int
		skipped   int
	}{}

	for _, entry := range index.Entries {
		err := decryptProcessEntry(in, aead, index.ChunkSize, entry, opts.OnFileConflict, opts.ProgressWriter, &stats)
		if err != nil {
			return err
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

	progressf(opts.ProgressWriter, "decrypt: done (restored=%d skipped=%d)", stats.decrypted, stats.skipped)

	return nil
}

func decryptProcessEntry(in *os.File, aead cipher.AEAD, chunkSize uint32, entry archiveEntry, conflictHandler FileConflictHandler, pw io.Writer, stats *struct {
	decrypted int
	skipped   int
}) error {
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
		resolvedTarget, skip, err := resolveFileConflictTarget(target, conflictHandler)
		if err != nil {
			return err
		}
		if skip {
			stats.skipped++
			progressf(pw, "decrypt: ignore existing %s", target)
			return nil
		}
		progressf(pw, "decrypt: restoring %s", resolvedTarget)
		if err := decryptFileEntry(in, aead, chunkSize, resolvedTarget, entry); err != nil {
			return err
		}
		stats.decrypted++
	default:
		return fmt.Errorf("unknown entry type %d for %q", entry.Type, entry.Path)
	}
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
		listed := ListedEntry{
			Path:    entry.Path,
			IsDir:   entry.Type == entryTypeDir,
			Size:    entry.Size,
			ModTime: entry.ModTime,
		}
		entries = append(entries, listed)
	}

	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(entries[i].Path) < strings.ToLower(entries[j].Path)
	})

	return entries, nil
}

// Extract extracts files and directories from the container to the specified extract path.
func Extract(opts ExtractOptions) error {
	if opts.Password == "" {
		return errors.New("password is required")
	}
	if opts.ContainerPath == "" {
		return errors.New("container file is required")
	}
	if opts.ExtractPath == "" {
		return errors.New("extract path is required")
	}

	progressf(opts.ProgressWriter, "extract: container=%q path=%q force-dirs=%v", opts.ContainerPath, opts.ExtractPath, opts.ForceDirs)

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

	// Normalize extract path (convert to forward slashes)
	extractPath := path.Clean(filepath.ToSlash(opts.ExtractPath))

	// Find matching entries
	matchingEntries := make([]archiveEntry, 0)
	for _, entry := range index.Entries {
		entryPath := entry.Path
		// Check if entry matches extract path or is within the extract path
		if entryPath == extractPath || strings.HasPrefix(entryPath, extractPath+"/") {
			matchingEntries = append(matchingEntries, entry)
		}
	}

	if len(matchingEntries) == 0 {
		return fmt.Errorf("no entries found for path %q", opts.ExtractPath)
	}

	if opts.OnFileConflict == nil {
		opts.OnFileConflict = promptFileConflict
	}

	// Check if we're extracting a single file
	isSingleFile := len(matchingEntries) == 1 && matchingEntries[0].Type == entryTypeFile && matchingEntries[0].Path == extractPath

	stats := struct {
		extracted int
		skipped   int
	}{}

	for _, entry := range matchingEntries {
		err := extractProcessEntry(in, aead, index.ChunkSize, entry, extractPath, isSingleFile, opts.ForceDirs, opts.OnFileConflict, opts.ProgressWriter, &stats)
		if err != nil {
			return err
		}
	}

	if err := in.Close(); err != nil {
		return fmt.Errorf("close container file: %w", err)
	}
	containerOpen = false

	progressf(opts.ProgressWriter, "extract: done (extracted=%d skipped=%d)", stats.extracted, stats.skipped)

	return nil
}

func extractProcessEntry(in *os.File, aead cipher.AEAD, chunkSize uint32, entry archiveEntry, extractPath string, isSingleFile, forceDirs bool, conflictHandler FileConflictHandler, pw io.Writer, stats *struct {
	extracted int
	skipped   int
}) error {
	// Skip directories for now (will be created as needed)
	if entry.Type == entryTypeDir {
		if forceDirs {
			target, err := safeOutputPath(entry.Path)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(target, fs.FileMode(entry.Mode)); err != nil {
				return fmt.Errorf("create directory %q: %w", target, err)
			}
		}
		return nil
	}

	var targetPath string
	var err error
	if forceDirs {
		// Keep full path structure
		targetPath, err = safeOutputPath(entry.Path)
		if err != nil {
			return err
		}
	} else {
		// Extract only the filename (or relative path from extract point)
		if isSingleFile {
			// For single file, use just the filename
			targetPath = path.Base(entry.Path)
		} else {
			// For directory, strip the extract path prefix and keep relative path
			relPath := strings.TrimPrefix(entry.Path, extractPath+"/")
			targetPath, err = safeOutputPath(relPath)
			if err != nil {
				return err
			}
		}
	}

	// Ensure parent directory exists
	targetDir := filepath.Dir(targetPath)
	if targetDir != "." {
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			return fmt.Errorf("create parent directory for %q: %w", targetPath, err)
		}
	}

	resolvedTarget, skip, err := resolveFileConflictTarget(targetPath, conflictHandler)
	if err != nil {
		return err
	}
	if skip {
		stats.skipped++
		progressf(pw, "extract: ignore existing %s", targetPath)
		return nil
	}

	progressf(pw, "extract: extracting %s", resolvedTarget)
	if err := decryptFileEntry(in, aead, chunkSize, resolvedTarget, entry); err != nil {
		return err
	}
	stats.extracted++
	return nil
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

	if entry.ModTime != 0 {
		modTime := time.Unix(entry.ModTime, 0)
		if err := os.Chtimes(target, modTime, modTime); err != nil {
			return fmt.Errorf("restore mod time for %q: %w", target, err)
		}
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
	// Default cleanup function does nothing; will be replaced if a temp file is created.
	cleanup = func() {
		// no-op
	}
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
		return "", 0, 0, false, cleanup, fmt.Errorf("create gzip writer: %w", err)
	}

	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		cleanup()
		return "", 0, 0, false, cleanup, fmt.Errorf("compress %q: %w", sourcePath, err)
	}
	if err := zw.Close(); err != nil {
		cleanup()
		return "", 0, 0, false, cleanup, fmt.Errorf("finalize compression for %q: %w", sourcePath, err)
	}

	compressedInfo, err := tmp.Stat()
	if err != nil {
		cleanup()
		return "", 0, 0, false, cleanup, fmt.Errorf("stat compressed data for %q: %w", sourcePath, err)
	}

	if compressedInfo.Size() >= originalSize {
		cleanup()
		return sourcePath, originalSize, originalSize, false, cleanup, nil
	}

	if err := tmp.Close(); err != nil {
		cleanup()
		return "", 0, 0, false, cleanup, fmt.Errorf("close compressed temp for %q: %w", sourcePath, err)
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
