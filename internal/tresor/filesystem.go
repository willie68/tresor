package tresor

import (
	"bytes"
	"compress/gzip"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// ReadOnlyFS provides a FUSE filesystem interface for decrypting and serving tresor files
type ReadOnlyFS struct {
	containerPath string
	password      string
	index         archiveIndex
	aead          cipher.AEAD
	containerFile *os.File
	chunkSize     uint32
	totalSize     uint64        // Total size of all files
	volumeLabel   string        // Volume label (container name without extension)
	mu            sync.Mutex    // Protects containerFile reads
}

// NewReadOnlyFS creates a new read-only filesystem for a tresor container
func NewReadOnlyFS(containerPath, password string) (*ReadOnlyFS, error) {
	fs := &ReadOnlyFS{
		containerPath: containerPath,
		password:      password,
	}

	// Open container and read index
	file, err := os.Open(containerPath)
	if err != nil {
		return nil, fmt.Errorf("open container: %w", err)
	}
	defer file.Close()

	// Read header
	hdr, err := readHeader(file)
	if err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	// Build AEAD cipher
	aead, err := buildAEAD(password, hdr)
	if err != nil {
		return nil, fmt.Errorf("build aead: %w", err)
	}

	fs.aead = aead

	// Read footer to get index location
	footer, err := readFooter(file)
	if err != nil {
		return nil, fmt.Errorf("read footer: %w", err)
	}

	// Seek to index and read it
	if _, err := file.Seek(int64(footer.IndexOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek index: %w", err)
	}

	indexCipher := make([]byte, footer.IndexLength)
	if _, err := io.ReadFull(file, indexCipher); err != nil {
		return nil, fmt.Errorf("read index ciphertext: %w", err)
	}

	indexPlain, err := aead.Open(nil, footer.IndexNonce[:], indexCipher, nil)
	if err != nil {
		if isAuthFailure(err) {
			return nil, errors.New("invalid password or corrupted container")
		}
		return nil, fmt.Errorf("decrypt index: %w", err)
	}

	// Unmarshal index
	if err := json.Unmarshal(indexPlain, &fs.index); err != nil {
		return nil, fmt.Errorf("parse index: %w", err)
	}

	if fs.index.ChunkSize == 0 {
		return nil, errors.New("invalid chunk size in index")
	}

	fs.chunkSize = fs.index.ChunkSize

	// Calculate total size and volume label
	var totalSize uint64
	for _, entry := range fs.index.Entries {
		if entry.Type == entryTypeFile { // Regular file
			if entry.Compressed && entry.Size > 0 {
				totalSize += uint64(entry.Size)
			} else if entry.StoredSize > 0 {
				totalSize += uint64(entry.StoredSize)
			} else {
				totalSize += uint64(entry.Size)
			}
		}
	}
	fs.totalSize = totalSize

	// Set volume label from container filename (without extension)
	containerName := containerPath
	if idx := strings.LastIndex(containerName, "\\"); idx != -1 {
		containerName = containerName[idx+1:]
	}
	if idx := strings.LastIndex(containerName, "/"); idx != -1 {
		containerName = containerName[idx+1:]
	}
	if strings.HasSuffix(strings.ToLower(containerName), ".tre") {
		containerName = containerName[:len(containerName)-4]
	}
	fs.volumeLabel = containerName

	// Open container file for later reading
	fs.containerFile, err = os.Open(containerPath)
	if err != nil {
		return nil, fmt.Errorf("open container for reading: %w", err)
	}

	// Validate file sizes for all entries
	for i := range fs.index.Entries {
		entry := &fs.index.Entries[i]
		if entry.Type == entryTypeFile { // Regular file
			if entry.Size <= 0 && entry.StoredSize <= 0 {
				return nil, fmt.Errorf("entry %q has no valid size", entry.Path)
			}
			if entry.ChunkCount == 0 && entry.Size > 0 {
				return nil, fmt.Errorf("entry %q has size but no chunks", entry.Path)
			}
		}
	}

	return fs, nil
}

// Close closes the filesystem
func (fs *ReadOnlyFS) Close() error {
	if fs.containerFile != nil {
		return fs.containerFile.Close()
	}
	return nil
}

// Getattr gets file attributes
func (fs *ReadOnlyFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	path = normalizePath(path)

	// Root directory
	if path == "" {
		stat.Mode = 0o40555 // dr-xr-xr-x
		return 0
	}

	// Check if this is a directory or file
	entry := fs.findEntry(path)
	if entry == nil {
		// Check if it's a directory prefix
		if fs.isDirectoryPrefix(path) {
			stat.Mode = 0o40555 // dr-xr-xr-x
			return 0
		}
		return -fuse.ENOENT
	}

	if entry.Type == entryTypeDir { // Directory
		stat.Mode = 0o40555 // dr-xr-xr-x
	} else { // File
		stat.Mode = 0o100444 // -r--r--r--
		// For compressed files: report Size (decompressed)
		// For non-compressed: report StoredSize (actual data size)
		fileSize := entry.Size
		if !entry.Compressed && entry.StoredSize > 0 {
			fileSize = entry.StoredSize
		}
		stat.Size = fileSize
	}

	if entry.ModTime > 0 {
		stat.Mtim = fuse.NewTimespec(time.Unix(entry.ModTime, 0))
	}

	return 0
}

// Open opens a file
func (fs *ReadOnlyFS) Open(path string, flags int) (errc int, fh uint64) {
	path = normalizePath(path)

	// Only allow read operations
	if (flags&fuse.O_WRONLY) != 0 || (flags&fuse.O_RDWR) != 0 || (flags&fuse.O_APPEND) != 0 {
		return -fuse.EACCES, 0
	}

	entry := fs.findEntry(path)
	if entry == nil || entry.Type == entryTypeDir { // Not found or is directory
		return -fuse.ENOENT, 0
	}

	return 0, ^uint64(0) // Return success with dummy fh (since we're read-only)
}

// Read reads from a file
func (fs *ReadOnlyFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	path = normalizePath(path)

	entry := fs.findEntry(path)
	if entry == nil || entry.Type == entryTypeDir {
		return -fuse.ENOENT
	}

	// For compressed files: maxSize is Size (decompressed)
	// For non-compressed: maxSize is StoredSize (actual data size)
	maxSize := entry.Size
	if !entry.Compressed && entry.StoredSize > 0 {
		maxSize = entry.StoredSize
	}

	// Ensure we don't read beyond EOF
	if ofst >= maxSize {
		return 0
	}

	if maxSize <= 0 {
		return -fuse.EIO // File has invalid size
	}

	readLen := int64(len(buff))
	if ofst+readLen > maxSize {
		readLen = maxSize - ofst
	}

	// Read encrypted data from container and decrypt
	decrypted, err := fs.readDecryptedFileData(entry, ofst, readLen)
	if err != nil {
		fmt.Printf("ERROR reading %s: %v\n", path, err)
		return -fuse.EIO
	}

	copy(buff, decrypted)
	return len(decrypted)
}

// Opendir opens a directory
func (fs *ReadOnlyFS) Opendir(path string) (errc int, fh uint64) {
	path = normalizePath(path)

	if path == "" || fs.isDirectoryPrefix(path) || fs.findEntry(path) != nil {
		return 0, ^uint64(0)
	}

	return -fuse.ENOENT, 0
}

// Readdir reads directory entries
func (fs *ReadOnlyFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) (errc int) {
	path = normalizePath(path)

	// Get all entries that are direct children of this path
	children := fs.getDirectoryChildren(path)

	for _, child := range children {
		stat := fuse.Stat_t{}
		if child.Type == entryTypeDir { // Directory
			stat.Mode = 0o40555 // dr-xr-xr-x
		} else { // File
			stat.Mode = 0o100444 // -r--r--r--
			// For compressed files: report Size (decompressed)
			// For non-compressed: report StoredSize (actual data size)
			fileSize := child.Size
			if !child.Compressed && child.StoredSize > 0 {
				fileSize = child.StoredSize
			}
			stat.Size = fileSize
		}

		if child.ModTime > 0 {
			stat.Mtim = fuse.NewTimespec(time.Unix(child.ModTime, 0))
		}

		// Extract just the name
		relPath := strings.TrimPrefix(child.Path, path)
		if path != "" {
			relPath = strings.TrimPrefix(relPath, "/")
		}
		name := strings.Split(relPath, "/")[0]

		if !fill(name, &stat, 0) {
			break
		}
	}

	return 0
}

// Release releases a file handle
func (fs *ReadOnlyFS) Release(path string, fh uint64) int {
	return 0
}

// Releasedir releases a directory handle
func (fs *ReadOnlyFS) Releasedir(path string, fh uint64) int {
	return 0
}

// Chmod is not supported in read-only mode
func (fs *ReadOnlyFS) Chmod(path string, mode uint32) int {
	return -fuse.EACCES
}

// Chown is not supported in read-only mode
func (fs *ReadOnlyFS) Chown(path string, uid uint32, gid uint32) int {
	return -fuse.EACCES
}

// Utime is not supported in read-only mode
func (fs *ReadOnlyFS) Utime(path string, tmsp *fuse.Timespec, amtsp *fuse.Timespec) int {
	return -fuse.EACCES
}

// Mkdir is not supported in read-only mode
func (fs *ReadOnlyFS) Mkdir(path string, mode uint32) int {
	return -fuse.EACCES
}

// Unlink is not supported in read-only mode
func (fs *ReadOnlyFS) Unlink(path string) int {
	return -fuse.EACCES
}

// Rmdir is not supported in read-only mode
func (fs *ReadOnlyFS) Rmdir(path string) int {
	return -fuse.EACCES
}

// Rename is not supported in read-only mode
func (fs *ReadOnlyFS) Rename(oldpath string, newpath string) int {
	return -fuse.EACCES
}

// Link is not supported in read-only mode
func (fs *ReadOnlyFS) Link(oldpath string, newpath string) int {
	return -fuse.EACCES
}

// Symlink is not supported in read-only mode
func (fs *ReadOnlyFS) Symlink(target string, linkpath string) int {
	return -fuse.EACCES
}

// Readlink is not supported
func (fs *ReadOnlyFS) Readlink(path string) (errc int, target string) {
	return -fuse.ENOSYS, ""
}

// Create is not supported in read-only mode
func (fs *ReadOnlyFS) Create(path string, flags int, mode uint32) (errc int, fh uint64) {
	return -fuse.EACCES, 0
}

// Write is not supported in read-only mode
func (fs *ReadOnlyFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	return -fuse.EACCES
}

// Flush is not needed for read-only filesystem
func (fs *ReadOnlyFS) Flush(path string, fh uint64) int {
	return 0
}

// Fsync is not needed for read-only filesystem
func (fs *ReadOnlyFS) Fsync(path string, datasync bool, fh uint64) int {
	return 0
}

// Statfs returns filesystem statistics
func (fs *ReadOnlyFS) Statfs(path string, stat *fuse.Statfs_t) int {
	stat.Bsize = 4096
	totalBlocks := (fs.totalSize + 4095) / 4096 // Round up to next block
	stat.Blocks = totalBlocks
	stat.Bfree = 0   // Read-only filesystem
	stat.Bavail = 0  // No available space for writing
	stat.Files = uint64(len(fs.index.Entries))
	stat.Ffree = 0   // No available files for creating
	stat.Namemax = 255
	return 0
}

// Access checks if path is accessible with given mode
func (fs *ReadOnlyFS) Access(path string, mask uint32) int {
	path = normalizePath(path)

	if path == "" {
		// Root is always accessible for reading
		return 0
	}

	entry := fs.findEntry(path)
	if entry == nil && !fs.isDirectoryPrefix(path) {
		return -fuse.ENOENT
	}

	// Read-only filesystem
	if (mask & 2) != 0 { // Write access
		return -fuse.EACCES
	}

	return 0
}

// Helper functions

func normalizePath(path string) string {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	return path
}

func (fs *ReadOnlyFS) findEntry(path string) *archiveEntry {
	for i := range fs.index.Entries {
		entryPath := strings.TrimPrefix(fs.index.Entries[i].Path, "/")
		if entryPath == path {
			return &fs.index.Entries[i]
		}
	}
	return nil
}

func (fs *ReadOnlyFS) isDirectoryPrefix(path string) bool {
	if path == "" {
		return true
	}
	prefix := path + "/"
	for i := range fs.index.Entries {
		if strings.HasPrefix(fs.index.Entries[i].Path, "/"+prefix) || strings.HasPrefix(fs.index.Entries[i].Path, prefix) {
			return true
		}
	}
	return false
}

func (fs *ReadOnlyFS) getDirectoryChildren(path string) []*archiveEntry {
	var children []*archiveEntry
	seen := make(map[string]bool)

	prefix := path
	if prefix != "" {
		prefix = prefix + "/"
	}

	for i := range fs.index.Entries {
		entry := &fs.index.Entries[i]
		entryPath := strings.TrimPrefix(entry.Path, "/")

		if path == "" {
			// Root directory
			if !strings.Contains(entryPath, "/") {
				if !seen[entryPath] {
					children = append(children, entry)
					seen[entryPath] = true
				}
			} else {
				// Add parent directory
				parts := strings.Split(entryPath, "/")
				if !seen[parts[0]] {
					// Create synthetic directory entry
					children = append(children, &archiveEntry{
						Path: "/" + parts[0],
						Type: 1, // Directory
						Mode: 0o40555,
					})
					seen[parts[0]] = true
				}
			}
		} else {
			// Subdirectory
			if strings.HasPrefix(entryPath, prefix) {
				rel := strings.TrimPrefix(entryPath, prefix)
				if !strings.Contains(rel, "/") {
					if !seen[rel] {
						children = append(children, entry)
						seen[rel] = true
					}
				} else {
					// Add parent directory
					parts := strings.Split(rel, "/")
					if !seen[parts[0]] {
						children = append(children, &archiveEntry{
							Path: "/" + prefix + parts[0],
							Type: 1, // Directory
							Mode: 0o40555,
						})
						seen[parts[0]] = true
					}
				}
			}
		}
	}

	return children
}

func (fs *ReadOnlyFS) readDecryptedFileData(entry *archiveEntry, offset, length int64) ([]byte, error) {
	if fs.containerFile == nil {
		return nil, errors.New("container file not open")
	}

	if offset < 0 || length < 0 {
		return nil, errors.New("invalid offset or length")
	}

	// For size limits: use Size if compressed, else StoredSize
	maxSize := entry.Size
	if !entry.Compressed && entry.StoredSize > 0 {
		maxSize = entry.StoredSize
	}

	// Data size in container (what we read from container)
	dataSize := entry.StoredSize
	if dataSize == 0 {
		dataSize = entry.Size
	}

	if offset >= maxSize {
		return []byte{}, nil
	}

	// Clamp length to file size
	if offset+length > maxSize {
		length = maxSize - offset
	}

	// Read and decrypt ALL chunks sequentially (like decryptFileEntry does)
	// Then extract only the requested bytes
	// Use mutex for entire read operation to keep container file position consistent
	fs.mu.Lock()
	defer fs.mu.Unlock()

	encChunkSize := int(fs.chunkSize) + aeadTagSize
	cipherChunk := make([]byte, encChunkSize)
	var allData []byte

	// Seek to start of file data
	if _, err := fs.containerFile.Seek(int64(entry.DataOffset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek data: %w", err)
	}

	for i := uint32(0); i < entry.ChunkCount; i++ {
		n, err := io.ReadFull(fs.containerFile, cipherChunk)
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("read chunk %d: %w", i, err)
		}
		if n < int(encChunkSize) && err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("chunk %d truncated: read %d, expected %d", i, n, encChunkSize)
		}

		// Decrypt chunk
		nonce := fs.chunkNonce(entry.NonceSeed, i)
		plain, err := fs.aead.Open(nil, nonce[:], cipherChunk[:n], nil)
		if err != nil {
			return nil, fmt.Errorf("decrypt chunk %d: %w", i, err)
		}

		// Only take what belongs to file (avoid padding)
		filePos := int64(i) * int64(fs.chunkSize)
		chunkDataLen := min(int64(len(plain)), dataSize-filePos)
		if chunkDataLen > 0 {
			allData = append(allData, plain[:chunkDataLen]...)
		}

		// Stop if we have enough data
		if int64(len(allData)) >= dataSize {
			break
		}
	}

	// Extract requested bytes
	if offset > int64(len(allData)) {
		return []byte{}, nil
	}

	end := offset + length
	if end > int64(len(allData)) {
		end = int64(len(allData))
	}

	result := allData[offset:end]

	// Decompress if needed (like decryptFileEntry does) - must decompress BEFORE extracting offset
	if entry.Compressed {
		zr, err := gzip.NewReader(bytes.NewReader(allData))
		if err != nil {
			return nil, fmt.Errorf("create gzip reader: %w", err)
		}
		decompressed, err := io.ReadAll(zr)
		closeErr := zr.Close()
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close gzip reader: %w", closeErr)
		}

		// Now extract from decompressed data
		if offset > int64(len(decompressed)) {
			return []byte{}, nil
		}
		end := offset + length
		if end > int64(len(decompressed)) {
			end = int64(len(decompressed))
		}
		result = decompressed[offset:end]
	}

	return result, nil
}

func (fs *ReadOnlyFS) chunkNonce(seed [8]byte, chunk uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:8], seed[:])
	binary.LittleEndian.PutUint32(nonce[8:], chunk)
	return nonce
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// Init is called when the file system is created
func (fs *ReadOnlyFS) Init() {
	// Nothing to initialize
}

// Destroy is called when the file system is destroyed
func (fs *ReadOnlyFS) Destroy() {
	// Nothing to clean up (Close() handles it)
}

// Mknod is not supported in read-only mode
func (fs *ReadOnlyFS) Mknod(path string, mode uint32, dev uint64) int {
	return -fuse.EACCES
}

// Utimens changes the access and modification times of a file
func (fs *ReadOnlyFS) Utimens(path string, tmsp []fuse.Timespec) int {
	return -fuse.EACCES
}

// Truncate changes the size of a file
func (fs *ReadOnlyFS) Truncate(path string, size int64, fh uint64) int {
	return -fuse.EACCES
}

// Fsyncdir synchronizes directory contents
func (fs *ReadOnlyFS) Fsyncdir(path string, datasync bool, fh uint64) int {
	return 0
}

// Setxattr sets extended attributes
func (fs *ReadOnlyFS) Setxattr(path string, name string, value []byte, flags int) int {
	return -fuse.EACCES
}

// Getxattr gets extended attributes
func (fs *ReadOnlyFS) Getxattr(path string, name string) (int, []byte) {
	return -fuse.ENODATA, nil
}

// Removexattr removes extended attributes
func (fs *ReadOnlyFS) Removexattr(path string, name string) int {
	return -fuse.EACCES
}

// Listxattr lists extended attributes
func (fs *ReadOnlyFS) Listxattr(path string, fill func(name string) bool) int {
	return 0
}
