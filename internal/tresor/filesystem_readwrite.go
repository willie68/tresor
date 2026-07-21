//go:build windows

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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// readWriteFS provides a FUSE filesystem interface that supports both reading from a tresor container
// and writing new or modified files. Changes are kept in memory or in temporary storage.
type readWriteFS struct {
	containerPath   string
	password        string
	index           archiveIndex
	aead            cipher.AEAD
	containerReader *containerReader
	chunkSize       uint32
	totalSize       uint64
	volumeLabel     string
	mu              sync.RWMutex // Protects containerReader reads and memoryFS writes
	cache           *FileCache
	memoryFS        *inMemoryFS // In-memory storage for new/modified files
}

// inMemoryFS represents in-memory file storage for new/modified files
type inMemoryFS struct {
	files map[string]*inMemoryFile // path -> file
	dirs  map[string]bool          // path -> exists
	mu    sync.RWMutex
}

// inMemoryFile represents a file stored in memory
type inMemoryFile struct {
	data    []byte
	modTime int64
	isDir   bool
}

// NewReadWriteFS creates a new read-write filesystem for a tresor container
func NewReadWriteFS(containerPath, password string, cacheSize int64) (*readWriteFS, error) {
	fs := &readWriteFS{
		containerPath: containerPath,
		password:      password,
		memoryFS: &inMemoryFS{
			files: make(map[string]*inMemoryFile),
			dirs:  make(map[string]bool),
		},
	}

	fs.cache = NewFileCache(cacheSize)

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
		if entry.Type == entryTypeFile {
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

	// Set volume label from container filename
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

	// Create container reader for multi-container support
	cr, err := newContainerReader(containerPath)
	if err != nil {
		return nil, fmt.Errorf("open containers: %w", err)
	}
	fs.containerReader = cr

	return fs, nil
}

// Close closes the filesystem
func (fs *readWriteFS) Close() error {
	if fs.containerReader != nil {
		fs.containerReader.close()
	}
	return nil
}

// Getattr gets file attributes
func (fs *readWriteFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	path = normalizePath(path)

	// Check root directory
	if path == "" {
		stat.Mode = fuse.S_IFDIR | 0o777
		stat.Nlink = 2
		stat.Uid = 0
		stat.Gid = 0
		stat.Ino = 1
		return 0
	}

	// Check in-memory filesystem first
	fs.memoryFS.mu.RLock()
	if memFile, ok := fs.memoryFS.files[path]; ok {
		fs.memoryFS.mu.RUnlock()
		if memFile.isDir {
			stat.Mode = 0o40777 // drwxrwxrwx
			stat.Nlink = 2
		} else {
			stat.Mode = 0o100777 // -rwxrwxrwx
			stat.Size = int64(len(memFile.data))
		}
		stat.Uid = 0
		stat.Gid = 0
		if memFile.modTime > 0 {
			stat.Mtim = fuse.NewTimespec(time.Unix(memFile.modTime, 0))
		}
		return 0
	}
	fs.memoryFS.mu.RUnlock()

	// Check if directory prefix exists in memory
	fs.memoryFS.mu.RLock()
	if fs.isDirectoryPrefixInMemory(path) {
		fs.memoryFS.mu.RUnlock()
		stat.Mode = 0o40777
		stat.Nlink = 2
		stat.Uid = 0
		stat.Gid = 0
		return 0
	}
	fs.memoryFS.mu.RUnlock()

	// Check in container
	entry := fs.findEntry(path)
	if entry == nil {
		// Check if it's a directory prefix
		if fs.isDirectoryPrefix(path) {
			stat.Mode = 0o40777 // drwxrwxrwx
			stat.Uid = 0
			stat.Gid = 0
			return 0
		}
		return -fuse.ENOENT
	}

	if entry.Type == entryTypeDir {
		stat.Mode = 0o40777 // drwxrwxrwx
	} else {
		stat.Mode = 0o100777 // -rwxrwxrwx
		fileSize := entry.Size
		if !entry.Compressed && entry.StoredSize > 0 {
			fileSize = entry.StoredSize
		}
		stat.Size = fileSize
	}
	stat.Uid = 0
	stat.Gid = 0

	if entry.ModTime > 0 {
		stat.Mtim = fuse.NewTimespec(time.Unix(entry.ModTime, 0))
	}

	return 0
}

// Open opens a file
func (fs *readWriteFS) Open(path string, flags int) (errc int, fh uint64) {
	path = normalizePath(path)

	// Check in-memory filesystem first
	fs.memoryFS.mu.RLock()
	if memFile, ok := fs.memoryFS.files[path]; ok {
		fs.memoryFS.mu.RUnlock()
		if memFile.isDir {
			return -fuse.EISDIR, 0
		}
		return 0, ^uint64(0)
	}
	fs.memoryFS.mu.RUnlock()

	// Check container
	entry := fs.findEntry(path)
	if entry == nil || entry.Type == entryTypeDir {
		return -fuse.ENOENT, 0
	}

	return 0, ^uint64(0)
}

// Read reads from a file
func (fs *readWriteFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	path = normalizePath(path)

	// Check in-memory filesystem first
	fs.memoryFS.mu.RLock()
	if memFile, ok := fs.memoryFS.files[path]; ok {
		fs.memoryFS.mu.RUnlock()
		if memFile.isDir {
			return -fuse.EISDIR
		}
		if ofst >= int64(len(memFile.data)) {
			return 0
		}
		end := ofst + int64(len(buff))
		if end > int64(len(memFile.data)) {
			end = int64(len(memFile.data))
		}
		n := copy(buff, memFile.data[ofst:end])
		return n
	}
	fs.memoryFS.mu.RUnlock()

	// Read from container
	entry := fs.findEntry(path)
	if entry == nil || entry.Type == entryTypeDir {
		return -fuse.ENOENT
	}

	maxSize := entry.Size
	if !entry.Compressed && entry.StoredSize > 0 {
		maxSize = entry.StoredSize
	}

	if ofst >= maxSize {
		return 0
	}

	if maxSize <= 0 {
		return -fuse.EIO
	}

	readLen := int64(len(buff))
	if ofst+readLen > maxSize {
		readLen = maxSize - ofst
	}

	decrypted, err := fs.readDecryptedFileData(entry, ofst, readLen)
	if err != nil {
		fmt.Printf("ERROR reading %s: %v\n", path, err)
		return -fuse.EIO
	}

	copy(buff, decrypted)
	return len(decrypted)
}

// Create creates a new file
func (fs *readWriteFS) Create(path string, flags int, mode uint32) (errc int, fh uint64) {
	path = normalizePath(path)

	if path == "" {
		return -fuse.EACCES, 0
	}

	// Check if parent directory exists - before taking lock
	parent := filepath.Dir(filepath.FromSlash(path))
	if parent != "." && parent != "" {
		parent = normalizePath(filepath.ToSlash(parent))
		if !fs.directoryExists(parent) {
			return -fuse.ENOENT, 0
		}
	}

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	// Check if file already exists in memory
	if memFile, ok := fs.memoryFS.files[path]; ok {
		if memFile.isDir {
			// Can't create a file over a directory
			return -fuse.EISDIR, 0
		}

		// Respect exclusive create semantics for conflict checks
		if (flags&os.O_EXCL) != 0 && (flags&os.O_TRUNC) == 0 {
			return -fuse.EEXIST, 0
		}

		// Only truncate existing files when requested explicitly
		if (flags & os.O_TRUNC) != 0 {
			memFile.data = []byte{}
			memFile.modTime = time.Now().Unix()
		}
		return 0, ^uint64(0)
	}

	if entry := fs.findEntry(path); entry != nil {
		if entry.Type == entryTypeDir {
			return -fuse.EISDIR, 0
		}

		// Respect exclusive create semantics for conflict checks
		if (flags&os.O_EXCL) != 0 && (flags&os.O_TRUNC) == 0 {
			return -fuse.EEXIST, 0
		}

		// Existing container file: create a writable memory shadow.
		// Preserve content unless caller explicitly requested truncate.
		var data []byte
		if (flags & os.O_TRUNC) == 0 {
			fileSize := entry.Size
			if !entry.Compressed && entry.StoredSize > 0 {
				fileSize = entry.StoredSize
			}

			if fileSize > 0 {
				decrypted, err := fs.readDecryptedFileData(entry, 0, fileSize)
				if err != nil {
					return -fuse.EIO, 0
				}
				data = decrypted
			} else {
				data = []byte{}
			}
		} else {
			data = []byte{}
		}

		fs.memoryFS.files[path] = &inMemoryFile{
			data:    data,
			modTime: time.Now().Unix(),
			isDir:   false,
		}
		return 0, ^uint64(0)
	}

	// Create new file in memory
	fs.memoryFS.files[path] = &inMemoryFile{
		data:    []byte{},
		modTime: time.Now().Unix(),
		isDir:   false,
	}

	return 0, ^uint64(0)
}

// Write writes to a file
func (fs *readWriteFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	path = normalizePath(path)

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	memFile, ok := fs.memoryFS.files[path]
	if !ok {
		return -fuse.ENOENT
	}

	if memFile.isDir {
		return -fuse.EISDIR
	}

	// Extend file if necessary
	endOffset := ofst + int64(len(buff))
	if endOffset > int64(len(memFile.data)) {
		newData := make([]byte, endOffset)
		copy(newData, memFile.data)
		memFile.data = newData
	}

	// Write data
	copy(memFile.data[ofst:], buff)
	memFile.modTime = time.Now().Unix()

	return len(buff)
}

// Flush is called on file close
func (fs *readWriteFS) Flush(path string, fh uint64) int {
	return 0
}

// Fsync synchronizes file data
func (fs *readWriteFS) Fsync(path string, datasync bool, fh uint64) int {
	return 0
}

// Release releases a file handle
func (fs *readWriteFS) Release(path string, fh uint64) int {
	return 0
}

// Mkdir creates a new directory
func (fs *readWriteFS) Mkdir(path string, mode uint32) int {
	path = normalizePath(path)

	if path == "" {
		return -fuse.EACCES
	}

	// Check if already exists in container
	if fs.findEntry(path) != nil {
		return -fuse.EEXIST
	}

	// Check if parent directory exists - before taking lock
	parent := filepath.Dir(filepath.FromSlash(path))
	if parent != "." && parent != "" {
		parent = normalizePath(filepath.ToSlash(parent))
		if !fs.directoryExists(parent) {
			return -fuse.ENOENT
		}
	}

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	// Check if already exists in memory
	if _, ok := fs.memoryFS.files[path]; ok {
		return -fuse.EEXIST
	}

	// Create directory in memory
	fs.memoryFS.files[path] = &inMemoryFile{
		data:    nil,
		modTime: time.Now().Unix(),
		isDir:   true,
	}
	fs.memoryFS.dirs[path] = true

	return 0
}

// Rmdir removes a directory
func (fs *readWriteFS) Rmdir(path string) int {
	path = normalizePath(path)

	if path == "" {
		return -fuse.EACCES
	}

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	memFile, ok := fs.memoryFS.files[path]
	if !ok {
		return -fuse.ENOENT
	}

	if !memFile.isDir {
		return -fuse.ENOTDIR
	}

	// Check if directory is empty
	prefix := path + "/"
	for fpath := range fs.memoryFS.files {
		if fpath != path && strings.HasPrefix(fpath, prefix) {
			return -fuse.ENOTEMPTY
		}
	}

	delete(fs.memoryFS.files, path)
	delete(fs.memoryFS.dirs, path)

	return 0
}

// Unlink removes a file
func (fs *readWriteFS) Unlink(path string) int {
	path = normalizePath(path)

	if path == "" {
		return -fuse.EACCES
	}

	// Cannot delete files from container
	if fs.findEntry(path) != nil {
		return -fuse.EACCES
	}

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	memFile, ok := fs.memoryFS.files[path]
	if !ok {
		return -fuse.ENOENT
	}

	if memFile.isDir {
		return -fuse.EISDIR
	}

	delete(fs.memoryFS.files, path)
	return 0
}

// Rename renames a file or directory
func (fs *readWriteFS) Rename(oldpath string, newpath string) int {
	oldpath = normalizePath(oldpath)
	newpath = normalizePath(newpath)

	if oldpath == "" || newpath == "" {
		return -fuse.EACCES
	}

	// Cannot rename files from container
	if fs.findEntry(oldpath) != nil {
		return -fuse.EACCES
	}

	parent := filepath.Dir(filepath.FromSlash(newpath))
	if parent != "." && parent != "" {
		parent = normalizePath(filepath.ToSlash(parent))
		if !fs.directoryExists(parent) {
			return -fuse.ENOENT
		}
	}

	if oldpath != newpath {
		if containerEntry := fs.findEntry(newpath); containerEntry != nil && containerEntry.Type == entryTypeDir {
			return -fuse.EISDIR
		}
	}

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	memFile, ok := fs.memoryFS.files[oldpath]
	if !ok {
		return -fuse.ENOENT
	}

	// Existing target directories cannot be replaced by a file rename.
	if targetMem, ok := fs.memoryFS.files[newpath]; ok && oldpath != newpath {
		if targetMem.isDir {
			return -fuse.EISDIR
		}
		delete(fs.memoryFS.files, newpath)
	}

	// Rename
	fs.memoryFS.files[newpath] = memFile
	delete(fs.memoryFS.files, oldpath)

	if memFile.isDir {
		fs.memoryFS.dirs[newpath] = true
		delete(fs.memoryFS.dirs, oldpath)

		// Update paths of files in renamed directory
		oldPrefix := oldpath + "/"
		newPrefix := newpath + "/"
		for fpath := range fs.memoryFS.files {
			if strings.HasPrefix(fpath, oldPrefix) {
				newFpath := newPrefix + strings.TrimPrefix(fpath, oldPrefix)
				fs.memoryFS.files[newFpath] = fs.memoryFS.files[fpath]
				delete(fs.memoryFS.files, fpath)
			}
		}
	}

	return 0
}

// Opendir opens a directory
func (fs *readWriteFS) Opendir(path string) (errc int, fh uint64) {
	path = normalizePath(path)

	// Check memory first
	fs.memoryFS.mu.RLock()
	if memFile, ok := fs.memoryFS.files[path]; ok && memFile.isDir {
		fs.memoryFS.mu.RUnlock()
		return 0, ^uint64(0)
	}
	fs.memoryFS.mu.RUnlock()

	// Check container
	if path == "" {
		return 0, ^uint64(0)
	}

	entry := fs.findEntry(path)
	if entry == nil || entry.Type != entryTypeDir {
		return -fuse.ENOENT, 0
	}

	return 0, ^uint64(0)
}

// Readdir reads directory contents
func (fs *readWriteFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	path = normalizePath(path)

	// Collect entries from both container and memory
	entries := make(map[string]*fuse.Stat_t)

	// Add entries from container
	containerChildren := fs.getDirectoryChildren(path)
	for _, entry := range containerChildren {
		entryPath := strings.TrimPrefix(entry.Path, "/")
		name := filepath.Base(entryPath)

		stat := &fuse.Stat_t{}
		if entry.Type == entryTypeDir {
			stat.Mode = 0o40777
		} else {
			stat.Mode = 0o100777
			fileSize := entry.Size
			if !entry.Compressed && entry.StoredSize > 0 {
				fileSize = entry.StoredSize
			}
			stat.Size = fileSize
		}
		stat.Uid = 0
		stat.Gid = 0
		if entry.ModTime > 0 {
			stat.Mtim = fuse.NewTimespec(time.Unix(entry.ModTime, 0))
		}
		entries[name] = stat
	}

	// Add entries from memory
	fs.memoryFS.mu.RLock()
	prefix := path
	if prefix != "" && prefix != "/" {
		prefix = prefix + "/"
	}

	for memPath, memFile := range fs.memoryFS.files {
		memPath = strings.TrimPrefix(memPath, "/")
		if prefix == "" || prefix == "/" {
			if !strings.Contains(memPath, "/") {
				name := memPath
				stat := &fuse.Stat_t{}
				if memFile.isDir {
					stat.Mode = 0o40777
				} else {
					stat.Mode = 0o100777
					stat.Size = int64(len(memFile.data))
				}
				stat.Uid = 0
				stat.Gid = 0
				if memFile.modTime > 0 {
					stat.Mtim = fuse.NewTimespec(time.Unix(memFile.modTime, 0))
				}
				entries[name] = stat
			} else {
				parts := strings.Split(memPath, "/")
				name := parts[0]
				if _, exists := entries[name]; !exists {
					stat := &fuse.Stat_t{Mode: 0o40777}
					entries[name] = stat
				}
			}
		} else {
			if strings.HasPrefix(memPath, prefix) {
				rel := strings.TrimPrefix(memPath, prefix)
				if !strings.Contains(rel, "/") {
					name := rel
					stat := &fuse.Stat_t{}
					if memFile.isDir {
						stat.Mode = 0o40777
					} else {
						stat.Mode = 0o100777
						stat.Size = int64(len(memFile.data))
					}
					stat.Uid = 0
					stat.Gid = 0
					if memFile.modTime > 0 {
						stat.Mtim = fuse.NewTimespec(time.Unix(memFile.modTime, 0))
					}
					entries[name] = stat
				} else {
					parts := strings.Split(rel, "/")
					name := parts[0]
					if _, exists := entries[name]; !exists {
						stat := &fuse.Stat_t{Mode: 0o40777}
						entries[name] = stat
					}
				}
			}
		}
	}
	fs.memoryFS.mu.RUnlock()

	// Call fill for each entry
	for name, stat := range entries {
		if !fill(name, stat, 0) {
			break
		}
	}

	return 0
}

// Releasedir releases a directory handle
func (fs *readWriteFS) Releasedir(path string, fh uint64) int {
	return 0
}

// Statfs returns filesystem statistics
func (fs *readWriteFS) Statfs(path string, stat *fuse.Statfs_t) int {
	stat.Bsize = uint64(4096)
	stat.Frsize = uint64(4096)

	// Total size includes container data and memory data
	fs.memoryFS.mu.RLock()
	var memoryUsed int64
	for _, memFile := range fs.memoryFS.files {
		if !memFile.isDir {
			memoryUsed += int64(len(memFile.data))
		}
	}
	fs.memoryFS.mu.RUnlock()

	totalSize := fs.totalSize + uint64(memoryUsed)
	totalBlocks := uint64((totalSize + 4095) / 4096)

	stat.Blocks = totalBlocks
	stat.Bfree = 1024 * 1024 * 1024 / 4096 // Pretend 1GB free space
	stat.Bavail = 1024 * 1024 * 1024 / 4096

	fs.memoryFS.mu.RLock()
	fileCount := uint64(len(fs.memoryFS.files))
	fs.memoryFS.mu.RUnlock()

	stat.Files = uint64(len(fs.index.Entries)) + fileCount
	stat.Ffree = uint64(1000000)
	stat.Namemax = uint64(255)

	return 0
}

// Access checks if path is accessible (allowing all operations like memfs)
func (fs *readWriteFS) Access(path string, mask uint32) int {
	return 0
}

// Chmod changes file mode
func (fs *readWriteFS) Chmod(path string, mode uint32) int {
	// Allow chmod on all files like memfs does
	return 0
}

// Chown changes file owner
func (fs *readWriteFS) Chown(path string, uid uint32, gid uint32) int {
	// Allow chown on all files like memfs does
	return 0
}

// Utime changes file times
func (fs *readWriteFS) Utime(path string, tmsp *fuse.Timespec, amtsp *fuse.Timespec) int {
	path = normalizePath(path)

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	if memFile, ok := fs.memoryFS.files[path]; ok {
		if tmsp != nil {
			memFile.modTime = tmsp.Sec
		}
		return 0
	}

	// Container files - allow the operation
	if fs.findEntry(path) != nil {
		return 0
	}

	return -fuse.ENOENT
}

// Truncate changes file size
func (fs *readWriteFS) Truncate(path string, size int64, fh uint64) int {
	path = normalizePath(path)

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	memFile, ok := fs.memoryFS.files[path]
	if !ok {
		return -fuse.ENOENT
	}

	if memFile.isDir {
		return -fuse.EISDIR
	}

	if size < 0 {
		return -fuse.EINVAL
	}

	if size > int64(len(memFile.data)) {
		// Extend with zeros
		newData := make([]byte, size)
		copy(newData, memFile.data)
		memFile.data = newData
	} else {
		// Truncate
		memFile.data = memFile.data[:size]
	}

	memFile.modTime = time.Now().Unix()
	return 0
}

// Mknod creates a special file
func (fs *readWriteFS) Mknod(path string, mode uint32, dev uint64) int {
	return -fuse.EACCES
}

// Link creates a hard link
func (fs *readWriteFS) Link(oldpath string, newpath string) int {
	return -fuse.EACCES
}

// Symlink creates a symbolic link
func (fs *readWriteFS) Symlink(target string, linkpath string) int {
	return -fuse.EACCES
}

// Readlink reads a symbolic link
func (fs *readWriteFS) Readlink(path string) (errc int, target string) {
	return -fuse.ENOSYS, ""
}

// Fsyncdir synchronizes directory contents
func (fs *readWriteFS) Fsyncdir(path string, datasync bool, fh uint64) int {
	return 0
}

// Setxattr sets extended attributes
func (fs *readWriteFS) Setxattr(path string, name string, value []byte, flags int) int {
	// Allow extended attributes like memfs does
	return 0
}

// Getxattr gets extended attributes
func (fs *readWriteFS) Getxattr(path string, name string) (int, []byte) {
	return -fuse.ENODATA, nil
}

// Removexattr removes extended attributes
func (fs *readWriteFS) Removexattr(path string, name string) int {
	return -fuse.EACCES
}

// Listxattr lists extended attributes
func (fs *readWriteFS) Listxattr(path string, fill func(name string) bool) int {
	return 0
}

// Utimens changes file access and modification times
func (fs *readWriteFS) Utimens(path string, tmsp []fuse.Timespec) int {
	path = normalizePath(path)

	fs.memoryFS.mu.Lock()
	defer fs.memoryFS.mu.Unlock()

	if memFile, ok := fs.memoryFS.files[path]; ok {
		if len(tmsp) > 1 {
			memFile.modTime = tmsp[1].Sec
		}
		return 0
	}

	// Container files - allow the operation
	if fs.findEntry(path) != nil {
		return 0
	}

	return -fuse.ENOENT
}

// Init is called when the file system is created
func (fs *readWriteFS) Init() {
}

// Destroy is called when the file system is destroyed
func (fs *readWriteFS) Destroy() {
}

// Helper functions (shared with readOnlyFS)

func (fs *readWriteFS) findEntry(path string) *archiveEntry {
	path = normalizePath(path)

	for _, entry := range fs.index.Entries {
		entryPath := strings.TrimPrefix(entry.Path, "/")
		if entryPath == path {
			return &entry
		}
	}
	return nil
}

func (fs *readWriteFS) isDirectoryPrefix(path string) bool {
	path = normalizePath(path)

	if path == "" {
		return true
	}
	prefix := path + "/"
	for i := range fs.index.Entries {
		entryPath := strings.TrimPrefix(fs.index.Entries[i].Path, "/")
		if strings.HasPrefix(entryPath, prefix) {
			return true
		}
	}
	return false
}

func (fs *readWriteFS) isDirectoryInMemory(path string) bool {
	path = normalizePath(path)

	fs.memoryFS.mu.RLock()
	defer fs.memoryFS.mu.RUnlock()

	if memFile, ok := fs.memoryFS.files[path]; ok {
		return memFile.isDir
	}
	return false
}

func (fs *readWriteFS) isDirectoryPrefixInMemory(path string) bool {
	path = normalizePath(path)

	fs.memoryFS.mu.RLock()
	defer fs.memoryFS.mu.RUnlock()

	if path == "" {
		return true
	}
	prefix := path + "/"
	for fpath := range fs.memoryFS.files {
		if strings.HasPrefix(normalizePath(fpath), prefix) {
			return true
		}
	}
	return false
}

func (fs *readWriteFS) directoryExists(path string) bool {
	path = normalizePath(path)
	if path == "" {
		return true
	}

	if fs.isDirectoryInMemory(path) || fs.isDirectoryPrefixInMemory(path) {
		return true
	}

	entry := fs.findEntry(path)
	if entry != nil && entry.Type == entryTypeDir {
		return true
	}

	return fs.isDirectoryPrefix(path)
}

func (fs *readWriteFS) getDirectoryChildren(path string) []*archiveEntry {
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
			if !strings.Contains(entryPath, "/") {
				if !seen[entryPath] {
					children = append(children, entry)
					seen[entryPath] = true
				}
			} else {
				parts := strings.Split(entryPath, "/")
				if !seen[parts[0]] {
					children = append(children, &archiveEntry{
						Path: "/" + parts[0],
						Type: 1,
						Mode: 0o40555,
					})
					seen[parts[0]] = true
				}
			}
		} else {
			if strings.HasPrefix(entryPath, prefix) {
				rel := strings.TrimPrefix(entryPath, prefix)
				if !strings.Contains(rel, "/") {
					if !seen[rel] {
						children = append(children, entry)
						seen[rel] = true
					}
				} else {
					parts := strings.Split(rel, "/")
					if !seen[parts[0]] {
						children = append(children, &archiveEntry{
							Path: "/" + prefix + parts[0],
							Type: 1,
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

func (fs *readWriteFS) readDecryptedFileData(entry *archiveEntry, offset, length int64) ([]byte, error) {
	if fs.containerReader == nil {
		return nil, errors.New("container reader not open")
	}

	if offset < 0 || length < 0 {
		return nil, errors.New("invalid offset or length")
	}

	maxSize := entry.Size
	if !entry.Compressed && entry.StoredSize > 0 {
		maxSize = entry.StoredSize
	}

	if offset >= maxSize {
		return []byte{}, nil
	}

	var finalData []byte
	if fs.cache.Has(entry.Path) {
		finalData, _ = fs.cache.Get(entry.Path)
	} else {
		if offset+length > maxSize {
			length = maxSize - offset
		}

		storedSize := entry.StoredSize
		if storedSize == 0 {
			storedSize = entry.Size
		}
		if storedSize < 0 {
			return nil, errors.New("invalid stored size")
		}

		cipherChunks, err := fs.getChunks(entry)
		if err != nil {
			return nil, err
		}

		var restoredData []byte
		restoredBytes, restoredData, err := fs.restoreBytes(cipherChunks, entry, storedSize)
		if err != nil {
			return nil, err
		}

		if restoredBytes != storedSize {
			return nil, fmt.Errorf("restored size mismatch: got %d want %d", restoredBytes, storedSize)
		}

		if entry.Compressed {
			finalData, err = fs.decompressData(restoredData)
			if err != nil {
				return nil, err
			}
		} else {
			finalData = restoredData
		}

		fs.cache.Set(entry.Path, finalData)
	}

	if offset > int64(len(finalData)) {
		return []byte{}, nil
	}

	end := offset + length
	if end > int64(len(finalData)) {
		end = int64(len(finalData))
	}

	return finalData[offset:end], nil
}

func (*readWriteFS) decompressData(restoredData []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(restoredData))
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
	return decompressed, nil
}

func (fs *readWriteFS) restoreBytes(cipherChunks [][]byte, entry *archiveEntry, storedSize int64) (int64, []byte, error) {
	restoredData := make([]byte, 0, storedSize)
	restoredBytes := int64(0)
	for i, chunk := range cipherChunks {
		nonce := fs.chunkNonce(entry.NonceSeed, uint32(i))
		plain, err := fs.aead.Open(nil, nonce[:], chunk, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("decrypt chunk %d: %w", i, err)
		}

		remaining := storedSize - restoredBytes
		if remaining <= 0 {
			break
		}

		writeLen := int64(len(plain))
		if remaining < writeLen {
			writeLen = remaining
		}

		restoredData = append(restoredData, plain[:writeLen]...)
		restoredBytes += writeLen
	}
	return restoredBytes, restoredData, nil
}

func (fs *readWriteFS) getChunks(entry *archiveEntry) ([][]byte, error) {
	encChunkSize := int(fs.chunkSize) + aeadTagSize
	cipherChunk := make([]byte, encChunkSize)
	cipherChunks := make([][]byte, 0, entry.ChunkCount)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	for i := uint32(0); i < entry.ChunkCount; i++ {
		err := fs.containerReader.seekAndRead(entry.ContainerIndex, int64(entry.DataOffset)+int64(i)*int64(encChunkSize), cipherChunk)
		if err != nil {
			return nil, fmt.Errorf("read encrypted chunk %d: %w", i, err)
		}
		chunk := make([]byte, len(cipherChunk))
		copy(chunk, cipherChunk)
		cipherChunks = append(cipherChunks, chunk)
	}
	return cipherChunks, nil
}

func (fs *readWriteFS) chunkNonce(seed [8]byte, chunk uint32) [12]byte {
	var nonce [12]byte
	copy(nonce[:8], seed[:])
	binary.LittleEndian.PutUint32(nonce[8:], chunk)
	return nonce
}
