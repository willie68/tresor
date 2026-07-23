//go:build windows

package tresor

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/winfsp/cgofuse/fuse"
)

// MemoryFS is a simple in-memory FUSE filesystem for testing and debugging
type MemoryFS struct {
	fuse.FileSystemBase
	files      map[string]*memoryNode
	index      map[string]string
	handles    map[uint64]string
	nextHandle uint64
	maxBytes   int64 // 0 means unlimited
	mu         sync.RWMutex
}

// memoryNode represents a file or directory in the in-memory filesystem
type memoryNode struct {
	isDir   bool
	data    []byte // Empty for directories
	modTime int64
}

// NewMemoryFS creates a new in-memory filesystem
func NewMemoryFS() *MemoryFS {
	return NewMemoryFSWithLimit(0)
}

// NewMemoryFSWithLimit creates a new in-memory filesystem with a max byte limit.
// maxBytes == 0 means unlimited.
func NewMemoryFSWithLimit(maxBytes int64) *MemoryFS {
	if maxBytes < 0 {
		maxBytes = 0
	}

	fs := &MemoryFS{
		files:      make(map[string]*memoryNode),
		index:      make(map[string]string),
		handles:    make(map[uint64]string),
		nextHandle: 1,
		maxBytes:   maxBytes,
	}
	// Add root directory
	fs.files[""] = &memoryNode{
		isDir:   true,
		modTime: time.Now().Unix(),
	}
	fs.index[""] = ""
	return fs
}

// Close closes the filesystem
func (fs *MemoryFS) Close() error {
	return nil
}

// Getattr gets file attributes
func (fs *MemoryFS) Getattr(path string, stat *fuse.Stat_t, fh uint64) int {
	path = fs.resolvePath(path, fh)

	fs.mu.RLock()
	path, node, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()

	if !exists {
		return -fuse.ENOENT
	}

	if node.isDir {
		stat.Mode = 0o40777 // drwxrwxrwx
		stat.Nlink = 2
	} else {
		stat.Mode = 0o100777 // -rwxrwxrwx
		stat.Nlink = 1
		stat.Size = int64(len(node.data))
	}
	stat.Uid = 0
	stat.Gid = 0

	if node.modTime > 0 {
		stat.Mtim = fuse.NewTimespec(time.Unix(node.modTime, 0))
	}

	return 0
}

// Open opens a file
func (fs *MemoryFS) Open(path string, flags int) (errc int, fh uint64) {
	path = normalizePath(path)

	fs.mu.Lock()
	path, node, exists := fs.lookupNodeLocked(path)
	if exists && !node.isDir && (flags&os.O_TRUNC) != 0 {
		node.data = node.data[:0]
		node.modTime = time.Now().Unix()
	}
	fs.mu.Unlock()

	if !exists {
		return -fuse.ENOENT, 0
	}

	if node.isDir {
		return -fuse.EISDIR, 0
	}

	return 0, fs.allocHandle(path)
}

// Read reads from a file
func (fs *MemoryFS) Read(path string, buff []byte, ofst int64, fh uint64) int {
	path = fs.resolvePath(path, fh)

	fs.mu.RLock()
	_, node, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()

	if !exists {
		return -fuse.ENOENT
	}

	if node.isDir {
		return -fuse.EISDIR
	}

	if ofst >= int64(len(node.data)) {
		return 0
	}

	end := ofst + int64(len(buff))
	if end > int64(len(node.data)) {
		end = int64(len(node.data))
	}

	n := copy(buff, node.data[ofst:end])
	return n
}

// Create creates a new file
func (fs *MemoryFS) Create(path string, flags int, mode uint32) (errc int, fh uint64) {
	path = normalizePath(path)

	if path == "" || path == "/" {
		return -fuse.EACCES, 0
	}

	// Check parent exists
	parent := getParentPath(path)
	fs.mu.RLock()
	_, parentNode, parentExists := fs.lookupNodeLocked(parent)
	fs.mu.RUnlock()

	if !parentExists || !parentNode.isDir {
		return -fuse.ENOENT, 0
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if already exists
	if existingPath, _, exists := fs.lookupNodeLocked(path); exists {
		path = existingPath
		if (flags & os.O_TRUNC) == 0 {
			// Open existing without truncate
			return 0, fs.allocHandleLocked(path)
		}
	}

	// Create new file
	fs.files[path] = &memoryNode{
		isDir:   false,
		data:    []byte{},
		modTime: time.Now().Unix(),
	}
	fs.index[pathKey(path)] = path

	return 0, fs.allocHandleLocked(path)
}

// Write writes to a file
func (fs *MemoryFS) Write(path string, buff []byte, ofst int64, fh uint64) int {
	path = fs.resolvePath(path, fh)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}

	if node.isDir {
		return -fuse.EISDIR
	}

	// Extend data if necessary
	endOffset := ofst + int64(len(buff))
	if endOffset < 0 {
		return -fuse.EINVAL
	}

	if fs.maxBytes > 0 {
		currentSize := fs.currentDataSizeLocked()
		newFileSize := int64(len(node.data))
		if endOffset > newFileSize {
			newFileSize = endOffset
		}
		projectedSize := currentSize - int64(len(node.data)) + newFileSize
		if projectedSize > fs.maxBytes {
			return -fuse.ENOSPC
		}
	}

	if endOffset > int64(len(node.data)) {
		newData := make([]byte, endOffset)
		copy(newData, node.data)
		node.data = newData
	}

	// Write data
	copy(node.data[ofst:], buff)
	node.modTime = time.Now().Unix()

	return len(buff)
}

// Mkdir creates a directory
func (fs *MemoryFS) Mkdir(path string, mode uint32) int {
	path = normalizePath(path)

	if path == "" || path == "/" {
		return -fuse.EACCES
	}

	// Check parent exists
	parent := getParentPath(path)
	fs.mu.RLock()
	_, parentNode, parentExists := fs.lookupNodeLocked(parent)
	fs.mu.RUnlock()

	if !parentExists || !parentNode.isDir {
		return -fuse.ENOENT
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	// Check if already exists
	if _, _, exists := fs.lookupNodeLocked(path); exists {
		return -fuse.EEXIST
	}

	// Create directory
	fs.files[path] = &memoryNode{
		isDir:   true,
		modTime: time.Now().Unix(),
	}
	fs.index[pathKey(path)] = path

	return 0
}

// Unlink removes a file
func (fs *MemoryFS) Unlink(path string) int {
	path = normalizePath(path)

	if path == "" || path == "/" {
		return -fuse.EACCES
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	actualPath, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}

	if node.isDir {
		return -fuse.EISDIR
	}

	delete(fs.files, actualPath)
	delete(fs.index, pathKey(actualPath))
	return 0
}

// Rmdir removes a directory
func (fs *MemoryFS) Rmdir(path string) int {
	path = normalizePath(path)

	if path == "" || path == "/" {
		return -fuse.EACCES
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	actualPath, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}

	if !node.isDir {
		return -fuse.ENOTDIR
	}

	// Check if directory is empty
	for fpath := range fs.files {
		if fpath != actualPath && strings.HasPrefix(fpath, actualPath+"/") {
			return -fuse.ENOTEMPTY
		}
	}

	delete(fs.files, actualPath)
	delete(fs.index, pathKey(actualPath))
	return 0
}

// Opendir opens a directory
func (fs *MemoryFS) Opendir(path string) (errc int, fh uint64) {
	path = normalizePath(path)

	fs.mu.RLock()
	path, node, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()

	if !exists {
		return -fuse.ENOENT, 0
	}

	if !node.isDir {
		return -fuse.ENOTDIR, 0
	}

	return 0, fs.allocHandle(path)
}

// Readdir reads directory contents
func (fs *MemoryFS) Readdir(path string, fill func(name string, stat *fuse.Stat_t, ofst int64) bool, ofst int64, fh uint64) int {
	path = normalizePath(path)

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Get all entries that start with path/
	prefix := path
	if prefix != "" && prefix != "/" {
		prefix = prefix + "/"
	}

	// Track which top-level entries we've seen
	seen := make(map[string]bool)

	for fpath, node := range fs.files {
		if fpath == path {
			continue // Skip the directory itself
		}

		if prefix == "/" {
			// Root directory
			if !strings.Contains(strings.TrimPrefix(fpath, "/"), "/") {
				// Top-level entry
				name := strings.TrimPrefix(fpath, "/")
				if !seen[name] {
					stat := &fuse.Stat_t{}
					if node.isDir {
						stat.Mode = 0o40777
					} else {
						stat.Mode = 0o100777
						stat.Size = int64(len(node.data))
					}
					if node.modTime > 0 {
						stat.Mtim = fuse.NewTimespec(time.Unix(node.modTime, 0))
					}
					if !fill(name, stat, 0) {
						return -fuse.EIO
					}
					seen[name] = true
				}
			}
		} else {
			// Subdirectory
			if strings.HasPrefix(fpath, prefix) {
				rel := strings.TrimPrefix(fpath, prefix)
				parts := strings.Split(rel, "/")
				name := parts[0]

				if !seen[name] {
					stat := &fuse.Stat_t{}
					if len(parts) == 1 {
						// Direct child
						if node.isDir {
							stat.Mode = 0o40777
						} else {
							stat.Mode = 0o100777
							stat.Size = int64(len(node.data))
						}
					} else {
						// Subdirectory entry
						stat.Mode = 0o40777
					}
					if node.modTime > 0 {
						stat.Mtim = fuse.NewTimespec(time.Unix(node.modTime, 0))
					}
					if !fill(name, stat, 0) {
						return -fuse.EIO
					}
					seen[name] = true
				}
			}
		}
	}

	return 0
}

// Releasedir releases a directory handle
func (fs *MemoryFS) Releasedir(path string, fh uint64) int {
	fs.releaseHandle(fh)
	return 0
}

// Release releases a file handle
func (fs *MemoryFS) Release(path string, fh uint64) int {
	fs.releaseHandle(fh)
	return 0
}

// Flush is called on file close
func (fs *MemoryFS) Flush(path string, fh uint64) int {
	return 0
}

// Fsync synchronizes file data
func (fs *MemoryFS) Fsync(path string, datasync bool, fh uint64) int {
	return 0
}

// Fsyncdir synchronizes directory contents
func (fs *MemoryFS) Fsyncdir(path string, datasync bool, fh uint64) int {
	return 0
}

// Statfs returns filesystem statistics
func (fs *MemoryFS) Statfs(path string, stat *fuse.Statfs_t) int {
	stat.Bsize = uint64(4096)
	stat.Frsize = uint64(4096)

	fs.mu.RLock()
	var totalSize int64
	for _, node := range fs.files {
		if !node.isDir {
			totalSize += int64(len(node.data))
		}
	}
	maxBytes := fs.maxBytes
	fileCount := uint64(len(fs.files))
	fs.mu.RUnlock()

	usedBlocks := uint64((totalSize + 4095) / 4096)
	totalBlocks := uint64(1024 * 1024 * 100 / 4096) // 100MB virtual capacity
	if maxBytes > 0 {
		totalBlocks = uint64((maxBytes + 4095) / 4096)
	}
	if totalBlocks < usedBlocks {
		totalBlocks = usedBlocks
	}
	freeBlocks := totalBlocks - usedBlocks

	stat.Blocks = totalBlocks
	stat.Bfree = freeBlocks
	stat.Bavail = freeBlocks
	stat.Files = fileCount
	stat.Ffree = 1000000
	stat.Namemax = 255

	return 0
}

// Access checks if path is accessible
func (fs *MemoryFS) Access(path string, mask uint32) int {
	path = normalizePath(path)

	fs.mu.RLock()
	_, _, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()

	if !exists {
		return -fuse.ENOENT
	}

	// All files/dirs are readable and writable
	return 0
}

// Chmod changes file mode
func (fs *MemoryFS) Chmod(path string, mode uint32) int {
	path = normalizePath(path)

	fs.mu.RLock()
	_, _, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()

	if !exists {
		return -fuse.ENOENT
	}

	// Allow chmod
	return 0
}

// Chown changes file owner
func (fs *MemoryFS) Chown(path string, uid uint32, gid uint32) int {
	return 0
}

// Utime changes file times
func (fs *MemoryFS) Utime(path string, tmsp *fuse.Timespec, amtsp *fuse.Timespec) int {
	path = normalizePath(path)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}

	if tmsp != nil {
		node.modTime = tmsp.Sec
	}

	return 0
}

// Truncate changes file size
func (fs *MemoryFS) Truncate(path string, size int64, fh uint64) int {
	path = fs.resolvePath(path, fh)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}

	if node.isDir {
		return -fuse.EISDIR
	}

	if size < 0 {
		return -fuse.EINVAL
	}

	if fs.maxBytes > 0 {
		currentSize := fs.currentDataSizeLocked()
		projectedSize := currentSize - int64(len(node.data)) + size
		if projectedSize > fs.maxBytes {
			return -fuse.ENOSPC
		}
	}

	if size > int64(len(node.data)) {
		// Extend with zeros
		newData := make([]byte, size)
		copy(newData, node.data)
		node.data = newData
	} else {
		// Truncate
		node.data = node.data[:size]
	}

	node.modTime = time.Now().Unix()
	return 0
}

// Rename renames a file or directory
func (fs *MemoryFS) Rename(oldpath string, newpath string) int {
	oldpath = normalizePath(oldpath)
	newpath = normalizePath(newpath)

	if oldpath == "" || oldpath == "/" || newpath == "" || newpath == "/" {
		return -fuse.EACCES
	}

	fs.mu.Lock()
	defer fs.mu.Unlock()

	oldpath, node, exists := fs.lookupNodeLocked(oldpath)
	if !exists {
		return -fuse.ENOENT
	}

	if existingTargetPath, existingTarget, exists := fs.lookupNodeLocked(newpath); exists {
		// Support overwrite semantics for file targets (needed by Windows copy /Y).
		if existingTarget.isDir || node.isDir {
			return -fuse.EEXIST
		}
		delete(fs.files, existingTargetPath)
		delete(fs.index, pathKey(existingTargetPath))
	}

	// Move file
	fs.files[newpath] = node
	delete(fs.files, oldpath)
	fs.index[pathKey(newpath)] = newpath
	delete(fs.index, pathKey(oldpath))

	// If it's a directory, rename all children
	if node.isDir {
		prefix := oldpath + "/"
		moved := make(map[string]*memoryNode)
		remove := make([]string, 0)
		for fpath := range fs.files {
			if strings.HasPrefix(fpath, prefix) {
				newFpath := newpath + "/" + strings.TrimPrefix(fpath, prefix)
				moved[newFpath] = fs.files[fpath]
				remove = append(remove, fpath)
			}
		}
		for _, oldChild := range remove {
			delete(fs.files, oldChild)
			delete(fs.index, pathKey(oldChild))
		}
		for newChild, childNode := range moved {
			fs.files[newChild] = childNode
			fs.index[pathKey(newChild)] = newChild
		}
	}
	return 0
}

// Mknod creates a special file
func (fs *MemoryFS) Mknod(path string, mode uint32, dev uint64) int {
	return -fuse.EACCES
}

// Link creates a hard link
func (fs *MemoryFS) Link(oldpath string, newpath string) int {
	return -fuse.EACCES
}

// Symlink creates a symbolic link
func (fs *MemoryFS) Symlink(target string, linkpath string) int {
	return -fuse.EACCES
}

// Readlink reads a symbolic link
func (fs *MemoryFS) Readlink(path string) (errc int, target string) {
	return -fuse.ENOSYS, ""
}

// Setxattr sets extended attributes
func (fs *MemoryFS) Setxattr(path string, name string, value []byte, flags int) int {
	return 0
}

// Getxattr gets extended attributes
func (fs *MemoryFS) Getxattr(path string, name string) (int, []byte) {
	return -fuse.ENODATA, nil
}

// Removexattr removes extended attributes
func (fs *MemoryFS) Removexattr(path string, name string) int {
	return 0
}

// Listxattr lists extended attributes
func (fs *MemoryFS) Listxattr(path string, fill func(name string) bool) int {
	return 0
}

// Getpath returns the canonical path casing for case-insensitive lookup.
func (fs *MemoryFS) Getpath(path string, fh uint64) (int, string) {
	resolved := fs.resolvePath(path, fh)
	fs.mu.RLock()
	actual, _, ok := fs.lookupNodeLocked(resolved)
	fs.mu.RUnlock()
	if !ok {
		return -fuse.ENOENT, ""
	}
	if actual == "" {
		return 0, "/"
	}
	return 0, "/" + actual
}

// Chflags handles Windows file attribute updates.
func (fs *MemoryFS) Chflags(path string, flags uint32) int {
	path = normalizePath(path)
	fs.mu.RLock()
	_, _, exists := fs.lookupNodeLocked(path)
	fs.mu.RUnlock()
	if !exists {
		return -fuse.ENOENT
	}
	// In-memory FS accepts flag changes but does not persist them.
	return 0
}

// Setcrtime handles Windows creation time updates.
func (fs *MemoryFS) Setcrtime(path string, tmsp fuse.Timespec) int {
	path = normalizePath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}
	node.modTime = tmsp.Sec
	return 0
}

// Setchgtime handles Windows change time updates.
func (fs *MemoryFS) Setchgtime(path string, tmsp fuse.Timespec) int {
	path = normalizePath(path)
	fs.mu.Lock()
	defer fs.mu.Unlock()

	_, node, exists := fs.lookupNodeLocked(path)
	if !exists {
		return -fuse.ENOENT
	}
	node.modTime = tmsp.Sec
	return 0
}

// Utimens changes file access and modification times
func (fs *MemoryFS) Utimens(path string, tmsp []fuse.Timespec) int {
	path = normalizePath(path)

	fs.mu.Lock()
	defer fs.mu.Unlock()

	node, exists := fs.files[path]
	if !exists {
		return -fuse.ENOENT
	}

	if len(tmsp) > 1 {
		node.modTime = tmsp[1].Sec
	}

	return 0
}

// Init is called when the file system is created
func (fs *MemoryFS) Init() {
}

// Destroy is called when the file system is destroyed
func (fs *MemoryFS) Destroy() {
}

// Helper functions

func getParentPath(path string) string {
	path = normalizePath(path)
	idx := strings.LastIndex(path, "/")
	if idx == 0 {
		return ""
	}
	if idx > 0 {
		return path[:idx]
	}
	return ""
}

func (fs *MemoryFS) allocHandle(path string) uint64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.allocHandleLocked(path)
}

func (fs *MemoryFS) allocHandleLocked(path string) uint64 {
	fh := fs.nextHandle
	fs.nextHandle++
	fs.handles[fh] = path
	return fh
}

func (fs *MemoryFS) releaseHandle(fh uint64) {
	if fh == 0 {
		return
	}
	fs.mu.Lock()
	delete(fs.handles, fh)
	fs.mu.Unlock()
}

func (fs *MemoryFS) lookupNodeLocked(path string) (string, *memoryNode, bool) {
	actual, ok := fs.index[pathKey(path)]
	if !ok {
		return "", nil, false
	}
	node, ok := fs.files[actual]
	if !ok {
		return "", nil, false
	}
	return actual, node, true
}

func pathKey(path string) string {
	return strings.ToLower(path)
}

func (fs *MemoryFS) resolvePath(path string, fh uint64) string {
	if fh == 0 {
		return normalizePath(path)
	}

	fs.mu.RLock()
	handlePath, ok := fs.handles[fh]
	fs.mu.RUnlock()
	if ok {
		return handlePath
	}

	return normalizePath(path)
}

func (fs *MemoryFS) currentDataSizeLocked() int64 {
	var total int64
	for _, node := range fs.files {
		if !node.isDir {
			total += int64(len(node.data))
		}
	}
	return total
}
