//go:build !windows

package tresor

import (
	"errors"
)

// readOnlyFS stub for non-Windows platforms
type readOnlyFS struct{}

// NewReadOnlyFS returns an error on non-Windows platforms
func NewReadOnlyFS(containerPath, password string) (*readOnlyFS, error) {
	return nil, errors.New("FUSE mount is only supported on Windows")
}

// Close is a no-op stub
func (fs *readOnlyFS) Close() error {
	return nil
}

// Stub implementations of FUSE interface methods
func (fs *readOnlyFS) Init()                                                            {}
func (fs *readOnlyFS) Destroy()                                                         {}
func (fs *readOnlyFS) Statfs(path string, stat interface{}) int                         { return -5 } // EIO
func (fs *readOnlyFS) Getattr(path string, stat interface{}, fh uint64) int             { return -2 } // ENOENT
func (fs *readOnlyFS) Open(path string, flags interface{}) (int, uint64)                { return -1, 0 }
func (fs *readOnlyFS) Read(path string, buff []byte, ofst int64, fh uint64) int         { return 0 }
func (fs *readOnlyFS) Release(path string, fh uint64) int                               { return 0 }
func (fs *readOnlyFS) Opendir(path string, fh *uint64) int                              { return 0 }
func (fs *readOnlyFS) Readdir(path string, fill interface{}, ofst int64, fh uint64) int { return 0 }
func (fs *readOnlyFS) Releasedir(path string, fh uint64) int                            { return 0 }
func (fs *readOnlyFS) Access(path string, mask uint32) int                              { return 0 }
func (fs *readOnlyFS) Mkdir(path string, mode interface{}) int                          { return -30 } // EROFS
func (fs *readOnlyFS) Rmdir(path string) int                                            { return -30 } // EROFS
func (fs *readOnlyFS) Unlink(path string) int                                           { return -30 } // EROFS
func (fs *readOnlyFS) Rename(oldpath, newpath string) int                               { return -30 } // EROFS
func (fs *readOnlyFS) Create(path string, flags interface{}, mode interface{}) (int, uint64) {
	return -30, 0
}                                                                                      // EROFS
func (fs *readOnlyFS) Write(path string, buff []byte, ofst int64, fh uint64) int       { return -30 }      // EROFS
func (fs *readOnlyFS) Truncate(path string, size int64, fh uint64) int                 { return -30 }      // EROFS
func (fs *readOnlyFS) Chmod(path string, mode interface{}) int                         { return -30 }      // EROFS
func (fs *readOnlyFS) Chown(path string, uid interface{}, gid interface{}) int         { return -30 }      // EROFS
func (fs *readOnlyFS) Utimens(path string, tmsp []interface{}) int                     { return -30 }      // EROFS
func (fs *readOnlyFS) Link(oldpath, newpath string) int                                { return -30 }      // EROFS
func (fs *readOnlyFS) Symlink(target, newpath string) int                              { return -30 }      // EROFS
func (fs *readOnlyFS) Readlink(path string) (int, string)                              { return -2, "" }   // ENOENT
func (fs *readOnlyFS) Getxattr(path, name string) (int, []byte)                        { return -61, nil } // ENODATA
func (fs *readOnlyFS) Setxattr(path, name string, value []byte, flags interface{}) int { return -30 }      // EROFS
func (fs *readOnlyFS) Removexattr(path, name string) int                               { return -30 }      // EROFS
func (fs *readOnlyFS) Listxattr(path string, fill interface{}) int                     { return 0 }
func (fs *readOnlyFS) Fsync(path string, datasync bool, fh uint64) int                 { return 0 }
