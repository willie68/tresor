package tresor

import "io"

type EncryptOptions struct {
	Password         string
	ContainerPath    string
	Inputs           []string
	RemoveSources    bool
	SecureRemove     bool // Use Gutmann method with 3 passes for secure deletion
	IfExists         string
	OnFileConflict   FileConflictHandler
	ProgressWriter   io.Writer
	MaxContainerSize int64 // Max size per container in bytes; 0 = no limit (single container)
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
	Filter        string // Filter pattern (e.g., ".jpg", "*.jpg", "input", "input\\", "\\input\\", "file.pdf")
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
