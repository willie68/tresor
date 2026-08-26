package tresor

import (
	"fmt"
	"io"
	"os"
)

type containerWriter struct {
	basePath        string              // e.g., "tresor.tre"
	maxSize         int64               // Max payload size per container; 0 = unlimited
	currentFile     *os.File            // Current container file handle
	currentIndex    uint32              // 0 for main, 1+ for .000, .001, etc
	currentSize     int64               // Bytes written to current container (after header)
	firstDataOffset int64               // Offset of first payload in current container (after header)
	files           map[uint32]*os.File // Map of open container files
	tmpPaths        map[uint32]string   // Track .tmp paths
}

// newContainerWriter creates a writer for potentially multiple containers
func newContainerWriter(basePath string, maxSize int64) *containerWriter {
	return &containerWriter{
		basePath:        basePath,
		maxSize:         maxSize,
		currentIndex:    0,
		firstDataOffset: int64(headerSize),
		files:           make(map[uint32]*os.File),
		tmpPaths:        make(map[uint32]string),
	}
}

// getPath returns the file path for a given container index
func (cw *containerWriter) getPath(index uint32) string {
	if index == 0 {
		return cw.basePath + ".tmp"
	}
	return fmt.Sprintf("%s.%03d.tmp", cw.basePath, index-1)
}

// finalPath returns the final (non-tmp) file path
func (cw *containerWriter) finalPath(index uint32) string {
	if index == 0 {
		return cw.basePath
	}
	return fmt.Sprintf("%s.%03d", cw.basePath, index-1)
}

// switchContainer closes current and opens next container if needed
// Returns (shouldSwitch, error)
func (cw *containerWriter) checkSwitchContainer(dataSize int64) (bool, error) {
	if cw.maxSize <= 0 {
		return false, nil // No limit, stay in current container
	}

	// Calculate size after writing this data
	projectedSize := cw.currentSize + dataSize
	if projectedSize <= cw.maxSize {
		return false, nil // Fits in current container
	}

	// Need to switch to next container
	return true, nil
}

// ensureContainerOpen creates/opens the current container file
func (cw *containerWriter) ensureContainerOpen() (*os.File, error) {
	if cw.currentFile != nil {
		return cw.currentFile, nil
	}

	tmpPath := cw.getPath(cw.currentIndex)
	f, err := os.Create(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("create container %d: %w", cw.currentIndex, err)
	}

	cw.currentFile = f
	cw.tmpPaths[cw.currentIndex] = tmpPath
	cw.files[cw.currentIndex] = f
	cw.currentSize = 0
	return f, nil
}

// switchToNextContainer closes current container and switches to next (but keeps it open)
func (cw *containerWriter) switchToNextContainer(hdr containerHeader) error {
	// Don't close the file - keep all containers open until finalize
	// Just mark that we're moving to a new one
	cw.currentIndex++
	cw.currentFile = nil // Reset so ensureContainerOpen creates new file for this index
	cw.currentSize = 0
	cw.firstDataOffset = int64(headerSize)

	// Open and write header to new container
	f, err := cw.ensureContainerOpen()
	if err != nil {
		return err
	}

	if err := writeHeader(f, hdr); err != nil {
		return fmt.Errorf("write header to container %d: %w", cw.currentIndex, err)
	}

	cw.currentSize = int64(headerSize)
	return nil
}

// write appends data to current container
func (cw *containerWriter) write(data []byte) error {
	f, err := cw.ensureContainerOpen()
	if err != nil {
		return err
	}

	n, err := f.Write(data)
	if err != nil {
		return fmt.Errorf("write to container %d: %w", cw.currentIndex, err)
	}

	cw.currentSize += int64(n)
	return nil
}

// seek returns current position in current container
func (cw *containerWriter) seek(offset int64, whence int) (int64, error) {
	f, err := cw.ensureContainerOpen()
	if err != nil {
		return 0, err
	}
	return f.Seek(offset, whence)
}

// getCurrentOffset returns the current write position in the current container
func (cw *containerWriter) getCurrentOffset() (int64, error) {
	f, err := cw.ensureContainerOpen()
	if err != nil {
		return 0, err
	}
	return f.Seek(0, io.SeekCurrent)
}

// close closes all container files
func (cw *containerWriter) close() error {
	var lastErr error
	for _, f := range cw.files {
		if f != nil {
			if err := f.Close(); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// cleanup removes all temporary files
func (cw *containerWriter) cleanup() {
	for _, tmpPath := range cw.tmpPaths {
		_ = os.Remove(tmpPath)
	}
}

// finalize atomically renames all tmp files to final paths
func (cw *containerWriter) finalize() error {
	for idx, tmpPath := range cw.tmpPaths {
		finalPath := cw.finalPath(idx)
		// Remove any existing file first
		_ = os.Remove(finalPath)
		if err := os.Rename(tmpPath, finalPath); err != nil {
			return fmt.Errorf("finalize container %d: %w", idx, err)
		}
	}
	return nil
}
