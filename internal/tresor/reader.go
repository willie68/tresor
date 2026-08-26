package tresor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type containerReader struct {
	basePath string              // e.g., "tresor.tre"
	files    map[uint32]*os.File // Open container files by index (0 = main, 1+ = .000, .001, etc)
	headers  map[uint32]containerHeader
	mainHdr  containerHeader
}

// newContainerReader opens all available container files for reading
func newContainerReader(basePath string) (*containerReader, error) {
	cr := &containerReader{
		basePath: basePath,
		files:    make(map[uint32]*os.File),
		headers:  make(map[uint32]containerHeader),
	}

	// Open main container (index 0)
	mainFile, err := os.Open(basePath)
	if err != nil {
		return nil, fmt.Errorf("open main container: %w", err)
	}
	hdr, err := readHeader(mainFile)
	if err != nil {
		_ = mainFile.Close()
		return nil, err
	}
	cr.mainHdr = hdr
	cr.files[0] = mainFile
	cr.headers[0] = hdr

	// Try to open sidecar containers (index 1+)
	for i := 0; i < 1000; i++ { // Reasonable upper limit
		sidecarPath := fmt.Sprintf("%s.%03d", basePath, i)
		sidecarFile, err := os.Open(sidecarPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// No more sidecar containers
				break
			}
			// Other error - cleanup and return
			cr.close()
			return nil, fmt.Errorf("open sidecar container %d: %w", i+1, err)
		}

		hdr, err := readHeader(sidecarFile)
		if err != nil {
			sidecarFile.Close()
			cr.close()
			return nil, fmt.Errorf("read header of sidecar %d: %w", i+1, err)
		}

		cr.files[uint32(i+1)] = sidecarFile
		cr.headers[uint32(i+1)] = hdr
	}

	return cr, nil
}

// readIndex reads and decrypts the index from main container
func (cr *containerReader) readIndex(password string) (containerHeader, archiveIndex, error) {
	mainFile := cr.files[0]
	if mainFile == nil {
		return containerHeader{}, archiveIndex{}, errors.New("main container not open")
	}

	// Build AEAD with main container header
	aead, err := buildAEAD(password, cr.mainHdr)
	if err != nil {
		return containerHeader{}, archiveIndex{}, err
	}

	// Read footer (always at end of main container)
	if _, err := mainFile.Seek(0, io.SeekEnd); err != nil {
		return containerHeader{}, archiveIndex{}, err
	}
	fileSize, err := mainFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return containerHeader{}, archiveIndex{}, err
	}

	if _, err := mainFile.Seek(-footerSize, io.SeekEnd); err != nil {
		return containerHeader{}, archiveIndex{}, fmt.Errorf("seek footer: %w", err)
	}

	footer, err := readFooter(mainFile)
	if err != nil {
		return containerHeader{}, archiveIndex{}, err
	}

	// Validate index bounds
	if footer.IndexOffset < uint64(headerSize) || footer.IndexOffset+footer.IndexLength > uint64(fileSize) {
		return containerHeader{}, archiveIndex{}, errors.New("invalid index bounds in footer")
	}

	// Read and decrypt index
	if _, err := mainFile.Seek(int64(footer.IndexOffset), io.SeekStart); err != nil {
		return containerHeader{}, archiveIndex{}, err
	}

	indexCipher := make([]byte, footer.IndexLength)
	if _, err := io.ReadFull(mainFile, indexCipher); err != nil {
		return containerHeader{}, archiveIndex{}, fmt.Errorf("read index ciphertext: %w", err)
	}

	indexPlain, err := aead.Open(nil, footer.IndexNonce[:], indexCipher, nil)
	if err != nil {
		if isAuthFailure(err) {
			return containerHeader{}, archiveIndex{}, errors.New("invalid password or corrupted container")
		}
		return containerHeader{}, archiveIndex{}, fmt.Errorf("decrypt index: %w", err)
	}

	var index archiveIndex
	if err := json.Unmarshal(indexPlain, &index); err != nil {
		return containerHeader{}, archiveIndex{}, fmt.Errorf("unmarshal index: %w", err)
	}

	if index.ChunkSize == 0 {
		return containerHeader{}, archiveIndex{}, errors.New("invalid chunk size in index")
	}

	return cr.mainHdr, index, nil
}

// getContainerFile returns the file handle for a given container index, or error if not available
func (cr *containerReader) getContainerFile(containerIndex uint32) (*os.File, error) {
	f := cr.files[containerIndex]
	if f == nil {
		return nil, fmt.Errorf("container %d not available", containerIndex)
	}
	return f, nil
}

// seekAndRead seeks to offset in specified container and reads data
func (cr *containerReader) seekAndRead(containerIndex uint32, offset int64, data []byte) error {
	f, err := cr.getContainerFile(containerIndex)
	if err != nil {
		return err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek in container %d: %w", containerIndex, err)
	}
	if _, err := io.ReadFull(f, data); err != nil {
		return fmt.Errorf("read from container %d: %w", containerIndex, err)
	}
	return nil
}

// close closes all container files
func (cr *containerReader) close() {
	for _, f := range cr.files {
		if f != nil {
			_ = f.Close()
		}
	}
}
