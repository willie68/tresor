package tresor

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
)

var errCompressionNotSmaller = errors.New("compressed payload is not smaller")

type preparedPayload struct {
	reader       io.Reader
	originalSize int64
	storedSize   int64
	compressed   bool
	cleanup      func()
}

// capWriter stops gzip once the output would no longer be smaller than the original.
type capWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.n+int64(len(p)) >= c.limit {
		return 0, errCompressionNotSmaller
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func preparePayload(sourcePath string) (preparedPayload, error) {
	return preparePayloadWithLimit(sourcePath, inMemoryCompressMax)
}

func preparePayloadWithLimit(sourcePath string, memoryLimit int64) (preparedPayload, error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return preparedPayload{}, fmt.Errorf("stat %q: %w", sourcePath, err)
	}
	originalSize := info.Size()
	if originalSize == 0 {
		return openUncompressedPayload(sourcePath, originalSize)
	}
	if originalSize <= memoryLimit {
		return preparePayloadInMemory(sourcePath, originalSize)
	}
	return preparePayloadTempFile(sourcePath, originalSize)
}

func preparePayloadInMemory(sourcePath string, originalSize int64) (preparedPayload, error) {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return preparedPayload{}, fmt.Errorf("read %q: %w", sourcePath, err)
	}

	var compressed bytes.Buffer
	err = compressIfSmaller(bytes.NewReader(data), &compressed, originalSize)
	if errors.Is(err, errCompressionNotSmaller) {
		return preparedPayload{
			reader:       bytes.NewReader(data),
			originalSize: originalSize,
			storedSize:   originalSize,
			compressed:   false,
			cleanup:      func() {},
		}, nil
	}
	if err != nil {
		return preparedPayload{}, fmt.Errorf("compress %q: %w", sourcePath, err)
	}

	return preparedPayload{
		reader:       bytes.NewReader(compressed.Bytes()),
		originalSize: originalSize,
		storedSize:   int64(compressed.Len()),
		compressed:   true,
		cleanup:      func() {},
	}, nil
}

func preparePayloadTempFile(sourcePath string, originalSize int64) (preparedPayload, error) {
	in, err := os.Open(sourcePath)
	if err != nil {
		return preparedPayload{}, fmt.Errorf("open %q: %w", sourcePath, err)
	}
	defer func() {
		_ = in.Close()
	}()

	tmp, err := os.CreateTemp("", "tresor-compress-*")
	if err != nil {
		return preparedPayload{}, fmt.Errorf("create temp compression file: %w", err)
	}
	tmpName := tmp.Name()
	cleanupTmp := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	err = compressIfSmaller(in, tmp, originalSize)
	if errors.Is(err, errCompressionNotSmaller) {
		cleanupTmp()
		return openUncompressedPayload(sourcePath, originalSize)
	}
	if err != nil {
		cleanupTmp()
		return preparedPayload{}, fmt.Errorf("compress %q: %w", sourcePath, err)
	}

	compressedInfo, err := tmp.Stat()
	if err != nil {
		cleanupTmp()
		return preparedPayload{}, fmt.Errorf("stat compressed data for %q: %w", sourcePath, err)
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		cleanupTmp()
		return preparedPayload{}, fmt.Errorf("seek compressed temp for %q: %w", sourcePath, err)
	}

	return preparedPayload{
		reader:       tmp,
		originalSize: originalSize,
		storedSize:   compressedInfo.Size(),
		compressed:   true,
		cleanup: func() {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		},
	}, nil
}

func openUncompressedPayload(sourcePath string, originalSize int64) (preparedPayload, error) {
	f, err := os.Open(sourcePath)
	if err != nil {
		return preparedPayload{}, fmt.Errorf("open %q: %w", sourcePath, err)
	}
	return preparedPayload{
		reader:       f,
		originalSize: originalSize,
		storedSize:   originalSize,
		compressed:   false,
		cleanup: func() {
			_ = f.Close()
		},
	}, nil
}

func compressIfSmaller(r io.Reader, w io.Writer, originalSize int64) error {
	zw, err := gzip.NewWriterLevel(&capWriter{w: w, limit: originalSize}, gzip.BestSpeed)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(zw, r)
	closeErr := zw.Close()
	if errors.Is(copyErr, errCompressionNotSmaller) || errors.Is(closeErr, errCompressionNotSmaller) {
		return errCompressionNotSmaller
	}
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
