package tresor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	headerMagic         uint32 = 0xA16F3D27
	footerMagic         uint32 = 0x7C9E21B4
	containerVersion    uint16 = 1
	kdfMemoryKB         uint32 = 64 * 1024
	kdfIterations       uint32 = 3
	kdfParallelism      uint8  = 2
	keySize                    = 32
	saltSize                   = 16
	chunkSize           uint32 = 64 * 1024
	aeadTagSize                = 16
	headerSize                 = 31
	inMemoryCompressMax int64  = 32 << 20 // compress files up to 32 MiB in RAM
)

const (
	entryTypeDir  uint8 = 1
	entryTypeFile uint8 = 2
)

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
	Path           string  `json:"path"`
	Mode           uint32  `json:"mode"`
	Type           uint8   `json:"type"`
	Size           int64   `json:"size"`
	ModTime        int64   `json:"mod_time,omitempty"`
	StoredSize     int64   `json:"stored_size,omitempty"`
	Compressed     bool    `json:"compressed,omitempty"`
	DataOffset     uint64  `json:"data_offset,omitempty"`
	DataLength     uint64  `json:"data_length,omitempty"`
	ChunkCount     uint32  `json:"chunk_count,omitempty"`
	NonceSeed      [8]byte `json:"nonce_seed,omitempty"`
	ContainerIndex uint32  `json:"container_index,omitempty"` // 0 = in main .tre, 1+ = in .000, .001, etc
}

func readContainerIndex(containerPath, password string) (containerHeader, archiveIndex, containerFooter, error) {
	cr, err := newContainerReader(containerPath)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
	}
	defer cr.close()

	hdr, index, err := cr.readIndex(password)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
	}

	// Read footer from main container to return it
	mainFile := cr.files[0]
	footer, err := readFooter(mainFile)
	if err != nil {
		return containerHeader{}, archiveIndex{}, containerFooter{}, err
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
