package util

import (
	"compress/gzip"
	"io"
	"os"

	"github.com/gabriel-vasile/mimetype"
	"github.com/ulikunitz/xz"
)

type fileType int

const (
	PLAINTEXT = iota
	GZIP
	XZ
)

func findFileType(file *os.File) (fileType, error) {
	cur_seek, err := file.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}
	defer file.Seek(cur_seek, io.SeekStart)
	content := make([]byte, 512)
	n, err := file.Read(content)
	if err != nil {
		return 0, err
	}
	fType := mimetype.Detect(content[:n])
	switch fType.String() {
	case "application/gzip":
		return GZIP, nil
	case "application/x-xz":
		return XZ, nil
	default:
		return PLAINTEXT, nil
	}
}

func Decompress(fd *os.File) (io.Reader, error) {
	magic, err := findFileType(fd)
	if err != nil {
		return nil, err
	}
	switch magic {
	case PLAINTEXT:
		return fd, nil
	case GZIP:
		r, err := gzip.NewReader(fd)
		if err != nil {
			return nil, err
		}
		return r, nil
	case XZ:
		r, err := xz.NewReader(fd)
		if err != nil {
			return nil, err
		}
		return r, nil
	default:
		return nil, err
	}

}
