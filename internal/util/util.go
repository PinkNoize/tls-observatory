package util

import (
	"bufio"
	"io"
)

// Strips off the newline
func ReadLine(r *bufio.Reader) ([]byte, error) {
	buf := []byte(nil)
	lineRead := false
	for !lineRead {
		tmp, err := r.ReadBytes('\n')
		switch err {
		case nil:
			if tmp[len(tmp)-1] == '\n' {
				lineRead = true
				tmp = tmp[:len(tmp)-1]
			}
			buf = append(buf, tmp...)
		case io.EOF:
			buf = append(buf, tmp...)
			return buf, err
		default:
			return nil, err
		}
	}
	return buf, nil
}
