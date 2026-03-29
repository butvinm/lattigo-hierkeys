package hierkeys

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// WriteTo writes the IntermediateKeys to the writer.
func (ik *IntermediateKeys) WriteTo(w io.Writer) (n int64, err error) {
	bw := bufio.NewWriter(w)

	var written int64

	nKeys := uint64(len(ik.Keys))
	if err = binary.Write(bw, binary.LittleEndian, nKeys); err != nil {
		return n, fmt.Errorf("write key count: %w", err)
	}
	n += 8

	keyRotsSorted := make([]int, 0, len(ik.Keys))
	for rot := range ik.Keys {
		keyRotsSorted = append(keyRotsSorted, rot)
	}
	sort.Ints(keyRotsSorted)

	for _, rot := range keyRotsSorted {
		mk := ik.Keys[rot]

		if err = binary.Write(bw, binary.LittleEndian, int64(rot)); err != nil {
			return n, fmt.Errorf("write rotation index: %w", err)
		}
		n += 8

		if written, err = mk.WriteTo(bw); err != nil {
			return n, fmt.Errorf("write key rot=%d: %w", rot, err)
		}
		n += written
	}

	if err = bw.Flush(); err != nil {
		return n, err
	}

	return
}

// ReadFrom reads IntermediateKeys from the reader.
func (ik *IntermediateKeys) ReadFrom(r io.Reader) (n int64, err error) {
	br := bufio.NewReader(r)

	var read int64

	var nKeys uint64
	if err = binary.Read(br, binary.LittleEndian, &nKeys); err != nil {
		return n, fmt.Errorf("read key count: %w", err)
	}
	n += 8

	ik.Keys = make(map[int]*MasterKey, nKeys)
	for i := uint64(0); i < nKeys; i++ {
		var rot int64
		if err = binary.Read(br, binary.LittleEndian, &rot); err != nil {
			return n, fmt.Errorf("read rotation index: %w", err)
		}
		n += 8

		mk := new(MasterKey)
		if read, err = mk.ReadFrom(br); err != nil {
			return n, fmt.Errorf("read key: %w", err)
		}
		n += read

		ik.Keys[int(rot)] = mk
	}

	return
}

// BinarySize returns the serialized size of the IntermediateKeys in bytes.
func (ik *IntermediateKeys) BinarySize() int {
	size := 8 // key count
	for _, mk := range ik.Keys {
		size += 8 + mk.BinarySize() // rotation index + key data
	}
	return size
}

// MarshalBinary encodes the IntermediateKeys into a byte slice.
func (ik *IntermediateKeys) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, ik.BinarySize()))
	if _, err := ik.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes IntermediateKeys from a byte slice.
func (ik *IntermediateKeys) UnmarshalBinary(p []byte) error {
	_, err := ik.ReadFrom(bytes.NewReader(p))
	return err
}
