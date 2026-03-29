package kgplus

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// BinarySize returns the serialized size of the TransmissionKeys in bytes.
func (tk *TransmissionKeys) BinarySize() int {
	size := 0

	if tk.HomingKey != nil {
		size += tk.HomingKey.BinarySize()
	}

	size += tk.PublicKey.BinarySize()

	size += 8 // number of master keys (uint64)
	for _, mk := range tk.MasterRotKeys {
		size += 8 + mk.BinarySize() // rotation index (int64) + data
	}

	return size
}

// WriteTo writes the TransmissionKeys to the writer.
func (tk *TransmissionKeys) WriteTo(w io.Writer) (n int64, err error) {
	bw := bufio.NewWriter(w)

	var written int64

	if written, err = tk.HomingKey.WriteTo(bw); err != nil {
		return n, fmt.Errorf("write homing key: %w", err)
	}
	n += written

	// Write encryption of zero
	if written, err = tk.PublicKey.WriteTo(bw); err != nil {
		return n, fmt.Errorf("write PublicKey: %w", err)
	}
	n += written

	// Write master rotation keys
	nMasters := uint64(len(tk.MasterRotKeys))
	if err = binary.Write(bw, binary.LittleEndian, nMasters); err != nil {
		return n, fmt.Errorf("write master key count: %w", err)
	}
	n += 8

	masterRotsSorted := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRotsSorted = append(masterRotsSorted, rot)
	}
	sort.Ints(masterRotsSorted)

	for _, rot := range masterRotsSorted {
		mk := tk.MasterRotKeys[rot]
		if err = binary.Write(bw, binary.LittleEndian, int64(rot)); err != nil {
			return n, fmt.Errorf("write rotation index: %w", err)
		}
		n += 8

		if written, err = mk.WriteTo(bw); err != nil {
			return n, fmt.Errorf("write master key rot=%d: %w", rot, err)
		}
		n += written
	}

	if err = bw.Flush(); err != nil {
		return n, err
	}

	return
}

// ReadFrom reads TransmissionKeys from the reader.
func (tk *TransmissionKeys) ReadFrom(r io.Reader) (n int64, err error) {
	br := bufio.NewReader(r)

	var read int64

	tk.HomingKey = new(rlwe.EvaluationKey)
	if read, err = tk.HomingKey.ReadFrom(br); err != nil {
		return n, fmt.Errorf("read homing key: %w", err)
	}
	n += read

	// Read encryption of zero
	tk.PublicKey = new(rlwe.PublicKey)
	if read, err = tk.PublicKey.ReadFrom(br); err != nil {
		return n, fmt.Errorf("read PublicKey: %w", err)
	}
	n += read

	// Read master rotation keys
	var nMasters uint64
	if err = binary.Read(br, binary.LittleEndian, &nMasters); err != nil {
		return n, fmt.Errorf("read master key count: %w", err)
	}
	n += 8

	tk.MasterRotKeys = make(map[int]*hierkeys.MasterKey, nMasters)
	for i := uint64(0); i < nMasters; i++ {
		var rot int64
		if err = binary.Read(br, binary.LittleEndian, &rot); err != nil {
			return n, fmt.Errorf("read rotation index: %w", err)
		}
		n += 8

		mk := new(hierkeys.MasterKey)
		if read, err = mk.ReadFrom(br); err != nil {
			return n, fmt.Errorf("read master key: %w", err)
		}
		n += read

		tk.MasterRotKeys[int(rot)] = mk
	}

	return
}

// MarshalBinary encodes the TransmissionKeys into a byte slice.
func (tk *TransmissionKeys) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, tk.BinarySize())
	w := bytes.NewBuffer(buf)
	if _, err := tk.WriteTo(w); err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// UnmarshalBinary decodes TransmissionKeys from a byte slice.
func (tk *TransmissionKeys) UnmarshalBinary(p []byte) error {
	_, err := tk.ReadFrom(bytes.NewReader(p))
	return err
}
