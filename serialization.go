package hierkeys

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// BinarySize returns the serialized size of the TransmissionKeys in bytes.
func (tk *TransmissionKeys) BinarySize() int {
	size := 8 // number of master keys (uint64)

	if tk.HomingKey != nil {
		size += 8 + tk.HomingKey.BinarySize() // length prefix + data
	}

	if tk.Shift0Key != nil {
		size += 8 + tk.Shift0Key.BinarySize()
	}

	for _, gk := range tk.MasterRotKeys {
		size += 8 + 8 + gk.BinarySize() // rotation index (int64) + length prefix + data
	}

	return size
}

// WriteTo writes the TransmissionKeys to the writer.
func (tk *TransmissionKeys) WriteTo(w io.Writer) (n int64, err error) {
	bw := bufio.NewWriter(w)

	var written int64

	// Write homing key
	if written, err = tk.HomingKey.WriteTo(bw); err != nil {
		return n, fmt.Errorf("write homing key: %w", err)
	}
	n += written

	// Write shift-0 key
	if written, err = tk.Shift0Key.WriteTo(bw); err != nil {
		return n, fmt.Errorf("write shift-0 key: %w", err)
	}
	n += written

	// Write number of master keys
	nMasters := uint64(len(tk.MasterRotKeys))
	if err = binary.Write(bw, binary.LittleEndian, nMasters); err != nil {
		return n, fmt.Errorf("write master key count: %w", err)
	}
	n += 8

	// Write each master key with its rotation index
	for rot, gk := range tk.MasterRotKeys {
		if err = binary.Write(bw, binary.LittleEndian, int64(rot)); err != nil {
			return n, fmt.Errorf("write rotation index: %w", err)
		}
		n += 8

		if written, err = gk.WriteTo(bw); err != nil {
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

	// Read homing key
	tk.HomingKey = new(rlwe.EvaluationKey)
	if read, err = tk.HomingKey.ReadFrom(br); err != nil {
		return n, fmt.Errorf("read homing key: %w", err)
	}
	n += read

	// Read shift-0 key
	tk.Shift0Key = new(rlwe.GaloisKey)
	if read, err = tk.Shift0Key.ReadFrom(br); err != nil {
		return n, fmt.Errorf("read shift-0 key: %w", err)
	}
	n += read

	// Read number of master keys
	var nMasters uint64
	if err = binary.Read(br, binary.LittleEndian, &nMasters); err != nil {
		return n, fmt.Errorf("read master key count: %w", err)
	}
	n += 8

	// Read each master key
	tk.MasterRotKeys = make(map[int]*rlwe.GaloisKey, nMasters)
	for i := uint64(0); i < nMasters; i++ {
		var rot int64
		if err = binary.Read(br, binary.LittleEndian, &rot); err != nil {
			return n, fmt.Errorf("read rotation index: %w", err)
		}
		n += 8

		gk := new(rlwe.GaloisKey)
		if read, err = gk.ReadFrom(br); err != nil {
			return n, fmt.Errorf("read master key: %w", err)
		}
		n += read

		tk.MasterRotKeys[int(rot)] = gk
	}

	return
}

// WriteTo writes the IntermediateKeys to the writer.
func (ik *IntermediateKeys) WriteTo(w io.Writer) (n int64, err error) {
	bw := bufio.NewWriter(w)

	var written int64

	nKeys := uint64(len(ik.Keys))
	if err = binary.Write(bw, binary.LittleEndian, nKeys); err != nil {
		return n, fmt.Errorf("write key count: %w", err)
	}
	n += 8

	for rot, gk := range ik.Keys {
		if err = binary.Write(bw, binary.LittleEndian, int64(rot)); err != nil {
			return n, fmt.Errorf("write rotation index: %w", err)
		}
		n += 8

		if written, err = gk.WriteTo(bw); err != nil {
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

	ik.Keys = make(map[int]*rlwe.GaloisKey, nKeys)
	for i := uint64(0); i < nKeys; i++ {
		var rot int64
		if err = binary.Read(br, binary.LittleEndian, &rot); err != nil {
			return n, fmt.Errorf("read rotation index: %w", err)
		}
		n += 8

		gk := new(rlwe.GaloisKey)
		if read, err = gk.ReadFrom(br); err != nil {
			return n, fmt.Errorf("read key: %w", err)
		}
		n += read

		ik.Keys[int(rot)] = gk
	}

	return
}
