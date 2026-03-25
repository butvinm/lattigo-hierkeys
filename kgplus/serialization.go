package kgplus

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// BinarySize returns the serialized size of the TransmissionKeys in bytes.
func (tk *TransmissionKeys) BinarySize() int {
	size := 0

	if tk.HomingKey != nil {
		size += tk.HomingKey.BinarySize()
	}

	size += 8 // shift-0 count
	for _, gk := range tk.Shift0Keys {
		size += gk.BinarySize()
	}

	size += 8 // number of master keys (uint64)
	for _, gk := range tk.MasterRotKeys {
		size += 8 + gk.BinarySize() // rotation index (int64) + data
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

	// Write shift-0 keys
	nShift0 := uint64(len(tk.Shift0Keys))
	if err = binary.Write(bw, binary.LittleEndian, nShift0); err != nil {
		return n, fmt.Errorf("write shift-0 count: %w", err)
	}
	n += 8

	for i, gk := range tk.Shift0Keys {
		if written, err = gk.WriteTo(bw); err != nil {
			return n, fmt.Errorf("write shift-0 key %d: %w", i, err)
		}
		n += written
	}

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
		gk := tk.MasterRotKeys[rot]
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

	tk.HomingKey = new(rlwe.EvaluationKey)
	if read, err = tk.HomingKey.ReadFrom(br); err != nil {
		return n, fmt.Errorf("read homing key: %w", err)
	}
	n += read

	// Read shift-0 keys
	var nShift0 uint64
	if err = binary.Read(br, binary.LittleEndian, &nShift0); err != nil {
		return n, fmt.Errorf("read shift-0 count: %w", err)
	}
	n += 8

	tk.Shift0Keys = make([]*rlwe.GaloisKey, nShift0)
	for i := uint64(0); i < nShift0; i++ {
		gk := new(rlwe.GaloisKey)
		if read, err = gk.ReadFrom(br); err != nil {
			return n, fmt.Errorf("read shift-0 key %d: %w", i, err)
		}
		n += read
		tk.Shift0Keys[i] = gk
	}

	// Read master rotation keys
	var nMasters uint64
	if err = binary.Read(br, binary.LittleEndian, &nMasters); err != nil {
		return n, fmt.Errorf("read master key count: %w", err)
	}
	n += 8

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

	keyRotsSorted := make([]int, 0, len(ik.Keys))
	for rot := range ik.Keys {
		keyRotsSorted = append(keyRotsSorted, rot)
	}
	sort.Ints(keyRotsSorted)

	for _, rot := range keyRotsSorted {
		gk := ik.Keys[rot]

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

// MarshalBinary encodes the IntermediateKeys into a byte slice.
func (ik *IntermediateKeys) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
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
