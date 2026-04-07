// Package kgplus implements KG+ hierarchical rotation key derivation with ring switching (R', degree 2N).
//
//	Client: rlwe.GenSecretKeyNew (×2) → ConstructExtendedSK → rlwe.GenGaloisKeyNew → hierkeys.GaloisKeyToMasterKey → TransmissionKeys
//	Server: PubToRot → NewLevelExpansion (per level) → FinalizeKey (per key, ring-switch + convention convert) → rlwe.MemEvaluationKeySet
//
// See example/kgplus/simple for complete single-party flow,
// and example/kgplus/multiparty for N-out-of-N multiparty.
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

// TransmissionKeys holds the client-to-server data for hierarchical key derivation.
type TransmissionKeys struct {
	HomingKey     *rlwe.EvaluationKey         // EvalKey(s̃₁ → s) at HK level
	PublicKey     *rlwe.PublicKey             // in R' at top Levels level, used by PubToRot
	MasterRotKeys map[int]*hierkeys.MasterKey // in R' at top Levels level, indexed by rotation
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

// MarshalBinary encodes the TransmissionKeys into a byte slice.
func (tk *TransmissionKeys) MarshalBinary() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, tk.BinarySize()))
	if _, err := tk.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// UnmarshalBinary decodes TransmissionKeys from a byte slice.
func (tk *TransmissionKeys) UnmarshalBinary(p []byte) error {
	_, err := tk.ReadFrom(bytes.NewReader(p))
	return err
}

// ConstructExtendedSK builds s̃ = s + Y·s̃₁ in R' (degree 2N) from two
// independent HK-level secret keys. skS and skS1 must be different keys.
//
// For k>2, paramsRP.Q may include primes beyond paramsHK.Q (the HK P primes).
// These extra coefficient slots are filled from skS.P and skS1.P.
func ConstructExtendedSK(paramsHK, paramsRP rlwe.Parameters, skS, skS1 *rlwe.SecretKey) *rlwe.SecretKey {
	N := paramsHK.N()
	ringQHK := paramsHK.RingQ()
	ringPHK := paramsHK.RingP()
	ringQRP := paramsRP.RingQ()

	skTilde := rlwe.NewSecretKey(paramsRP)

	// Convert s and s̃₁ Q-part from NTT+Montgomery to coefficient domain.
	sCoeffsQ := ringQHK.NewPoly()
	s1CoeffsQ := ringQHK.NewPoly()
	ringQHK.IMForm(skS.Value.Q, sCoeffsQ)
	ringQHK.INTT(sCoeffsQ, sCoeffsQ)
	ringQHK.IMForm(skS1.Value.Q, s1CoeffsQ)
	ringQHK.INTT(s1CoeffsQ, s1CoeffsQ)

	// Interleave into R' (degree 2N): even = s, odd = s̃₁
	sTildeCoeffs := ringQRP.NewPoly()

	// Fill from HK Q primes
	nQFromQ := paramsRP.QCount()
	if nQFromQ > paramsHK.QCount() {
		nQFromQ = paramsHK.QCount()
	}
	for m := 0; m < nQFromQ; m++ {
		for j := 0; j < N; j++ {
			sTildeCoeffs.Coeffs[m][2*j] = sCoeffsQ.Coeffs[m][j]
			sTildeCoeffs.Coeffs[m][2*j+1] = s1CoeffsQ.Coeffs[m][j]
		}
	}

	// Fill additional Q primes from HK P primes (for k>2 where Levels.Q > HK.Q)
	if paramsRP.QCount() > paramsHK.QCount() && ringPHK != nil {
		sCoeffsP := ringPHK.NewPoly()
		s1CoeffsP := ringPHK.NewPoly()
		ringPHK.IMForm(skS.Value.P, sCoeffsP)
		ringPHK.INTT(sCoeffsP, sCoeffsP)
		ringPHK.IMForm(skS1.Value.P, s1CoeffsP)
		ringPHK.INTT(s1CoeffsP, s1CoeffsP)

		nExtra := paramsRP.QCount() - paramsHK.QCount()
		if nExtra > paramsHK.PCount() {
			nExtra = paramsHK.PCount()
		}
		for m := 0; m < nExtra; m++ {
			rpIdx := paramsHK.QCount() + m
			for j := 0; j < N; j++ {
				sTildeCoeffs.Coeffs[rpIdx][2*j] = sCoeffsP.Coeffs[m][j]
				sTildeCoeffs.Coeffs[rpIdx][2*j+1] = s1CoeffsP.Coeffs[m][j]
			}
		}
	}

	ringQRP.NTT(sTildeCoeffs, skTilde.Value.Q)
	ringQRP.MForm(skTilde.Value.Q, skTilde.Value.Q)

	// Extend to P basis
	if paramsRP.PCount() > 0 {
		ringQP := paramsRP.RingQP().AtLevel(skTilde.LevelQ(), skTilde.LevelP())
		ringQP.ExtendBasisSmallNormAndCenter(sTildeCoeffs, skTilde.LevelP(), sTildeCoeffs, skTilde.Value.P)
		paramsRP.RingP().NTT(skTilde.Value.P, skTilde.Value.P)
		paramsRP.RingP().MForm(skTilde.Value.P, skTilde.Value.P)
	}

	return skTilde
}
