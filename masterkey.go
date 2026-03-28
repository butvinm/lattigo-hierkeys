package hierkeys

import (
	"bufio"
	"io"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/utils/buffer"
)

// MasterKey is a rotation key in paper convention (automorph-then-keyswitch),
// used as input to [RotToRot] expansion. It wraps an [rlwe.GaloisKey] and
// enforces convention awareness at the type level.
//
// Construct via [NewMasterKey] (multiparty), or receive from [PubToRot] /
// [RotToRot]. Single-party code receives MasterKeys from package-level
// GenTransmissionKeys and ExpandLevel.
//
// After expansion, convert to standard lattigo convention with
// [ConvertToLattigoConvention], which consumes the MasterKey and returns
// a standard [rlwe.GaloisKey].
type MasterKey struct {
	gk *rlwe.GaloisKey
}

// NewMasterKey wraps a GaloisKey as a MasterKey.
// The caller asserts that gk is in paper convention
// (EvalKey with skIn=σ_r(s), skOut=s).
func NewMasterKey(gk *rlwe.GaloisKey) *MasterKey {
	return &MasterKey{gk: gk}
}

// GaloisKey returns the underlying GaloisKey.
func (mk *MasterKey) GaloisKey() *rlwe.GaloisKey {
	return mk.gk
}

// GaloisElement returns the Galois element of the underlying key.
func (mk *MasterKey) GaloisElement() uint64 {
	return mk.gk.GaloisElement
}

// NthRoot returns the NthRoot of the underlying key.
func (mk *MasterKey) NthRoot() uint64 {
	return mk.gk.NthRoot
}

// BinarySize returns the serialized size of the MasterKey in bytes.
func (mk *MasterKey) BinarySize() int {
	return mk.gk.BinarySize()
}

// WriteTo writes the MasterKey to the writer.
func (mk *MasterKey) WriteTo(w io.Writer) (n int64, err error) {
	switch w := w.(type) {
	case buffer.Writer:
		return mk.gk.WriteTo(w)
	default:
		return mk.WriteTo(bufio.NewWriter(w))
	}
}

// ReadFrom reads a MasterKey from the reader.
func (mk *MasterKey) ReadFrom(r io.Reader) (n int64, err error) {
	if mk.gk == nil {
		mk.gk = new(rlwe.GaloisKey)
	}
	switch r := r.(type) {
	case buffer.Reader:
		return mk.gk.ReadFrom(r)
	default:
		return mk.ReadFrom(bufio.NewReader(r))
	}
}

// MarshalBinary encodes the MasterKey into a binary form.
func (mk *MasterKey) MarshalBinary() ([]byte, error) {
	return mk.gk.MarshalBinary()
}

// UnmarshalBinary decodes a MasterKey from binary form.
func (mk *MasterKey) UnmarshalBinary(p []byte) error {
	if mk.gk == nil {
		mk.gk = new(rlwe.GaloisKey)
	}
	return mk.gk.UnmarshalBinary(p)
}
