package hierkeys

import (
	"fmt"
	"io"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// MasterKey is a rotation key in paper convention (automorph-then-keyswitch),
// used as input to [RotToRot] expansion.
//
// Construct via:
//   - [GaloisKeyToMasterKey]: converts a standard lattigo GaloisKey (recommended)
//   - [NewMasterKey]: raw constructor, caller asserts paper convention
//   - [PubToRot], [RotToRot]: returned by derivation primitives
//
// Convert back to standard lattigo convention with [MasterKeyToGaloisKey].
type MasterKey struct {
	gk *rlwe.GaloisKey
}

// NewMasterKey wraps a GaloisKey as a MasterKey.
// The caller asserts that gk is already in paper convention
// (EvalKey with skIn=σ_r(s), skOut=s).
//
// Prefer [GaloisKeyToMasterKey] which converts from standard lattigo
// convention automatically.
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
	return mk.gk.WriteTo(w)
}

// ReadFrom reads a MasterKey from the reader.
func (mk *MasterKey) ReadFrom(r io.Reader) (n int64, err error) {
	if mk.gk == nil {
		mk.gk = new(rlwe.GaloisKey)
	}
	return mk.gk.ReadFrom(r)
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

// GaloisKeyToMasterKey converts a standard lattigo [rlwe.GaloisKey] to a
// [MasterKey] by applying σ_r to all GadgetCiphertext components.
// Consumes the input in-place.
func GaloisKeyToMasterKey(params rlwe.Parameters, gk *rlwe.GaloisKey) (*MasterKey, error) {
	if err := automorphGadgetCiphertext(params, gk, gk.GaloisElement); err != nil {
		return nil, err
	}
	return &MasterKey{gk: gk}, nil
}

// MasterKeyToGaloisKey converts a [MasterKey] back to a standard lattigo
// [rlwe.GaloisKey] by applying σ^{-1}_r to all GadgetCiphertext components.
// Consumes the MasterKey in-place.
func MasterKeyToGaloisKey(params rlwe.Parameters, mk *MasterKey) (*rlwe.GaloisKey, error) {
	gk := mk.gk
	mk.gk = nil // consume
	galElInv := params.ModInvGaloisElement(gk.GaloisElement)
	if err := automorphGadgetCiphertext(params, gk, galElInv); err != nil {
		return nil, err
	}
	return gk, nil
}

// automorphGadgetCiphertext applies an automorphism (identified by galEl) to every
// component of a GaloisKey's GadgetCiphertext in-place.
func automorphGadgetCiphertext(params rlwe.Parameters, gk *rlwe.GaloisKey, galEl uint64) error {
	ringQ := params.RingQ()
	ringP := params.RingP()

	indexQ, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galEl)
	if err != nil {
		return fmt.Errorf("Q automorphism index: %w", err)
	}

	var indexP []uint64
	if ringP != nil {
		indexP, err = ring.AutomorphismNTTIndex(ringP.N(), ringP.NthRoot(), galEl)
		if err != nil {
			return fmt.Errorf("P automorphism index: %w", err)
		}
	}

	for i := range gk.Value {
		for j := range gk.Value[i] {
			component := gk.Value[i][j]

			automorphInPlace(ringQ, indexQ, component[0].Q)
			if ringP != nil {
				automorphInPlace(ringP, indexP, component[0].P)
			}

			automorphInPlace(ringQ, indexQ, component[1].Q)
			if ringP != nil {
				automorphInPlace(ringP, indexP, component[1].P)
			}
		}
	}

	return nil
}

// automorphInPlace applies an automorphism to a polynomial using a pre-computed
// index. Allocates a temporary buffer internally.
func automorphInPlace(r *ring.Ring, index []uint64, p ring.Poly) {
	tmp := r.NewPoly()
	r.AutomorphismNTTWithIndex(p, index, tmp)
	p.CopyLvl(p.Level(), tmp)
}
