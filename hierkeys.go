package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// MasterRotationsForBase returns the set of master rotation indices for a
// p-ary number system with the given base and number of slots.
//
// For base=4, nSlots=32768: returns {1, 4, 16, 64, 256, 1024, 4096, 16384}.
// These are powers of base up to nSlots/2 (since rotations are mod nSlots).
//
// With these master keys, any rotation in [1, nSlots/2] can be decomposed as a
// sum of at most ceil(log_base(nSlots)) master rotations via RotToRot.
// Negative rotations are normalized to positive equivalents by DeriveGaloisKeys.
func MasterRotationsForBase(base, nSlots int) []int {
	if base < 2 || nSlots < 1 {
		return nil
	}
	rots := make([]int, 0)
	for p := 1; p <= nSlots/2; p *= base {
		rots = append(rots, p)
	}
	return rots
}

// DecomposeRotation decomposes a target rotation as a sum of master rotation
// indices using greedy p-ary decomposition (largest master first).
//
// masterRots must be a sorted (ascending) p-ary set (powers of some base p)
// as produced by [MasterRotationsForBase]. The function greedily subtracts
// the largest fitting master at each step, which is optimal for p-ary sets.
//
// Returns a sequence of master rotation indices whose sum equals target.
// Returns nil if target cannot be decomposed (e.g., target <= 0 or no masters).
func DecomposeRotation(target int, masterRots []int) []int {
	if target <= 0 || len(masterRots) == 0 {
		return nil
	}

	result := make([]int, 0)
	remaining := target

	// Greedy from largest to smallest master rotation
	for i := len(masterRots) - 1; i >= 0 && remaining > 0; i-- {
		m := masterRots[i]
		for remaining >= m {
			result = append(result, m)
			remaining -= m
		}
	}

	if remaining != 0 {
		return nil // cannot fully decompose
	}
	return result
}

// GaloisKeyToMasterKey converts a standard lattigo-convention [rlwe.GaloisKey]
// to a paper-convention [MasterKey] by applying σ_r (the forward automorphism)
// to each GadgetCiphertext component.
//
// Use this to convert GaloisKeys produced by [rlwe.KeyGenerator.GenGaloisKeyNew]
// or [multiparty.GaloisKeyGenProtocol] into MasterKeys for hierarchical derivation.
//
// This modifies the input key in-place. The GaloisKey must not be used after this call.
func GaloisKeyToMasterKey(params rlwe.Parameters, gk *rlwe.GaloisKey) (*MasterKey, error) {
	if err := automorphGadgetCiphertext(params, gk, gk.GaloisElement); err != nil {
		return nil, err
	}
	return &MasterKey{gk: gk}, nil
}

// MasterKeyToGaloisKey converts a paper-convention [MasterKey] to a standard
// lattigo-convention [rlwe.GaloisKey] by applying σ^{-1}_r (the inverse automorphism)
// to each GadgetCiphertext component.
//
// This consumes the MasterKey — it must not be used after this call.
//
// This allocates temporary buffers per call. For repeated use in a hot loop,
// consider pre-allocating buffers (see kgplus.Evaluator for an example).
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

// GenerateUniquePrimes generates NTT-friendly primes of the given bit sizes
// that are not in the usedPrimes set. Used by both LLKN and KG+ to avoid
// prime collisions when building multi-level parameter chains.
func GenerateUniquePrimes(logP []int, nthRoot uint64, usedPrimes map[uint64]bool) ([]uint64, error) {
	primes := make([]uint64, 0, len(logP))

	// Group by bit size to share generators
	bySize := make(map[int]int)
	for _, bits := range logP {
		bySize[bits]++
	}

	generated := make(map[int][]uint64)
	for bits, count := range bySize {
		g := ring.NewNTTFriendlyPrimesGenerator(uint64(bits), nthRoot)
		ps := make([]uint64, 0, count)
		for len(ps) < count {
			p, err := g.NextAlternatingPrime()
			if err != nil {
				return nil, fmt.Errorf("exhausted %d-bit NTT-friendly primes (need %d, got %d)", bits, count, len(ps))
			}
			if !usedPrimes[p] {
				ps = append(ps, p)
			}
		}
		generated[bits] = ps
	}

	// Reconstruct in original order
	counters := make(map[int]int)
	for _, bits := range logP {
		idx := counters[bits]
		primes = append(primes, generated[bits][idx])
		counters[bits] = idx + 1
	}

	return primes, nil
}
