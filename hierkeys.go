// Package hierkeys provides shared primitives for hierarchical rotation key
// derivation with lattigo v6. See [llkn] and [kgplus] sub-packages for
// scheme-specific implementations.
package hierkeys

import (
	"fmt"

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
