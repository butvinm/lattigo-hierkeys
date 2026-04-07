package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/ring"
)

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
