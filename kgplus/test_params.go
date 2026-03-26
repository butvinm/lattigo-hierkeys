package kgplus

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

// TestParametersLiteral wraps an rlwe.ParametersLiteral with the auxiliary
// prime sizes needed for hierarchical key generation.
type TestParametersLiteral struct {
	rlwe.ParametersLiteral
	LogPHK    []int   // bit-sizes of auxiliary P primes for the homing key (and RPrime[1])
	LogPExtra [][]int // bit-sizes of P primes for additional RPrime levels (k>2)
}

var (
	// NTT-friendly 61-bit primes for N up to 2^17 (q ≡ 1 mod 2^18).
	testQi60 = []uint64{
		0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001,
		0x1fffffffff380001, 0x1fffffffff000001, 0x1ffffffffef00001, 0x1ffffffffee80001,
	}

	// Additional 61-bit NTT-friendly primes for P chains.
	testPi60 = []uint64{
		0x1ffffffff6c80001, // P_eval
		0x1ffffffff6140001, // P_hk
	}

	// testInsecure are insecure parameters used for the sole purpose of fast testing.
	testInsecure = []TestParametersLiteral{
		// k=2, 5 Q primes, 1 P prime, 1 homing-key prime
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    10,
				Q:       testQi60[:5],
				P:       testPi60[:1],
				NTTFlag: true,
			},
			LogPHK: []int{61},
		},
		// k=2, 3 Q primes, 1 P prime, 1 homing-key prime (fewer levels)
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    10,
				Q:       testQi60[:3],
				P:       testPi60[:1],
				NTTFlag: true,
			},
			LogPHK: []int{61},
		},
		// k=3, 5 Q primes, 1 P prime, 1 homing-key prime + extra level
		// Needs enough P primes at RPrime[1] to keep noise manageable.
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    10,
				Q:       testQi60[:5],
				P:       testPi60[:1],
				NTTFlag: true,
			},
			LogPHK:    []int{61, 61, 61, 61, 61, 61},
			LogPExtra: [][]int{{61, 61, 61, 61, 61, 61}},
		},
	}
)
