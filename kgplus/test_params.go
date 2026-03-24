package kgplus

import "github.com/tuneinsight/lattigo/v6/core/rlwe"

// TestParametersLiteral wraps an rlwe.ParametersLiteral with the auxiliary
// prime sizes needed for hierarchical key generation.
type TestParametersLiteral struct {
	rlwe.ParametersLiteral
	LogPHK []int // bit-sizes of auxiliary P primes for the homing key
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
		// 5 Q primes, 1 P prime, 1 homing-key prime
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    10,
				Q:       testQi60[:5],
				P:       testPi60[:1],
				NTTFlag: true,
			},
			LogPHK: []int{61},
		},
		// 3 Q primes, 1 P prime, 1 homing-key prime (fewer levels)
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:    10,
				Q:       testQi60[:3],
				P:       testPi60[:1],
				NTTFlag: true,
			},
			LogPHK: []int{61},
		},
	}
)
