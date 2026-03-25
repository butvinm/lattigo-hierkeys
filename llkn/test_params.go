package llkn

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// TestParametersLiteral wraps an rlwe.ParametersLiteral with the auxiliary
// prime sizes needed for LLKN hierarchical key generation.
type TestParametersLiteral struct {
	rlwe.ParametersLiteral
	LogPMaster []int // bit-sizes of auxiliary P primes for the master level
}

var (
	// NTT-friendly 61-bit primes for N up to 2^17 (q ≡ 1 mod 2^18).
	testQi60 = []uint64{
		0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001,
		0x1fffffffff380001, 0x1fffffffff000001, 0x1ffffffffef00001, 0x1ffffffffee80001,
	}

	testPi60 = []uint64{
		0x1ffffffff6c80001, // P_eval
		0x1ffffffff6140001, // P_master
	}

	testInsecure = []TestParametersLiteral{
		// Standard ring
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:     10,
				Q:        testQi60[:5],
				P:        testPi60[:1],
				NTTFlag:  true,
				RingType: ring.Standard,
			},
			LogPMaster: []int{61},
		},
		// Standard ring, fewer levels
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:     10,
				Q:        testQi60[:3],
				P:        testPi60[:1],
				NTTFlag:  true,
				RingType: ring.Standard,
			},
			LogPMaster: []int{61},
		},
		// ConjugateInvariant ring
		{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN:     10,
				Q:        testQi60[:5],
				P:        testPi60[:1],
				NTTFlag:  true,
				RingType: ring.ConjugateInvariant,
			},
			LogPMaster: []int{61},
		},
	}
)
