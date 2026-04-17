package llkn

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// testConjugateInvariantParams is the sole insecure fixture retained in
// test_params.go: a LogN=10 ConjugateInvariant ring configuration. Production
// scenarios in testutil.Scenarios cover only the Standard ring; this fixture
// is the only test coverage for the ConjugateInvariant code path.
var (
	testQi60 = []uint64{
		0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001,
		0x1fffffffff380001,
	}
	testPi60 = []uint64{
		0x1ffffffff6c80001,
	}

	testConjugateInvariantParams = struct {
		rlwe.ParametersLiteral
		LogPLevels [][]int
	}{
		ParametersLiteral: rlwe.ParametersLiteral{
			LogN:     10,
			Q:        testQi60,
			P:        testPi60,
			NTTFlag:  true,
			RingType: ring.ConjugateInvariant,
		},
		LogPLevels: [][]int{{61}},
	}
)
