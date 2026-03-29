package llkn

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Parameters bundles the multi-tier parameter sets needed for LLKN
// hierarchical rotation key generation (same ring, no ring switching).
//
// The hierarchy has k levels (k = len(Levels)):
//   - Levels[0] = Eval: Q = Q_eval, P = P_eval — for ciphertext evaluation
//   - Levels[1]: Q = Q_eval ∪ P_eval, P = P_1 — first master/intermediate level
//   - Levels[i]: Q = Levels[i-1].Q ∪ Levels[i-1].P, P = P_i
//   - Levels[k-1]: top master level
//
// For k=2, this is the standard LLKN two-tier scheme from Lee-Lee-Kim-No.
// For k>2, intermediate levels enable further TX bandwidth reduction
// at the cost of additional server-side computation.
//
// At each adjacent level pair, the RotToRot constraint must hold:
//
//	Levels[i+1].QCount() == Levels[i].QCount() + Levels[i].PCount()
//
// Unlike KG+, LLKN does not use an extension ring and supports both
// Standard and ConjugateInvariant ring types.
type Parameters struct {
	Levels []rlwe.Parameters
}

// Eval returns the evaluation-level parameters (Levels[0]).
func (p Parameters) Eval() rlwe.Parameters {
	return p.Levels[0]
}

// Top returns the top (master) level parameters (Levels[k-1]).
func (p Parameters) Top() rlwe.Parameters {
	return p.Levels[len(p.Levels)-1]
}

// NumLevels returns the number of hierarchy levels (k).
func (p Parameters) NumLevels() int {
	return len(p.Levels)
}

// ProjectToEvalKey projects a top-level secret key to evaluation level.
// The evaluation key has Q = Q_eval and P = P_eval.
//
// Returns an error if the secret key is not at the expected top level.
func (p Parameters) ProjectToEvalKey(skTop *rlwe.SecretKey) (*rlwe.SecretKey, error) {
	expectedQ := p.Top().QCount()
	if skTop.LevelQ()+1 != expectedQ {
		return nil, fmt.Errorf("sk has %d Q primes, want %d (top level)", skTop.LevelQ()+1, expectedQ)
	}
	// projectToLevel logic for level 0
	paramsLevel := p.Levels[0]
	skLevel := rlwe.NewSecretKey(paramsLevel)
	for m := 0; m <= paramsLevel.MaxLevel(); m++ {
		copy(skLevel.Value.Q.Coeffs[m], skTop.Value.Q.Coeffs[m])
	}
	for m := 0; m <= paramsLevel.MaxLevelP(); m++ {
		copy(skLevel.Value.P.Coeffs[m], skTop.Value.Q.Coeffs[paramsLevel.QCount()+m])
	}
	return skLevel, nil
}

// NewParameters constructs LLKN hierarchical key parameters from standard
// evaluation parameters and auxiliary prime bit-sizes for each level above eval.
//
// logPPerLevel[i] gives the P-prime bit-sizes for Levels[i+1].
// The number of hierarchy levels is k = len(logPPerLevel) + 1.
//
// P primes at each level are generated to be distinct from all Q primes at
// that level and from all primes used at lower levels. This prevents the
// prime collision that would cause GadgetProduct/ModDown to fail.
//
// For k=2 (standard two-tier): NewParameters(eval, [][]int{{61}})
// For k=3 (three-tier):        NewParameters(eval, [][]int{{61}, {61}})
func NewParameters(eval rlwe.Parameters, logPPerLevel [][]int) (Parameters, error) {

	if len(logPPerLevel) == 0 {
		return Parameters{}, fmt.Errorf("logPPerLevel must have at least one element (for k>=2)")
	}

	if eval.PCount() == 0 {
		return Parameters{}, fmt.Errorf("eval parameters must have P primes")
	}

	for i, logP := range logPPerLevel {
		if len(logP) == 0 {
			return Parameters{}, fmt.Errorf("logPPerLevel[%d] must have at least one element", i)
		}
	}

	// Collect all primes already in use (to avoid collisions when generating P)
	usedPrimes := make(map[uint64]bool)
	for _, q := range eval.Q() {
		usedPrimes[q] = true
	}
	for _, p := range eval.P() {
		usedPrimes[p] = true
	}

	nthRoot := uint64(eval.RingQ().NthRoot())

	k := len(logPPerLevel) + 1
	levels := make([]rlwe.Parameters, k)
	levels[0] = eval

	// Build each level: Q_{i+1} = Q_i ∪ P_i, P_{i+1} = fresh primes from logPPerLevel[i]
	for i := 0; i < len(logPPerLevel); i++ {
		prev := levels[i]

		// Q_{i+1} = Q_i ∪ P_i
		qNext := make([]uint64, 0, prev.QCount()+prev.PCount())
		qNext = append(qNext, prev.Q()...)
		qNext = append(qNext, prev.P()...)

		// Generate fresh P primes that don't collide with any existing primes
		pNext, err := hierkeys.GenerateUniquePrimes(logPPerLevel[i], nthRoot, usedPrimes)
		if err != nil {
			return Parameters{}, fmt.Errorf("cannot generate P primes for level %d: %w", i+1, err)
		}

		// Mark new P primes as used
		for _, p := range pNext {
			usedPrimes[p] = true
		}

		next, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:     eval.LogN(),
			Q:        qNext,
			P:        pNext,
			NTTFlag:  true,
			RingType: eval.RingType(),
		})
		if err != nil {
			return Parameters{}, fmt.Errorf("cannot create level %d parameters: %w", i+1, err)
		}

		levels[i+1] = next
	}

	return Parameters{Levels: levels}, nil
}
