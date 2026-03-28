package kgplus

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// Parameters bundles the parameter sets needed for KG+
// hierarchical rotation key generation via ring switching.
//
// Three tiers of primes:
//   - Q_eval, P_eval: standard evaluation parameters (computation + key-switching)
//   - P_hk: auxiliary primes consumed by the homing key during ring switching
//
// The hierarchy has k levels in the extension ring R' (degree 2N):
//   - RPrime[0]: Q = Q_eval, P = P_eval — level-0 keys
//   - RPrime[1]: Q = Q_eval ∪ P_eval, P = P_hk — first master level (same P as HK)
//   - RPrime[i]: Q = RPrime[i-1].Q ∪ RPrime[i-1].P, P = P_i — higher levels
//
// For k=2, this is the standard KG+ scheme.
// For k>2, extra levels provide additional hierarchy depth.
//
// KG+ only supports the Standard ring type (not ConjugateInvariant),
// because the X → Y² extension ring embedding requires Standard cyclotomic structure.
type Parameters struct {
	Eval   rlwe.Parameters
	HK     rlwe.Parameters
	RPrime []rlwe.Parameters // RPrime[0]=level0, RPrime[k-1]=top master
}

// NumLevels returns the number of hierarchy levels (k = len(RPrime)).
func (p Parameters) NumLevels() int {
	return len(p.RPrime)
}

// ProjectToEvalKey projects a homing-key-level secret key to evaluation level.
// The evaluation key has Q = Q_eval and P = P_eval.
//
// Returns an error if the secret key is not at the expected HK level.
func (p Parameters) ProjectToEvalKey(skHK *rlwe.SecretKey) (*rlwe.SecretKey, error) {
	expectedQ := p.HK.QCount()
	if skHK.LevelQ()+1 != expectedQ {
		return nil, fmt.Errorf("sk has %d Q primes, want %d (HK level)", skHK.LevelQ()+1, expectedQ)
	}
	skEval := rlwe.NewSecretKey(p.Eval)
	for m := 0; m <= p.Eval.MaxLevel(); m++ {
		copy(skEval.Value.Q.Coeffs[m], skHK.Value.Q.Coeffs[m])
	}
	for m := 0; m <= p.Eval.MaxLevelP(); m++ {
		copy(skEval.Value.P.Coeffs[m], skHK.Value.Q.Coeffs[p.Eval.QCount()+m])
	}
	return skEval, nil
}

// NewParameters constructs KG+ hierarchical key parameters from standard evaluation
// parameters and auxiliary prime bit-sizes.
//
// logPHK specifies auxiliary primes for the homing key and RPrime[1].
// logPExtra (optional) specifies P-prime bit-sizes for additional levels (k>2).
//
// For k=2 (standard): NewParameters(eval, logPHK)
// For k=3: NewParameters(eval, logPHK, logP2)
//
// All primes must be NTT-friendly for degree 2N. Returns an error if the evaluation
// parameters use the ConjugateInvariant ring type.
func NewParameters(eval rlwe.Parameters, logPHK []int, logPExtra ...[]int) (Parameters, error) {

	if eval.RingType() == ring.ConjugateInvariant {
		return Parameters{}, fmt.Errorf("KG+ does not support ConjugateInvariant ring type; use the llkn package instead")
	}

	if len(logPHK) == 0 {
		return Parameters{}, fmt.Errorf("logPHK must have at least one element")
	}

	if eval.PCount() == 0 {
		return Parameters{}, fmt.Errorf("eval parameters must have P primes")
	}

	// Q_hk = Q_eval ∪ P_eval
	qHK := make([]uint64, 0, eval.QCount()+eval.PCount())
	qHK = append(qHK, eval.Q()...)
	qHK = append(qHK, eval.P()...)

	// Collect all primes for collision avoidance
	usedPrimes := make(map[uint64]bool)
	for _, q := range eval.Q() {
		usedPrimes[q] = true
	}
	for _, p := range eval.P() {
		usedPrimes[p] = true
	}

	nthRoot := uint64(eval.RingQ().NthRoot())
	nthRoot2N := nthRoot * 2 // NTT-friendly for degree 2N

	// Generate HK P primes (avoiding existing primes).
	// Must be NTT-friendly for degree 2N because they are also used as P in RPrime[1].
	pHK, err := hierkeys.GenerateUniquePrimes(logPHK, nthRoot2N, usedPrimes)
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot generate HK P primes: %w", err)
	}
	for _, p := range pHK {
		usedPrimes[p] = true
	}

	// Homing key: Q = Q_eval ∪ P_eval, P = P_hk, degree N
	paramsHK, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN(),
		Q:       qHK,
		P:       pHK,
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create HK parameters: %w", err)
	}

	// Build RPrime levels (degree 2N)
	k := 2 + len(logPExtra) // k=2 minimum, +1 per extra level

	rpLevels := make([]rlwe.Parameters, k)

	// RPrime[0]: Q = Q_eval, P = P_eval, degree 2N
	paramsRPrime0, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN() + 1,
		Q:       eval.Q(),
		P:       eval.P(),
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create R' level-0 parameters (primes may not be NTT-friendly for degree 2N): %w", err)
	}
	rpLevels[0] = paramsRPrime0

	// RPrime[1]: Q = Q_eval ∪ P_eval, P = P_hk, degree 2N
	paramsRPrime1, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN() + 1,
		Q:       qHK,
		P:       pHK,
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create R' level-1 parameters: %w", err)
	}
	rpLevels[1] = paramsRPrime1

	// Build additional RPrime levels (k>2)
	for i := 0; i < len(logPExtra); i++ {
		if len(logPExtra[i]) == 0 {
			return Parameters{}, fmt.Errorf("logPExtra[%d] must have at least one element", i)
		}

		prev := rpLevels[i+1]

		// Q_{next} = prev.Q ∪ prev.P
		qNext := make([]uint64, 0, prev.QCount()+prev.PCount())
		qNext = append(qNext, prev.Q()...)
		qNext = append(qNext, prev.P()...)

		// Generate fresh P primes avoiding all used primes, NTT-friendly for degree 2N
		pNext, err := hierkeys.GenerateUniquePrimes(logPExtra[i], nthRoot2N, usedPrimes)
		if err != nil {
			return Parameters{}, fmt.Errorf("cannot generate P primes for R' level %d: %w", i+2, err)
		}
		for _, p := range pNext {
			usedPrimes[p] = true
		}

		next, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:    eval.LogN() + 1,
			Q:       qNext,
			P:       pNext,
			NTTFlag: true,
		})
		if err != nil {
			return Parameters{}, fmt.Errorf("cannot create R' level-%d parameters: %w", i+2, err)
		}

		rpLevels[i+2] = next
	}

	return Parameters{
		Eval:   eval,
		HK:     paramsHK,
		RPrime: rpLevels,
	}, nil
}
