package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Parameters bundles the four-tier parameter sets needed for hierarchical
// rotation key generation via ring switching.
//
// Three tiers of primes:
//   - Q_eval, P_eval: standard evaluation parameters (computation + key-switching)
//   - P_hk: auxiliary primes consumed by the homing key during ring switching
//
// Four parameter sets derived from these:
//   - Eval:         Q = Q_eval, P = P_eval, degree N — for ciphertext evaluation
//   - HK:           Q = Q_eval ∪ P_eval, P = P_hk, degree N — for homing key operations
//   - RPrime:       Q = Q_eval, P = P_eval, degree 2N — level-0 keys in extension ring R'
//   - RPrimeMaster: Q = Q_eval ∪ P_eval, P = P_hk, degree 2N — master keys in extension ring R'
type Parameters struct {
	Eval         rlwe.Parameters
	HK           rlwe.Parameters
	RPrime       rlwe.Parameters
	RPrimeMaster rlwe.Parameters
}

// NewParameters constructs hierarchical key parameters from standard evaluation
// parameters and auxiliary prime bit-sizes for the homing key.
//
// The auxiliary primes (logPHK) are additional special primes consumed during
// ring switching. They must be NTT-friendly for degree 2N. Typically one 61-bit
// prime suffices.
//
// Example:
//
//	paramsEval, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
//	    LogN: 16, LogQ: []int{55, 45, 45, 45}, LogP: []int{61}, NTTFlag: true,
//	})
//	hkParams, _ := hierkeys.NewParameters(paramsEval, []int{61})
func NewParameters(eval rlwe.Parameters, logPHK []int) (Parameters, error) {

	if len(logPHK) == 0 {
		return Parameters{}, fmt.Errorf("logPHK must have at least one element")
	}

	if eval.PCount() == 0 {
		return Parameters{}, fmt.Errorf("eval parameters must have P primes")
	}

	// Q_hk = Q_eval ∪ P_eval (concatenate Q and P primes from eval)
	qHK := make([]uint64, 0, eval.QCount()+eval.PCount())
	qHK = append(qHK, eval.Q()...)
	qHK = append(qHK, eval.P()...)

	// Homing key: Q = Q_eval ∪ P_eval, P = P_hk, degree N
	paramsHK, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN(),
		Q:       qHK,
		LogP:    logPHK,
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create HK parameters: %w", err)
	}

	// Extension ring R': Q = Q_eval, P = P_eval, degree 2N.
	// IMPORTANT: All Q and P primes must be NTT-friendly for degree 2N
	// (i.e., q ≡ 1 mod 4N). If paramsEval was created with LogQ/LogP,
	// the generated primes may only satisfy q ≡ 1 mod 2N. In that case,
	// use explicit primes that satisfy the 2N constraint.
	paramsRPrime, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN() + 1,
		Q:       eval.Q(),
		P:       eval.P(),
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create R' parameters (primes may not be NTT-friendly for degree 2N): %w", err)
	}

	// Master level in R': Q = Q_eval ∪ P_eval, P = P_hk, degree 2N
	paramsRPrimeMaster, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:    eval.LogN() + 1,
		Q:       qHK,
		LogP:    logPHK,
		NTTFlag: true,
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create R' master parameters: %w", err)
	}

	return Parameters{
		Eval:         eval,
		HK:           paramsHK,
		RPrime:       paramsRPrime,
		RPrimeMaster: paramsRPrimeMaster,
	}, nil
}
