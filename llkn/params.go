package llkn

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Parameters bundles the two-tier parameter sets needed for LLKN
// hierarchical rotation key generation (same ring, no ring switching).
//
// Two tiers of primes:
//   - Eval:   Q = Q_eval, P = P_eval, degree N — for ciphertext evaluation
//   - Master: Q = Q_eval ∪ P_eval, P = P_master, degree N — for master rotation keys
//
// The master level has a larger Q because the eval P primes become
// part of master Q. This is exactly the k=2 hierarchy from Lee-Lee-Kim-No.
//
// Unlike KG+, LLKN does not use an extension ring and supports both
// Standard and ConjugateInvariant ring types.
type Parameters struct {
	Eval   rlwe.Parameters
	Master rlwe.Parameters
}

// NewParameters constructs LLKN hierarchical key parameters from standard
// evaluation parameters and auxiliary prime bit-sizes for the master level.
//
// The auxiliary primes (logPMaster) are consumed by RotToRot when generating
// lower-level keys. Typically one 61-bit prime suffices.
func NewParameters(eval rlwe.Parameters, logPMaster []int) (Parameters, error) {

	if len(logPMaster) == 0 {
		return Parameters{}, fmt.Errorf("logPMaster must have at least one element")
	}

	if eval.PCount() == 0 {
		return Parameters{}, fmt.Errorf("eval parameters must have P primes")
	}

	// Q_master = Q_eval ∪ P_eval
	qMaster := make([]uint64, 0, eval.QCount()+eval.PCount())
	qMaster = append(qMaster, eval.Q()...)
	qMaster = append(qMaster, eval.P()...)

	paramsMaster, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:     eval.LogN(),
		Q:        qMaster,
		LogP:     logPMaster,
		NTTFlag:  true,
		RingType: eval.RingType(),
	})
	if err != nil {
		return Parameters{}, fmt.Errorf("cannot create master parameters: %w", err)
	}

	return Parameters{
		Eval:   eval,
		Master: paramsMaster,
	}, nil
}
