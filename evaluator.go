package hierkeys

import (
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// Evaluator pre-allocates all buffers for server-side hierarchical key
// derivation (RingSwitchGaloisKey, RotToRot, DeriveGaloisKeys).
//
// Following lattigo's evaluator pattern, the struct separates read-only
// state (params, rlwe evaluators) from mutable buffers so that
// ConcurrentCopy can produce a concurrency-safe copy that shares the
// read-only parts.
type Evaluator struct {
	params Parameters
	*evaluatorBuffers
}

type evaluatorBuffers struct {
	// --- Buffers for RingSwitchGaloisKey (eval.go) ---

	// R' Q-domain working space (degree 2N)
	bQRPrime, aQRPrime ring.Poly // copy of component Q part
	bQCoeff, aQCoeff   ring.Poly // after IMForm+INTT

	// R' P-domain working space (degree 2N)
	bPRPrime, aPRPrime ring.Poly // copy of component P part
	bPCoeff, aPCoeff   ring.Poly // after IMForm+INTT

	// Extracted even/odd at Q_hk level (degree N)
	b0RS, a0RS, a1RS ring.Poly
	Xa1RS            ring.Poly // X * a1

	// Key-switch output and result at Q_hk level
	rsBRS, rsARS ring.Poly
	ctKSRS       *rlwe.Ciphertext
	evalHK       *rlwe.Evaluator // evaluator at HK level for GadgetProduct

	// --- Buffers for RotToRot (rottorot.go) ---

	// Combined Q+P at Q_hk level (degree 2N, RPrimeMaster ring)
	bCombined, aCombined ring.Poly
	// Automorphed at Q_hk level
	bAut, aAut ring.Poly
	// Key-switch output
	ctKSRot *rlwe.Ciphertext
	evalRot *rlwe.Evaluator // evaluator at RPrimeMaster level

	// --- Buffers for convertToLattigoConvention / automorphInPlace ---

	// Temporary poly for in-place automorphism (Q and P levels)
	autTmpQ ring.Poly // at eval Q level
	autTmpP ring.Poly // at eval P level
}

// NewEvaluator creates an Evaluator with pre-allocated buffers for the
// given hierarchical parameters. All subsequent calls to RingSwitchGaloisKey,
// RotToRot, and DeriveGaloisKeys reuse these buffers.
func NewEvaluator(params Parameters) *Evaluator {
	return &Evaluator{
		params:           params,
		evaluatorBuffers: newEvaluatorBuffers(params),
	}
}

func newEvaluatorBuffers(params Parameters) *evaluatorBuffers {
	ringQRPrime := params.RPrime.RingQ()
	ringPRPrime := params.RPrime.RingP()
	ringQHK := params.HK.RingQ()
	ringQRPMaster := params.RPrimeMaster.RingQ()
	ringQEval := params.Eval.RingQ()

	buf := &evaluatorBuffers{
		// RingSwitchGaloisKey buffers
		bQRPrime: ringQRPrime.NewPoly(),
		aQRPrime: ringQRPrime.NewPoly(),
		bQCoeff:  ringQRPrime.NewPoly(),
		aQCoeff:  ringQRPrime.NewPoly(),
		bPRPrime: ringPRPrime.NewPoly(),
		aPRPrime: ringPRPrime.NewPoly(),
		bPCoeff:  ringPRPrime.NewPoly(),
		aPCoeff:  ringPRPrime.NewPoly(),
		b0RS:     ringQHK.NewPoly(),
		a0RS:     ringQHK.NewPoly(),
		a1RS:     ringQHK.NewPoly(),
		Xa1RS:    ringQHK.NewPoly(),
		rsBRS:    ringQHK.NewPoly(),
		rsARS:    ringQHK.NewPoly(),
		ctKSRS:   rlwe.NewCiphertext(params.HK, 1, params.HK.MaxLevel()),
		evalHK:   rlwe.NewEvaluator(params.HK, nil),

		// RotToRot buffers
		bCombined: ringQRPMaster.NewPoly(),
		aCombined: ringQRPMaster.NewPoly(),
		bAut:      ringQRPMaster.NewPoly(),
		aAut:      ringQRPMaster.NewPoly(),
		ctKSRot:   rlwe.NewCiphertext(params.RPrimeMaster, 1, params.RPrimeMaster.MaxLevel()),
		evalRot:   rlwe.NewEvaluator(params.RPrimeMaster, nil),

		// automorphInPlace buffers
		autTmpQ: ringQEval.NewPoly(),
	}

	buf.ctKSRS.IsNTT = true
	buf.ctKSRot.IsNTT = true

	if params.Eval.RingP() != nil {
		buf.autTmpP = params.Eval.RingP().NewPoly()
	}

	return buf
}

// ConcurrentCopy creates a copy of this Evaluator that shares read-only
// data (parameters) but has its own mutable buffers. The original and
// the copy can be used concurrently.
func (eval *Evaluator) ConcurrentCopy() *Evaluator {
	return &Evaluator{
		params:           eval.params,
		evaluatorBuffers: newEvaluatorBuffers(eval.params),
	}
}
