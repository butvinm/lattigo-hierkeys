package kgplus

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
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
	// --- Buffers for RingSwitchGaloisKey ---

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

	// --- RotToRot buffers for each adjacent RPrime level pair ---
	rotBufs []*hierkeys.RotToRotBuffers

	// --- Buffers for convertToLattigoConvention ---
	autTmpQ ring.Poly // at eval Q level
	autTmpP ring.Poly // at eval P level
}

// NewEvaluator creates an Evaluator with pre-allocated buffers for the
// given hierarchical parameters.
func NewEvaluator(params Parameters) *Evaluator {
	return &Evaluator{
		params:           params,
		evaluatorBuffers: newEvaluatorBuffers(params),
	}
}

func newEvaluatorBuffers(params Parameters) *evaluatorBuffers {
	ringQRPrime := params.RPrime[0].RingQ()
	ringPRPrime := params.RPrime[0].RingP()
	ringQHK := params.HK.RingQ()
	ringQEval := params.Eval.RingQ()

	// RotToRot buffers for each adjacent RPrime level pair
	k := params.NumLevels()
	rotBufs := make([]*hierkeys.RotToRotBuffers, k-1)
	for i := 0; i < k-1; i++ {
		rotBufs[i] = hierkeys.NewRotToRotBuffers(params.RPrime[i], params.RPrime[i+1])
	}

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

		// Shared RotToRot buffers
		rotBufs: rotBufs,

		// automorphInPlace buffers
		autTmpQ: ringQEval.NewPoly(),
	}

	buf.ctKSRS.IsNTT = true

	if params.Eval.RingP() != nil {
		buf.autTmpP = params.Eval.RingP().NewPoly()
	}

	return buf
}

// ConcurrentCopy creates a copy of this Evaluator that shares read-only
// data (parameters) but has its own mutable buffers.
func (eval *Evaluator) ConcurrentCopy() *Evaluator {
	return &Evaluator{
		params:           eval.params,
		evaluatorBuffers: newEvaluatorBuffers(eval.params),
	}
}

// RotToRot generates a combined rotation key from a level-i key and a
// level-(i+1) key in the extension ring R'. See [hierkeys.RotToRot] for details.
func (eval *Evaluator) RotToRot(
	level int,
	inputKey *hierkeys.MasterKey,
	masterKey *hierkeys.MasterKey,
	combinedGalEl uint64,
) (*hierkeys.MasterKey, error) {
	return hierkeys.RotToRot(eval.rotBufs[level], eval.params.RPrime[level], eval.params.RPrime[level+1], inputKey, masterKey, combinedGalEl)
}
