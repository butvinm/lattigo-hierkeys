package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Evaluator pre-allocates all buffers for server-side hierarchical key
// derivation via RotToRot (no ring switching needed).
type Evaluator struct {
	params Parameters
	*evaluatorBuffers
}

type evaluatorBuffers struct {
	// Shared RotToRot buffers
	rotBuf *hierkeys.RotToRotBuffers
}

// NewEvaluator creates an Evaluator with pre-allocated buffers.
func NewEvaluator(params Parameters) *Evaluator {
	return &Evaluator{
		params:           params,
		evaluatorBuffers: newEvaluatorBuffers(params),
	}
}

func newEvaluatorBuffers(params Parameters) *evaluatorBuffers {
	return &evaluatorBuffers{
		rotBuf: hierkeys.NewRotToRotBuffers(params.Eval, params.Master),
	}
}

// ConcurrentCopy creates a copy of this Evaluator that shares read-only
// data (parameters) but has its own mutable buffers.
func (eval *Evaluator) ConcurrentCopy() *Evaluator {
	return &Evaluator{
		params:           eval.params,
		evaluatorBuffers: newEvaluatorBuffers(eval.params),
	}
}

// RotToRot generates a combined rotation key from a level-0 key and a master
// key. See [hierkeys.RotToRot] for details.
func (eval *Evaluator) RotToRot(
	inputKey *rlwe.GaloisKey,
	masterKey *rlwe.GaloisKey,
	combinedGalEl uint64,
) (*rlwe.GaloisKey, error) {
	return hierkeys.RotToRot(eval.rotBuf, eval.params.Eval, eval.params.Master, inputKey, masterKey, combinedGalEl)
}
