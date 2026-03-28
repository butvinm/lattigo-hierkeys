package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
)

// Evaluator pre-allocates all buffers for server-side hierarchical key
// derivation via RotToRot (no ring switching needed).
type Evaluator struct {
	params Parameters
	*evaluatorBuffers
}

type evaluatorBuffers struct {
	// rotBufs[i] is for RotToRot between Levels[i] and Levels[i+1]
	rotBufs []*hierkeys.RotToRotBuffers
}

// NewEvaluator creates an Evaluator with pre-allocated buffers.
func NewEvaluator(params Parameters) *Evaluator {
	return &Evaluator{
		params:           params,
		evaluatorBuffers: newEvaluatorBuffers(params),
	}
}

func newEvaluatorBuffers(params Parameters) *evaluatorBuffers {
	k := params.NumLevels()
	rotBufs := make([]*hierkeys.RotToRotBuffers, k-1)
	for i := 0; i < k-1; i++ {
		rotBufs[i] = hierkeys.NewRotToRotBuffers(params.Levels[i], params.Levels[i+1])
	}
	return &evaluatorBuffers{rotBufs: rotBufs}
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
// level-(i+1) key. See [hierkeys.RotToRot] for details.
func (eval *Evaluator) RotToRot(
	level int,
	inputKey *hierkeys.MasterKey,
	masterKey *hierkeys.MasterKey,
	combinedGalEl uint64,
) (*hierkeys.MasterKey, error) {
	return hierkeys.RotToRot(
		eval.rotBufs[level],
		eval.params.Levels[level],
		eval.params.Levels[level+1],
		inputKey,
		masterKey,
		combinedGalEl,
	)
}
