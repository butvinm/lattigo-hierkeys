package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
)

// Evaluator pre-allocates buffers for server-side hierarchical key derivation.
// Thread-safe: can be used concurrently from multiple goroutines.
type Evaluator struct {
	params   Parameters
	rotEvals []*hierkeys.RotToRotEvaluator // one per adjacent level pair
}

// NewEvaluator creates an Evaluator with thread-safe pool-based buffers.
func NewEvaluator(params Parameters) *Evaluator {
	k := params.NumLevels()
	rotEvals := make([]*hierkeys.RotToRotEvaluator, k-1)
	for i := 0; i < k-1; i++ {
		rotEvals[i] = hierkeys.NewRotToRotEvaluator(params.Levels[i], params.Levels[i+1])
	}
	return &Evaluator{params: params, rotEvals: rotEvals}
}

// RotToRot at a specific level. Thread-safe.
func (eval *Evaluator) RotToRot(level int, inputKey, masterKey *hierkeys.MasterKey, targetGalEl uint64) (*hierkeys.MasterKey, error) {
	return eval.rotEvals[level].RotToRot(inputKey, masterKey, targetGalEl)
}

// NewLevelExpansion creates a thread-safe expansion session at the given level.
func (eval *Evaluator) NewLevelExpansion(level int, shift0Key *hierkeys.MasterKey, masterKeys map[int]*hierkeys.MasterKey) *hierkeys.LevelExpansion {
	return hierkeys.NewLevelExpansion(
		eval.rotEvals[level].RotToRot,
		eval.params.Levels[level],
		eval.params.Eval().N()/2,
		shift0Key,
		masterKeys,
	)
}

// ExpandLevel derives keys at the given hierarchy level sequentially.
// For concurrent derivation, use [Evaluator.NewLevelExpansion] and call
// Derive from goroutines.
func (eval *Evaluator) ExpandLevel(
	level int,
	shift0Key *hierkeys.MasterKey,
	masterKeys map[int]*hierkeys.MasterKey,
	targetRotations []int,
) (*hierkeys.IntermediateKeys, error) {
	return hierkeys.ExpandLevel(
		eval.rotEvals[level].RotToRot,
		eval.params.Levels[level],
		eval.params.Eval().N()/2,
		shift0Key,
		masterKeys,
		targetRotations,
	)
}
