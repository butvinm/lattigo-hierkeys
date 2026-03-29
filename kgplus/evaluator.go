package kgplus

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// Evaluator performs server-side hierarchical key derivation for KG+.
// Thread-safe: can be used concurrently from multiple goroutines.
type Evaluator struct {
	params Parameters

	// RotToRot per adjacent RPrime level pair (thread-safe)
	rotEvals []*hierkeys.RotToRotEvaluator

	// Ring-switch resources (all thread-safe)
	evalHK  *rlwe.Evaluator  // HK-level evaluator for GadgetProduct
	poolRPQ *ring.BufferPool // R' Q-domain (degree 2N)
	poolRPP *ring.BufferPool // R' P-domain (degree 2N)
	poolHK  *ring.BufferPool // HK level (degree N)

	// Convention convert resources
	poolEvQ *ring.BufferPool // eval Q (degree N)
	poolEvP *ring.BufferPool // eval P (degree N), may be nil
}

// NewEvaluator creates an Evaluator with thread-safe pool-based buffers.
func NewEvaluator(params Parameters) *Evaluator {
	k := params.NumLevels()
	rotEvals := make([]*hierkeys.RotToRotEvaluator, k-1)
	for i := 0; i < k-1; i++ {
		rotEvals[i] = hierkeys.NewRotToRotEvaluator(params.RPrime[i], params.RPrime[i+1])
	}

	eval := &Evaluator{
		params:   params,
		rotEvals: rotEvals,
		evalHK:   rlwe.NewEvaluator(params.HK, nil),
		poolRPQ:  ring.NewPool(params.RPrime[0].RingQ(), structs.NewSyncPoolUint64(params.RPrime[0].N())),
		poolRPP:  ring.NewPool(params.RPrime[0].RingP(), structs.NewSyncPoolUint64(params.RPrime[0].N())),
		poolHK:   ring.NewPool(params.HK.RingQ(), structs.NewSyncPoolUint64(params.HK.N())),
		poolEvQ:  ring.NewPool(params.Eval.RingQ(), structs.NewSyncPoolUint64(params.Eval.N())),
	}

	if params.Eval.RingP() != nil {
		eval.poolEvP = ring.NewPool(params.Eval.RingP(), structs.NewSyncPoolUint64(params.Eval.N()))
	}

	return eval
}

// RotToRot at a specific R' level. Thread-safe.
func (eval *Evaluator) RotToRot(level int, inputKey, masterKey *hierkeys.MasterKey, targetGalEl uint64) (*hierkeys.MasterKey, error) {
	return eval.rotEvals[level].RotToRot(inputKey, masterKey, targetGalEl)
}

// NewLevelExpansion creates a thread-safe expansion session at the given R' level.
func (eval *Evaluator) NewLevelExpansion(level int, shift0Key *hierkeys.MasterKey, masterKeys map[int]*hierkeys.MasterKey) *hierkeys.LevelExpansion {
	return hierkeys.NewLevelExpansion(
		eval.rotEvals[level].RotToRot,
		eval.params.RPrime[level],
		eval.params.Eval.N()/2,
		shift0Key,
		masterKeys,
	)
}

// ExpandLevel derives keys at the given R' hierarchy level sequentially.
// For concurrent derivation, use [Evaluator.NewLevelExpansion].
func (eval *Evaluator) ExpandLevel(
	level int,
	shift0Key *hierkeys.MasterKey,
	masterKeys map[int]*hierkeys.MasterKey,
	targetRotations []int,
) (*hierkeys.IntermediateKeys, error) {
	return hierkeys.ExpandLevel(
		eval.rotEvals[level].RotToRot,
		eval.params.RPrime[level],
		eval.params.Eval.N()/2,
		shift0Key,
		masterKeys,
		targetRotations,
	)
}
