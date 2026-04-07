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

	// RotToRot per adjacent Levels level pair (thread-safe)
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
		rotEvals[i] = hierkeys.NewRotToRotEvaluator(params.levels[i], params.levels[i+1])
	}

	eval := &Evaluator{
		params:   params,
		rotEvals: rotEvals,
		evalHK:   rlwe.NewEvaluator(params.hk, nil),
		poolRPQ:  ring.NewPool(params.levels[0].RingQ(), structs.NewSyncPoolUint64(params.levels[0].N())),
		poolRPP:  ring.NewPool(params.levels[0].RingP(), structs.NewSyncPoolUint64(params.levels[0].N())),
		poolHK:   ring.NewPool(params.hk.RingQ(), structs.NewSyncPoolUint64(params.hk.N())),
		poolEvQ:  ring.NewPool(params.eval.RingQ(), structs.NewSyncPoolUint64(params.eval.N())),
	}

	if params.eval.RingP() != nil {
		eval.poolEvP = ring.NewPool(params.eval.RingP(), structs.NewSyncPoolUint64(params.eval.N()))
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
		eval.params.levels[level],
		eval.params.eval.N()/2,
		shift0Key,
		masterKeys,
	)
}
