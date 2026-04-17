// Package hierkeys provides shared primitives for hierarchical rotation key derivation with lattigo v6.
//
// Two schemes live in sub-packages and share the same client/server pipeline shape.
// Both produce standard *rlwe.GaloisKey objects compatible with rlwe.Evaluator,
// ckks.Evaluator.Rotate, and hoisted rotations.
//
//	llkn   — same ring, supports Standard and ConjugateInvariant ring types.
//	kgplus — ring switching into R' (degree 2N), Standard ring only.
//
// Typical server-side pipeline, using primitives from this package:
//
//	shift0, _  := hierkeys.PubToRot(paramsLevel0, paramsTop, tk.PublicKey)
//	exp        := eval.NewLevelExpansion(level, shift0, tk.MasterRotKeys, targets)
//	for _, r := range targets {
//	    mk, _  := exp.Derive(r)        // thread-safe, dedup'd via sync.Once
//	    gk, _  := eval.FinalizeKey(mk) // convention convert (+ ring switch for KG+)
//	}
//
// See [llkn] and [kgplus] for scheme-specific evaluators and parameters,
// and example/{llkn,kgplus}/{simple,concurrent,multiparty} for runnable end-to-end flows.
package hierkeys
