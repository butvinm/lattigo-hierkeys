package llkn

import (
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// IntermediateKeys holds GaloisKeys produced by RotToRot expansion.
// These are in the paper's convention (not yet post-converted).
// They can be stored by the server for the "inactive" use case and later
// finalized to evaluation keys on demand via [Evaluator.FinalizeKeys].
type IntermediateKeys struct {
	Keys map[int]*rlwe.GaloisKey // indexed by rotation index
}

// DeriveGaloisKeys is a convenience wrapper that creates a temporary
// Evaluator internally. For repeated calls, use [Evaluator.DeriveGaloisKeys].
func DeriveGaloisKeys(params Parameters, tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {
	eval := NewEvaluator(params)
	return eval.DeriveGaloisKeys(tk, targetRotations)
}

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys. The returned keys are in lattigo convention and work
// directly with rlwe.Evaluator.Automorphism, ckks.Evaluator.Rotate, and
// hoisted rotations.
//
// This is a convenience wrapper that calls [Evaluator.Expand] followed
// by [Evaluator.FinalizeKeys]. For finer control (e.g., storing
// intermediate keys for later finalization), call those methods directly.
//
// The returned MemEvaluationKeySet can be passed directly to
// rlwe.NewEvaluator or ckks.NewEvaluator.
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	intermediate, err := eval.Expand(tk, targetRotations)
	if err != nil {
		return nil, err
	}

	return eval.FinalizeKeys(intermediate)
}

// Expand expands master keys via RotToRot to produce eval-level keys
// for all target rotations. This is the expensive phase.
//
// Intermediate RotToRot results are cached: if multiple targets share a
// prefix in their decomposition, the shared intermediate is computed once.
//
// The results are in paper convention and can be stored for later
// finalization via [Evaluator.FinalizeKeys].
func (eval *Evaluator) Expand(tk *TransmissionKeys, targetRotations []int) (*IntermediateKeys, error) {

	if tk == nil || tk.Shift0Key == nil {
		return nil, fmt.Errorf("transmission keys and shift-0 key must not be nil")
	}

	// Extract available master rotation indices (sorted ascending for greedy decomposition)
	masterRots := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRots = append(masterRots, rot)
	}
	sort.Ints(masterRots)

	// Cache: rotation index -> eval-level key (paper convention)
	cache := make(map[int]*rlwe.GaloisKey)
	cache[0] = tk.Shift0Key // seed

	// Normalize negative rotations: CKKS rotation by -k = rotation by nSlots-k.
	nSlots := eval.params.Eval.N() / 2

	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}

		if _, ok := cache[normalized]; ok {
			continue
		}

		steps := hierkeys.DecomposeRotation(normalized, masterRots)
		if steps == nil {
			return nil, fmt.Errorf("cannot decompose rotation %d (normalized from %d) from available masters",
				normalized, target)
		}

		currentRot := 0
		for _, step := range steps {
			nextRot := currentRot + step

			if _, ok := cache[nextRot]; !ok {
				combinedGalEl := eval.params.Eval.GaloisElement(nextRot)
				key, err := eval.RotToRot(cache[currentRot], tk.MasterRotKeys[step], combinedGalEl)
				if err != nil {
					return nil, fmt.Errorf("RotToRot step (current=%d + master=%d -> %d): %w",
						currentRot, step, nextRot, err)
				}
				cache[nextRot] = key
			}

			currentRot = nextRot
		}
	}

	// Extract requested targets
	result := &IntermediateKeys{Keys: make(map[int]*rlwe.GaloisKey, len(targetRotations))}
	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}
		result.Keys[target] = cache[normalized]
	}
	return result, nil
}

// FinalizeKeys converts intermediate keys from paper convention to lattigo
// convention. This is the cheap phase.
//
// The result is a standard MemEvaluationKeySet usable with [rlwe.Evaluator].
func (eval *Evaluator) FinalizeKeys(intermediate *IntermediateKeys) (*rlwe.MemEvaluationKeySet, error) {

	if intermediate == nil || len(intermediate.Keys) == 0 {
		return nil, fmt.Errorf("intermediate keys must not be nil or empty")
	}

	galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))

	for rot, gk := range intermediate.Keys {
		if err := hierkeys.ConvertToLattigoConvention(eval.params.Eval, gk); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}
		galoisKeys = append(galoisKeys, gk)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}
