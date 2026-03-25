package llkn

import (
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

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
// Unlike KG+, LLKN does not need ring switching — the RotToRot output
// is already in the evaluation ring R. Convention conversion (π⁻¹
// automorphism) is applied to produce lattigo-compatible keys.
//
// The returned MemEvaluationKeySet can be passed directly to
// rlwe.NewEvaluator or ckks.NewEvaluator.
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

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

	// Convert from paper convention to lattigo convention and collect
	galoisKeys := make([]*rlwe.GaloisKey, 0, len(targetRotations))

	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}

		gk := cache[normalized]

		if err := hierkeys.ConvertToLattigoConvention(eval.params.Eval, gk); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", target, err)
		}

		galoisKeys = append(galoisKeys, gk)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}
