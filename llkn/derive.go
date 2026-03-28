package llkn

import (
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// IntermediateKeys holds GaloisKeys produced by RotToRot expansion at a
// single hierarchy level. These are in the paper's convention (not yet
// post-converted). They can be serialized, stored, and later used as input
// to expand the next level down or finalized via [Evaluator.FinalizeKeys].
type IntermediateKeys struct {
	Keys map[int]*rlwe.GaloisKey // indexed by rotation index
}

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys in one shot. The returned keys are in lattigo convention
// and work directly with rlwe.Evaluator.Automorphism, ckks.Evaluator.Rotate,
// and hoisted rotations.
//
// For per-level control (e.g., storing intermediates at each level for the
// inactive/active pattern), derive shift-0 keys via PubToRot and use
// [Evaluator.ExpandLevel] directly:
//
//	shift0L1, _ := hierkeys.PubToRot(params.Levels[1], params.Top(), tk.EncZero)
//	level1Keys, _ := eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots)
//	// store level1Keys to disk...
//	shift0L0, _ := hierkeys.PubToRot(params.Levels[0], params.Top(), tk.EncZero)
//	level0Keys, _ := eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots)
//	// store level0Keys to disk...
//	evk, _ := eval.FinalizeKeys(level0Keys)
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.EncZero == nil {
		return nil, fmt.Errorf("transmission keys and EncZero must not be nil")
	}

	k := eval.params.NumLevels()

	masterRots := sortedKeys(tk.MasterRotKeys)
	currentMasters := tk.MasterRotKeys

	isDerived := false // tracks whether currentMasters is derived (safe to nil) vs original TX data
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.Levels[level], eval.params.Top(), tk.EncZero)
		if err != nil {
			return nil, fmt.Errorf("PubToRot at level %d: %w", level, err)
		}
		derived, err := eval.ExpandLevel(level, shift0Key, currentMasters, masterRots)
		if err != nil {
			return nil, fmt.Errorf("expand level %d: %w", level, err)
		}

		// Release previous level's derived keys — no longer needed.
		// Skip if currentMasters is tk.MasterRotKeys (don't mutate caller's data).
		if isDerived {
			for rot := range currentMasters {
				currentMasters[rot] = nil // permit early GC
			}
		}

		currentMasters = derived.Keys
		isDerived = true
	}

	shift0Key0, err := hierkeys.PubToRot(eval.params.Levels[0], eval.params.Top(), tk.EncZero)
	if err != nil {
		return nil, fmt.Errorf("PubToRot at level 0: %w", err)
	}
	level0Keys, err := eval.ExpandLevel(0, shift0Key0, currentMasters, targetRotations)
	if err != nil {
		return nil, fmt.Errorf("expand level 0: %w", err)
	}

	// Release intermediate masters — no longer needed after level-0 expansion.
	if isDerived {
		for rot := range currentMasters {
			currentMasters[rot] = nil // permit early GC
		}
	}

	return eval.FinalizeKeys(level0Keys)
}

// ExpandLevel derives keys at the given hierarchy level using RotToRot with
// master keys from the level above.
//
// Parameters:
//   - level: the hierarchy level to derive keys at (0 = eval level)
//   - shift0Key: the identity (shift-0) key at this level (derived via PubToRot from TransmissionKeys.EncZero)
//   - masterKeys: keys at level+1, indexed by rotation (either from TransmissionKeys.MasterRotKeys
//     or from a previous ExpandLevel call's IntermediateKeys.Keys)
//   - targetRotations: which rotations to derive at this level
//
// The returned IntermediateKeys can be serialized for storage, then later
// passed as masterKeys to the next ExpandLevel call (level-1), or finalized
// via [Evaluator.FinalizeKeys] if level == 0.
//
// Intermediate RotToRot results within a level are cached: if multiple targets
// share a decomposition prefix, the shared intermediate is computed once.
func (eval *Evaluator) ExpandLevel(
	level int,
	shift0Key *rlwe.GaloisKey,
	masterKeys map[int]*rlwe.GaloisKey,
	targetRotations []int,
) (*IntermediateKeys, error) {

	if shift0Key == nil {
		return nil, fmt.Errorf("shift-0 key must not be nil")
	}

	if len(masterKeys) == 0 {
		return nil, fmt.Errorf("master keys must not be empty")
	}

	paramsLow := eval.params.Levels[level]
	nSlots := eval.params.Eval().N() / 2

	masterRots := sortedKeys(masterKeys)

	cache := make(map[int]*rlwe.GaloisKey)
	cache[0] = shift0Key

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
				masterKey, ok := masterKeys[step]
				if !ok {
					return nil, fmt.Errorf("missing master key for rotation %d at level %d", step, level+1)
				}
				combinedGalEl := paramsLow.GaloisElement(nextRot)
				key, err := eval.RotToRot(level, cache[currentRot], masterKey, combinedGalEl)
				if err != nil {
					return nil, fmt.Errorf("RotToRot step (current=%d + master=%d -> %d): %w",
						currentRot, step, nextRot, err)
				}
				cache[nextRot] = key
			}

			currentRot = nextRot
		}
	}

	result := &IntermediateKeys{Keys: make(map[int]*rlwe.GaloisKey, len(targetRotations))}
	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}
		if key, ok := cache[normalized]; ok {
			result.Keys[target] = key
		}
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
		if err := hierkeys.ConvertToLattigoConvention(eval.params.Eval(), gk); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}
		galoisKeys = append(galoisKeys, gk)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}

func sortedKeys(m map[int]*rlwe.GaloisKey) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
