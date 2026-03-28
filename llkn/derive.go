package llkn

import (
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// IntermediateKeys holds MasterKeys produced by [Evaluator.ExpandLevel] at a
// single hierarchy level. Can be serialized, used as input to the next
// ExpandLevel call, or finalized via [Evaluator.FinalizeKeys].
type IntermediateKeys struct {
	Keys map[int]*hierkeys.MasterKey // indexed by rotation index
}

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys in one shot. The returned keys work with standard
// lattigo evaluators.
//
// For per-level control (inactive/active pattern), use [Evaluator.ExpandLevel]
// and [Evaluator.FinalizeKeys] directly. See example/llkn.
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.PublicKey == nil {
		return nil, fmt.Errorf("transmission keys and PublicKey must not be nil")
	}

	k := eval.params.NumLevels()

	masterRots := sortedKeys(tk.MasterRotKeys)
	currentMasters := tk.MasterRotKeys

	isDerived := false // tracks whether currentMasters is derived (safe to nil) vs original TX data
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.Levels[level], eval.params.Top(), tk.PublicKey)
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

	shift0Key0, err := hierkeys.PubToRot(eval.params.Levels[0], eval.params.Top(), tk.PublicKey)
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

// ExpandLevel derives keys at the given hierarchy level using RotToRot.
// shift0Key comes from [hierkeys.PubToRot], masterKeys from [TransmissionKeys]
// or a previous ExpandLevel call. Shared decomposition prefixes are cached.
func (eval *Evaluator) ExpandLevel(
	level int,
	shift0Key *hierkeys.MasterKey,
	masterKeys map[int]*hierkeys.MasterKey,
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

	cache := make(map[int]*hierkeys.MasterKey)
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

	result := &IntermediateKeys{Keys: make(map[int]*hierkeys.MasterKey, len(targetRotations))}
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

// FinalizeKeys converts level-0 IntermediateKeys to a standard
// [rlwe.MemEvaluationKeySet] usable with lattigo evaluators.
func (eval *Evaluator) FinalizeKeys(intermediate *IntermediateKeys) (*rlwe.MemEvaluationKeySet, error) {

	if intermediate == nil || len(intermediate.Keys) == 0 {
		return nil, fmt.Errorf("intermediate keys must not be nil or empty")
	}

	galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))

	for rot, mk := range intermediate.Keys {
		gk, err := hierkeys.MasterKeyToGaloisKey(eval.params.Eval(), mk)
		if err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}
		galoisKeys = append(galoisKeys, gk)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}

func sortedKeys(m map[int]*hierkeys.MasterKey) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
