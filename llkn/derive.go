package llkn

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

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

	masterRots := hierkeys.SortedIntKeys(tk.MasterRotKeys)
	currentMasters := tk.MasterRotKeys

	isDerived := false
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.Levels[level], eval.params.Top(), tk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("PubToRot at level %d: %w", level, err)
		}
		derived, err := eval.ExpandLevel(level, shift0Key, currentMasters, masterRots)
		if err != nil {
			return nil, fmt.Errorf("expand level %d: %w", level, err)
		}

		if isDerived {
			for rot := range currentMasters {
				currentMasters[rot] = nil
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

	if isDerived {
		for rot := range currentMasters {
			currentMasters[rot] = nil
		}
	}

	return eval.FinalizeKeys(level0Keys)
}

// FinalizeKey converts one level-0 MasterKey to a standard lattigo GaloisKey.
// Thread-safe.
func (eval *Evaluator) FinalizeKey(mk *hierkeys.MasterKey) (*rlwe.GaloisKey, error) {
	return hierkeys.MasterKeyToGaloisKey(eval.params.Eval(), mk)
}

// FinalizeKeys converts level-0 IntermediateKeys to a standard
// [rlwe.MemEvaluationKeySet] usable with lattigo evaluators.
func (eval *Evaluator) FinalizeKeys(intermediate *hierkeys.IntermediateKeys) (*rlwe.MemEvaluationKeySet, error) {

	if intermediate == nil || len(intermediate.Keys) == 0 {
		return nil, fmt.Errorf("intermediate keys must not be nil or empty")
	}

	galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))

	for _, mk := range intermediate.Keys {
		gk, err := eval.FinalizeKey(mk)
		if err != nil {
			return nil, err
		}
		galoisKeys = append(galoisKeys, gk)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}
