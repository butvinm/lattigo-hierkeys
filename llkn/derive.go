package llkn

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

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
