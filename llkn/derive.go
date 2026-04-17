package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// FinalizeKey converts one level-0 MasterKey to a standard lattigo GaloisKey.
// Thread-safe.
func (eval *Evaluator) FinalizeKey(mk *hierkeys.MasterKey) (*rlwe.GaloisKey, error) {
	return hierkeys.MasterKeyToGaloisKey(eval.params.Eval(), mk)
}
