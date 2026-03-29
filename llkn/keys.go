// Package llkn implements LLKN hierarchical rotation key derivation (same ring, no ring switching).
//
//	Client: rlwe.GenSecretKeyNew → rlwe.GenGaloisKeyNew → hierkeys.GaloisKeyToMasterKey → TransmissionKeys
//	Server: PubToRot → ExpandLevel → FinalizeKeys → rlwe.MemEvaluationKeySet
//
// See example/llkn/simple for complete single-party flow,
// and example/llkn/multiparty for N-out-of-N multiparty.
package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// TransmissionKeys holds the client-to-server data for hierarchical key derivation.
type TransmissionKeys struct {
	PublicKey     *rlwe.PublicKey             // at top level, used by PubToRot
	MasterRotKeys map[int]*hierkeys.MasterKey // at top level, indexed by rotation
}
