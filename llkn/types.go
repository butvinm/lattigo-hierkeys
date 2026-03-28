package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// TransmissionKeys holds everything the client sends to the server.
type TransmissionKeys struct {
	// PublicKey at the top level (Levels[k-1]).
	// The server derives shift-0 keys at each lower level via PubToRot.
	PublicKey *rlwe.PublicKey

	// MasterRotKeys are rotation keys at the top level in paper convention.
	// Indexed by rotation index (not Galois element).
	MasterRotKeys map[int]*hierkeys.MasterKey
}
