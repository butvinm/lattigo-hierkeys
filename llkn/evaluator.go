package llkn

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// Evaluator pre-allocates all buffers for server-side hierarchical key
// derivation via RotToRot (no ring switching needed).
type Evaluator struct {
	params Parameters
	*evaluatorBuffers
}

type evaluatorBuffers struct {
	// Shared RotToRot buffers
	rotBuf *hierkeys.RotToRotBuffers

	// Buffers for convention conversion
	autTmpQ ring.Poly
	autTmpP ring.Poly
}

// NewEvaluator creates an Evaluator with pre-allocated buffers.
func NewEvaluator(params Parameters) *Evaluator {
	return &Evaluator{
		params:           params,
		evaluatorBuffers: newEvaluatorBuffers(params),
	}
}

func newEvaluatorBuffers(params Parameters) *evaluatorBuffers {
	ringQEval := params.Eval.RingQ()

	buf := &evaluatorBuffers{
		rotBuf:  hierkeys.NewRotToRotBuffers(params.Eval, params.Master),
		autTmpQ: ringQEval.NewPoly(),
	}

	if params.Eval.RingP() != nil {
		buf.autTmpP = params.Eval.RingP().NewPoly()
	}

	return buf
}

// ConcurrentCopy creates a copy of this Evaluator that shares read-only
// data (parameters) but has its own mutable buffers.
func (eval *Evaluator) ConcurrentCopy() *Evaluator {
	return &Evaluator{
		params:           eval.params,
		evaluatorBuffers: newEvaluatorBuffers(eval.params),
	}
}

// RotToRot generates a combined rotation key from a level-0 key and a master
// key. See [hierkeys.RotToRot] for details.
func (eval *Evaluator) RotToRot(
	inputKey *rlwe.GaloisKey,
	masterKey *rlwe.GaloisKey,
	combinedGalEl uint64,
) (*rlwe.GaloisKey, error) {
	return hierkeys.RotToRot(eval.rotBuf, eval.params.Eval, eval.params.Master, inputKey, masterKey, combinedGalEl)
}

// convertToLattigoConvention applies pi^{-1} to each GadgetCiphertext component,
// converting from paper convention to lattigo convention in-place.
// Uses pre-allocated buffers for efficiency.
func (eval *Evaluator) convertToLattigoConvention(gk *rlwe.GaloisKey) error {

	paramsEval := eval.params.Eval

	galEl := gk.GaloisElement
	galElInv := paramsEval.ModInvGaloisElement(galEl)

	ringQ := paramsEval.RingQ()
	ringP := paramsEval.RingP()

	indexQ, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galElInv)
	if err != nil {
		return err
	}

	var indexP []uint64
	if ringP != nil {
		indexP, err = ring.AutomorphismNTTIndex(ringP.N(), ringP.NthRoot(), galElInv)
		if err != nil {
			return err
		}
	}

	for i := range gk.Value {
		for j := range gk.Value[i] {
			component := gk.Value[i][j]

			eval.automorphInPlaceQ(ringQ, indexQ, component[0].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[0].P)
			}

			eval.automorphInPlaceQ(ringQ, indexQ, component[1].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[1].P)
			}
		}
	}

	return nil
}

func (eval *Evaluator) automorphInPlaceQ(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpQ)
	p.CopyLvl(p.Level(), eval.autTmpQ)
}

func (eval *Evaluator) automorphInPlaceP(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpP)
	p.CopyLvl(p.Level(), eval.autTmpP)
}
