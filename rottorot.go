package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// RotToRotBuffers holds pre-allocated buffers for the [RotToRot] operation.
// Create with [NewRotToRotBuffers]. Not safe for concurrent use; create one
// per goroutine.
type RotToRotBuffers struct {
	// Combined Q+P at high level
	BCombined, ACombined ring.Poly
	// Automorphed at high level
	BAut, AAut ring.Poly
	// Key-switch output
	CtKS *rlwe.Ciphertext
	// Evaluator at paramsHigh level for GadgetProduct
	Eval *rlwe.Evaluator
}

// NewRotToRotBuffers allocates buffers for RotToRot between the given
// parameter pairs.
func NewRotToRotBuffers(paramsTarget, paramsMaster rlwe.Parameters) *RotToRotBuffers {
	ringQHigh := paramsMaster.RingQ()
	ctKS := rlwe.NewCiphertext(paramsMaster, 1, paramsMaster.MaxLevel())
	ctKS.IsNTT = true

	return &RotToRotBuffers{
		BCombined: ringQHigh.NewPoly(),
		ACombined: ringQHigh.NewPoly(),
		BAut:      ringQHigh.NewPoly(),
		AAut:      ringQHigh.NewPoly(),
		CtKS:      ctKS,
		Eval:      rlwe.NewEvaluator(paramsMaster, nil),
	}
}

// RotToRot combines inputKey (shift r) with masterKey (shift r') to produce
// a [MasterKey] for shift r+r' (Algorithm 2 from Lee-Lee-Kim-No 2022).
//
// Requires paramsTarget.LogN() == paramsMaster.LogN() and
// paramsMaster.QCount() == paramsTarget.QCount() + paramsTarget.PCount().
func RotToRot(
	buf *RotToRotBuffers,
	paramsTarget, paramsMaster rlwe.Parameters,
	inputKey *MasterKey,
	masterKey *MasterKey,
	targetGalEl uint64,
) (*MasterKey, error) {

	// --- Input validation ---
	if inputKey == nil || masterKey == nil {
		return nil, fmt.Errorf("inputKey and masterKey must not be nil")
	}
	if paramsTarget.LogN() != paramsMaster.LogN() {
		return nil, fmt.Errorf("paramsTarget.LogN()=%d must equal paramsMaster.LogN()=%d",
			paramsTarget.LogN(), paramsMaster.LogN())
	}
	expectedQMaster := paramsTarget.QCount() + paramsTarget.PCount()
	if paramsMaster.QCount() != expectedQMaster {
		return nil, fmt.Errorf("paramsMaster.QCount()=%d must equal paramsTarget.QCount()+PCount()=%d",
			paramsMaster.QCount(), expectedQMaster)
	}

	inputGK := inputKey.gk
	masterGK := masterKey.gk

	gc := &inputGK.GadgetCiphertext
	nRNS := len(gc.Value)

	levelQLow := paramsTarget.MaxLevel()
	levelPLow := paramsTarget.MaxLevelP()
	levelQHigh := paramsMaster.MaxLevel()

	ringQLow := paramsTarget.RingQ()
	ringPLow := paramsTarget.RingP()
	ringQHigh := paramsMaster.RingQ()

	// --- Output key at target level ---
	outputKey := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsTarget, 1, levelQLow, levelPLow, 0),
		},
		GaloisElement: targetGalEl,
		NthRoot:       paramsTarget.RingQ().NthRoot(),
	}

	// --- Automorphism index for master's Galois element ---
	masterGalEl := masterGK.GaloisElement
	autIdx, err := ring.AutomorphismNTTIndex(ringQHigh.N(), ringQHigh.NthRoot(), masterGalEl)
	if err != nil {
		return nil, fmt.Errorf("AutomorphismNTTIndex: %w", err)
	}

	// Index where P primes start in Q_high
	pIdx := levelQLow + 1

	for i := 0; i < nRNS; i++ {
		for j := 0; j < len(gc.Value[i]); j++ {
			component := gc.Value[i][j]

			// Step 1: IMForm (strip Montgomery) and combine Q+P into Q_high
			for m := 0; m <= levelQLow; m++ {
				s := ringQLow.SubRings[m]
				s.IMForm(component[0].Q.Coeffs[m], buf.BCombined.Coeffs[m])
				s.IMForm(component[1].Q.Coeffs[m], buf.ACombined.Coeffs[m])
			}
			for m := 0; m <= levelPLow; m++ {
				s := ringPLow.SubRings[m]
				s.IMForm(component[0].P.Coeffs[m], buf.BCombined.Coeffs[pIdx+m])
				s.IMForm(component[1].P.Coeffs[m], buf.ACombined.Coeffs[pIdx+m])
			}

			// Step 2: Automorph by master's Galois element
			ringQHigh.AutomorphismNTTWithIndex(buf.BCombined, autIdx, buf.BAut)
			ringQHigh.AutomorphismNTTWithIndex(buf.ACombined, autIdx, buf.AAut)

			// Step 3: GadgetProduct(aAut, masterKey) at paramsHigh
			buf.Eval.GadgetProduct(levelQHigh, buf.AAut, &masterGK.GadgetCiphertext, buf.CtKS)

			// Step 4: Add automorphed b component
			ringQHigh.Add(buf.BAut, buf.CtKS.Value[0], buf.CtKS.Value[0])

			// Step 5: Split Q_high back into Q_low and P_low, apply MForm
			for m := 0; m <= levelQLow; m++ {
				s := ringQLow.SubRings[m]
				s.MForm(buf.CtKS.Value[0].Coeffs[m], outputKey.Value[i][j][0].Q.Coeffs[m])
				s.MForm(buf.CtKS.Value[1].Coeffs[m], outputKey.Value[i][j][1].Q.Coeffs[m])
			}
			for m := 0; m <= levelPLow; m++ {
				s := ringPLow.SubRings[m]
				srcIdx := pIdx + m
				s.MForm(buf.CtKS.Value[0].Coeffs[srcIdx], outputKey.Value[i][j][0].P.Coeffs[m])
				s.MForm(buf.CtKS.Value[1].Coeffs[srcIdx], outputKey.Value[i][j][1].P.Coeffs[m])
			}
		}
	}

	return &MasterKey{gk: outputKey}, nil
}
