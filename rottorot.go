package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// RotToRot is a convenience wrapper that creates a temporary Evaluator
// internally. For repeated calls, use [Evaluator.RotToRot].
// RotToRot is a convenience wrapper that creates a temporary Evaluator.
// For repeated calls, use [Evaluator.RotToRot].
//
// Note: allocates a full Evaluator with buffers for all parameter sets.
// Eval/HK placeholders mean some buffers are over-sized but unused.
func RotToRot(
	paramsLow rlwe.Parameters,
	paramsHigh rlwe.Parameters,
	inputKey *rlwe.GaloisKey,
	masterKey *rlwe.GaloisKey,
	combinedGalEl uint64,
) (*rlwe.GaloisKey, error) {
	params := Parameters{
		Eval:         paramsLow, // placeholder — ring-switch buffers unused by RotToRot
		HK:           paramsLow, // placeholder
		RPrime:       paramsLow,
		RPrimeMaster: paramsHigh,
	}
	eval := NewEvaluator(params)
	return eval.RotToRot(inputKey, masterKey, combinedGalEl)
}

// RotToRot generates a combined rotation key from a level-0 key and a master
// key in the extension ring R', implementing Algorithm 2 from the Lee-Lee-Kim-No
// paper "Rotation Key Reduction for Client-Server Systems of Deep Neural Networks."
//
// Given:
//   - inputKey: a level-0 rotation key for shift r (at RPrime: Q=Q_eval, P=P_eval, degree 2N)
//   - masterKey: a master rotation key for shift r' (at RPrimeMaster: Q=Q_eval|P_eval, P=P_hk, degree 2N)
//
// Produces: a level-0 rotation key for shift r+r' (at RPrime).
//
// The operation treats each GadgetCiphertext component (b_i, a_i) of inputKey
// as a ciphertext and applies: automorph by master's Galois element, then
// key-switch using masterKey's GadgetCiphertext.
//
// PARAMETER REQUIREMENTS:
//   - params.RPrime.LogN() == params.RPrimeMaster.LogN() (both degree 2N)
//   - params.RPrimeMaster.QCount() == params.RPrime.QCount() + params.RPrime.PCount()
func (eval *Evaluator) RotToRot(
	inputKey *rlwe.GaloisKey,
	masterKey *rlwe.GaloisKey,
	combinedGalEl uint64,
) (*rlwe.GaloisKey, error) {

	paramsLow := eval.params.RPrime
	paramsHigh := eval.params.RPrimeMaster

	// --- Input validation ---
	if inputKey == nil || masterKey == nil {
		return nil, fmt.Errorf("inputKey and masterKey must not be nil")
	}
	if paramsLow.LogN() != paramsHigh.LogN() {
		return nil, fmt.Errorf("paramsLow.LogN()=%d must equal paramsHigh.LogN()=%d",
			paramsLow.LogN(), paramsHigh.LogN())
	}
	expectedQHigh := paramsLow.QCount() + paramsLow.PCount()
	if paramsHigh.QCount() != expectedQHigh {
		return nil, fmt.Errorf("paramsHigh.QCount()=%d must equal paramsLow.QCount()+PCount()=%d",
			paramsHigh.QCount(), expectedQHigh)
	}

	gc := &inputKey.GadgetCiphertext
	nRNS := len(gc.Value)

	levelQLow := paramsLow.MaxLevel()
	levelPLow := paramsLow.MaxLevelP()
	levelQHigh := paramsHigh.MaxLevel()

	ringQLow := paramsLow.RingQ()
	ringPLow := paramsLow.RingP()
	ringQHigh := paramsHigh.RingQ()

	// --- Output key at level-0 ---
	outputKey := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsLow, 1, levelQLow, levelPLow, 0),
		},
		GaloisElement: combinedGalEl,
		NthRoot:       paramsLow.RingQ().NthRoot(),
	}

	// --- Automorphism index for master's Galois element ---
	masterGalEl := masterKey.GaloisElement
	autIdx, err := ring.AutomorphismNTTIndex(ringQHigh.N(), ringQHigh.NthRoot(), masterGalEl)
	if err != nil {
		return nil, fmt.Errorf("AutomorphismNTTIndex: %w", err)
	}

	// Use pre-allocated buffers
	bCombined := eval.bCombined
	aCombined := eval.aCombined
	bAut := eval.bAut
	aAut := eval.aAut
	ctKS := eval.ctKSRot

	// Index where P_eval primes start in Q_hk
	pIdx := levelQLow + 1

	for i := 0; i < nRNS; i++ {
		for j := 0; j < len(gc.Value[i]); j++ {
			component := gc.Value[i][j]

			// Step 1: IMForm (strip Montgomery) and combine Q+P into Q_hk
			for m := 0; m <= levelQLow; m++ {
				s := ringQLow.SubRings[m]
				s.IMForm(component[0].Q.Coeffs[m], bCombined.Coeffs[m])
				s.IMForm(component[1].Q.Coeffs[m], aCombined.Coeffs[m])
			}
			for m := 0; m <= levelPLow; m++ {
				s := ringPLow.SubRings[m]
				s.IMForm(component[0].P.Coeffs[m], bCombined.Coeffs[pIdx+m])
				s.IMForm(component[1].P.Coeffs[m], aCombined.Coeffs[pIdx+m])
			}

			// Step 2: Automorph by master's Galois element
			ringQHigh.AutomorphismNTTWithIndex(bCombined, autIdx, bAut)
			ringQHigh.AutomorphismNTTWithIndex(aCombined, autIdx, aAut)

			// Step 3: GadgetProduct(aAut, masterKey) at paramsHigh
			eval.evalRot.GadgetProduct(levelQHigh, aAut, &masterKey.GadgetCiphertext, ctKS)

			// Step 4: Add automorphed b component
			ringQHigh.Add(bAut, ctKS.Value[0], ctKS.Value[0])

			// Step 5: Split Q_hk back into Q_eval and P_eval, apply MForm
			for m := 0; m <= levelQLow; m++ {
				s := ringQLow.SubRings[m]
				s.MForm(ctKS.Value[0].Coeffs[m], outputKey.Value[i][j][0].Q.Coeffs[m])
				s.MForm(ctKS.Value[1].Coeffs[m], outputKey.Value[i][j][1].Q.Coeffs[m])
			}
			for m := 0; m <= levelPLow; m++ {
				s := ringPLow.SubRings[m]
				srcIdx := pIdx + m
				s.MForm(ctKS.Value[0].Coeffs[srcIdx], outputKey.Value[i][j][0].P.Coeffs[m])
				s.MForm(ctKS.Value[1].Coeffs[srcIdx], outputKey.Value[i][j][1].P.Coeffs[m])
			}
		}
	}

	return outputKey, nil
}
