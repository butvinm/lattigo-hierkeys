package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

// RotToRotEvaluator performs RotToRot between two adjacent hierarchy levels.
// Thread-safe: scratch buffers are drawn from sync.Pool per call, matching
// lattigo v6.2's evaluator pattern.
//
// Create with [NewRotToRotEvaluator].
type RotToRotEvaluator struct {
	paramsTarget rlwe.Parameters
	paramsMaster rlwe.Parameters
	eval         *rlwe.Evaluator  // thread-safe (pool-based in lattigo v6.2)
	pool         *ring.BufferPool // thread-safe (backed by sync.Pool)
}

// NewRotToRotEvaluator creates a thread-safe evaluator for RotToRot between
// the given parameter pairs.
//
// Requires paramsMaster.QCount() == paramsTarget.QCount() + paramsTarget.PCount().
func NewRotToRotEvaluator(paramsTarget, paramsMaster rlwe.Parameters) *RotToRotEvaluator {
	return &RotToRotEvaluator{
		paramsTarget: paramsTarget,
		paramsMaster: paramsMaster,
		eval:         rlwe.NewEvaluator(paramsMaster, nil),
		pool:         ring.NewPool(paramsMaster.RingQ(), structs.NewSyncPoolUint64(paramsMaster.N())),
	}
}

// RotToRot combines inputKey (shift r) with masterKey (shift r') to produce
// a [MasterKey] for shift r+r' (Algorithm 2 from Lee-Lee-Kim-No 2022).
//
// Thread-safe: can be called concurrently from multiple goroutines.
//
// Requires paramsTarget.LogN() == paramsMaster.LogN() and
// paramsMaster.QCount() == paramsTarget.QCount() + paramsTarget.PCount().
func (rtr *RotToRotEvaluator) RotToRot(
	inputKey *MasterKey,
	masterKey *MasterKey,
	targetGalEl uint64,
) (*MasterKey, error) {

	if inputKey == nil || masterKey == nil {
		return nil, fmt.Errorf("inputKey and masterKey must not be nil")
	}

	paramsTarget := rtr.paramsTarget
	paramsMaster := rtr.paramsMaster

	inputGK := inputKey.gk
	masterGK := masterKey.gk

	gc := &inputGK.GadgetCiphertext
	nRNS := len(gc.Value)

	levelQTarget := paramsTarget.MaxLevel()
	levelPTarget := paramsTarget.MaxLevelP()
	levelQMaster := paramsMaster.MaxLevel()

	ringQTarget := paramsTarget.RingQ()
	ringPTarget := paramsTarget.RingP()
	ringQMaster := paramsMaster.RingQ()

	// Scratch buffers from pool
	poolMaster := rtr.pool.AtLevel(levelQMaster)
	bCombined := poolMaster.GetBuffPoly()
	defer poolMaster.RecycleBuffPoly(bCombined)
	aCombined := poolMaster.GetBuffPoly()
	defer poolMaster.RecycleBuffPoly(aCombined)
	bAut := poolMaster.GetBuffPoly()
	defer poolMaster.RecycleBuffPoly(bAut)
	aAut := poolMaster.GetBuffPoly()
	defer poolMaster.RecycleBuffPoly(aAut)

	ctKS := rlwe.NewCiphertext(paramsMaster, 1, levelQMaster)
	ctKS.IsNTT = true

	// Output key at target level
	outputKey := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsTarget, 1, levelQTarget, levelPTarget, 0),
		},
		GaloisElement: targetGalEl,
		NthRoot:       paramsTarget.RingQ().NthRoot(),
	}

	// Automorphism index for master's Galois element
	masterGalEl := masterGK.GaloisElement
	autIdx, err := ring.AutomorphismNTTIndex(ringQMaster.N(), ringQMaster.NthRoot(), masterGalEl)
	if err != nil {
		return nil, fmt.Errorf("AutomorphismNTTIndex: %w", err)
	}

	// Index where P primes start in Q_master
	pIdx := levelQTarget + 1

	for i := 0; i < nRNS; i++ {
		for j := 0; j < len(gc.Value[i]); j++ {
			component := gc.Value[i][j]

			// Step 1: IMForm (strip Montgomery) and combine Q+P into Q_master
			for m := 0; m <= levelQTarget; m++ {
				s := ringQTarget.SubRings[m]
				s.IMForm(component[0].Q.Coeffs[m], bCombined.Coeffs[m])
				s.IMForm(component[1].Q.Coeffs[m], aCombined.Coeffs[m])
			}
			for m := 0; m <= levelPTarget; m++ {
				s := ringPTarget.SubRings[m]
				s.IMForm(component[0].P.Coeffs[m], bCombined.Coeffs[pIdx+m])
				s.IMForm(component[1].P.Coeffs[m], aCombined.Coeffs[pIdx+m])
			}

			// Step 2: Automorph by master's Galois element
			ringQMaster.AutomorphismNTTWithIndex(*bCombined, autIdx, *bAut)
			ringQMaster.AutomorphismNTTWithIndex(*aCombined, autIdx, *aAut)

			// Step 3: GadgetProduct(aAut, masterKey) at paramsMaster
			rtr.eval.GadgetProduct(levelQMaster, *aAut, &masterGK.GadgetCiphertext, ctKS)

			// Step 4: Add automorphed b component
			ringQMaster.Add(*bAut, ctKS.Value[0], ctKS.Value[0])

			// Step 5: Split Q_master back into Q_target and P_target, apply MForm
			for m := 0; m <= levelQTarget; m++ {
				s := ringQTarget.SubRings[m]
				s.MForm(ctKS.Value[0].Coeffs[m], outputKey.Value[i][j][0].Q.Coeffs[m])
				s.MForm(ctKS.Value[1].Coeffs[m], outputKey.Value[i][j][1].Q.Coeffs[m])
			}
			for m := 0; m <= levelPTarget; m++ {
				s := ringPTarget.SubRings[m]
				srcIdx := pIdx + m
				s.MForm(ctKS.Value[0].Coeffs[srcIdx], outputKey.Value[i][j][0].P.Coeffs[m])
				s.MForm(ctKS.Value[1].Coeffs[srcIdx], outputKey.Value[i][j][1].P.Coeffs[m])
			}
		}
	}

	return &MasterKey{gk: outputKey}, nil
}
