package kgplus

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// FinalizeKey ring-switches one R' MasterKey to R and converts to a standard
// lattigo GaloisKey. Thread-safe.
func (eval *Evaluator) FinalizeKey(rot int, mk *hierkeys.MasterKey, homingKey *rlwe.EvaluationKey) (*rlwe.GaloisKey, error) {
	galElR := eval.params.eval.GaloisElement(rot)
	rsGK, err := eval.RingSwitchGaloisKey(mk, homingKey, galElR)
	if err != nil {
		return nil, fmt.Errorf("ring switch for rotation %d: %w", rot, err)
	}
	if err = eval.convertToLattigoConvention(rsGK); err != nil {
		return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
	}
	return rsGK, nil
}

// RingSwitchGaloisKey ring-switches a MasterKey from R' (degree 2N) to a
// standard GaloisKey in R (degree N) using a homing key. Thread-safe.
func (eval *Evaluator) RingSwitchGaloisKey(
	masterKeyRP *hierkeys.MasterKey,
	homingKey *rlwe.EvaluationKey,
	galoisElement uint64,
) (*rlwe.GaloisKey, error) {

	paramsEval := eval.params.eval
	paramsHK := eval.params.HK
	paramsRP := eval.params.Levels[0]

	if masterKeyRP == nil || homingKey == nil {
		return nil, fmt.Errorf("masterKeyRP and homingKey must not be nil")
	}

	rpGK := masterKeyRP.GaloisKey()

	N := paramsEval.N()
	ringQHK := paramsHK.RingQ()

	levelQHK := paramsHK.MaxLevel()
	levelQEval := paramsEval.MaxLevel()
	levelPEval := paramsEval.MaxLevelP()

	gc := &rpGK.GadgetCiphertext
	nRNS := len(gc.Value)

	nEvalRNS := paramsEval.BaseRNSDecompositionVectorSize(levelQEval, levelPEval)
	if nRNS < nEvalRNS {
		return nil, fmt.Errorf("master key has %d RNS components, need at least %d", nRNS, nEvalRNS)
	}

	targetGK := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsEval, 1, levelQEval, levelPEval, 0),
		},
		GaloisElement: galoisElement,
		NthRoot:       paramsEval.RingQ().NthRoot(),
	}

	ringQRP := paramsRP.RingQ()
	ringPRP := paramsRP.RingP()
	ringQEval := paramsEval.RingQ()
	ringPEval := paramsEval.RingP()

	// Pool-based scratch buffers
	poolRPQ := eval.poolRPQ.AtLevel(paramsRP.MaxLevel())
	bQRP := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(bQRP)
	aQRP := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(aQRP)
	bQCoeff := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(bQCoeff)
	aQCoeff := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(aQCoeff)

	poolRPP := eval.poolRPP.AtLevel(paramsRP.MaxLevelP())
	bPRP := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(bPRP)
	aPRP := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(aPRP)
	bPCoeff := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(bPCoeff)
	aPCoeff := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(aPCoeff)

	poolHK := eval.poolHK.AtLevel(levelQHK)
	b0 := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(b0)
	a0 := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(a0)
	a1 := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(a1)
	Xa1 := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(Xa1)
	rsB := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(rsB)
	rsA := poolHK.GetBuffPoly()
	defer poolHK.RecycleBuffPoly(rsA)

	ctKS := rlwe.NewCiphertext(paramsHK, 1, levelQHK)
	ctKS.IsNTT = true

	pIdx := levelQEval + 1

	for i := 0; i < nEvalRNS; i++ {
		component := gc.Value[i][0]

		bQRP.CopyLvl(paramsRP.MaxLevel(), component[0].Q)
		aQRP.CopyLvl(paramsRP.MaxLevel(), component[1].Q)
		ringQRP.IMForm(*bQRP, *bQRP)
		ringQRP.IMForm(*aQRP, *aQRP)
		ringQRP.INTT(*bQRP, *bQCoeff)
		ringQRP.INTT(*aQRP, *aQCoeff)

		bPRP.CopyLvl(paramsRP.MaxLevelP(), component[0].P)
		aPRP.CopyLvl(paramsRP.MaxLevelP(), component[1].P)
		ringPRP.IMForm(*bPRP, *bPRP)
		ringPRP.IMForm(*aPRP, *aPRP)
		ringPRP.INTT(*bPRP, *bPCoeff)
		ringPRP.INTT(*aPRP, *aPCoeff)

		for m := 0; m <= paramsRP.MaxLevel(); m++ {
			for j := 0; j < N; j++ {
				b0.Coeffs[m][j] = bQCoeff.Coeffs[m][2*j]
				a0.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j]
				a1.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j+1]
			}
		}
		for m := 0; m <= paramsRP.MaxLevelP(); m++ {
			for j := 0; j < N; j++ {
				b0.Coeffs[pIdx+m][j] = bPCoeff.Coeffs[m][2*j]
				a0.Coeffs[pIdx+m][j] = aPCoeff.Coeffs[m][2*j]
				a1.Coeffs[pIdx+m][j] = aPCoeff.Coeffs[m][2*j+1]
			}
		}

		for m := range a1.Coeffs {
			qi := ringQHK.SubRings[m].Modulus
			Xa1.Coeffs[m][0] = qi - a1.Coeffs[m][N-1]
			for k := 1; k < N; k++ {
				Xa1.Coeffs[m][k] = a1.Coeffs[m][k-1]
			}
		}

		ringQHK.NTT(*b0, *b0)
		ringQHK.NTT(*a0, *a0)
		ringQHK.NTT(*Xa1, *Xa1)

		eval.evalHK.GadgetProduct(levelQHK, *Xa1, &homingKey.GadgetCiphertext, ctKS)

		ringQHK.Add(*b0, ctKS.Value[0], *rsB)
		ringQHK.Add(*a0, ctKS.Value[1], *rsA)

		for m := 0; m <= levelQEval; m++ {
			s := ringQEval.SubRings[m]
			s.MForm(rsB.Coeffs[m], targetGK.Value[i][0][0].Q.Coeffs[m])
			s.MForm(rsA.Coeffs[m], targetGK.Value[i][0][1].Q.Coeffs[m])
		}
		for m := 0; m <= levelPEval; m++ {
			s := ringPEval.SubRings[m]
			srcIdx := pIdx + m
			s.MForm(rsB.Coeffs[srcIdx], targetGK.Value[i][0][0].P.Coeffs[m])
			s.MForm(rsA.Coeffs[srcIdx], targetGK.Value[i][0][1].P.Coeffs[m])
		}
	}

	return targetGK, nil
}

// convertToLattigoConvention applies pi^{-1} to each GadgetCiphertext component,
// converting from paper convention to lattigo convention in-place.
// Thread-safe: uses pool-based scratch buffers.
func (eval *Evaluator) convertToLattigoConvention(gk *rlwe.GaloisKey) error {

	paramsEval := eval.params.eval

	galEl := gk.GaloisElement
	galElInv := paramsEval.ModInvGaloisElement(galEl)

	ringQ := paramsEval.RingQ()
	ringP := paramsEval.RingP()

	indexQ, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galElInv)
	if err != nil {
		return fmt.Errorf("Q automorphism index: %w", err)
	}

	var indexP []uint64
	if ringP != nil {
		indexP, err = ring.AutomorphismNTTIndex(ringP.N(), ringP.NthRoot(), galElInv)
		if err != nil {
			return fmt.Errorf("P automorphism index: %w", err)
		}
	}

	// Pool-based scratch for automorphism
	poolQ := eval.poolEvQ.AtLevel(paramsEval.MaxLevel())
	autTmpQ := poolQ.GetBuffPoly()
	defer poolQ.RecycleBuffPoly(autTmpQ)

	var autTmpP *ring.Poly
	if ringP != nil {
		poolP := eval.poolEvP.AtLevel(paramsEval.MaxLevelP())
		autTmpP = poolP.GetBuffPoly()
		defer poolP.RecycleBuffPoly(autTmpP)
	}

	for i := range gk.Value {
		for j := range gk.Value[i] {
			component := gk.Value[i][j]

			ringQ.AutomorphismNTTWithIndex(component[0].Q, indexQ, *autTmpQ)
			component[0].Q.CopyLvl(component[0].Q.Level(), *autTmpQ)
			if ringP != nil {
				ringP.AutomorphismNTTWithIndex(component[0].P, indexP, *autTmpP)
				component[0].P.CopyLvl(component[0].P.Level(), *autTmpP)
			}

			ringQ.AutomorphismNTTWithIndex(component[1].Q, indexQ, *autTmpQ)
			component[1].Q.CopyLvl(component[1].Q.Level(), *autTmpQ)
			if ringP != nil {
				ringP.AutomorphismNTTWithIndex(component[1].P, indexP, *autTmpP)
				component[1].P.CopyLvl(component[1].P.Level(), *autTmpP)
			}
		}
	}

	return nil
}
