package kgplus

import (
	"fmt"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys in one shot. The returned keys work with standard
// lattigo evaluators.
//
// For per-level control (inactive/active pattern), use [Evaluator.ExpandLevel]
// and [Evaluator.FinalizeKeys] directly. See example/kgplus.
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.PublicKey == nil {
		return nil, fmt.Errorf("transmission keys and PublicKey must not be nil")
	}

	k := eval.params.NumLevels()
	topLevel := k - 1

	masterRots := hierkeys.SortedIntKeys(tk.MasterRotKeys)
	currentMasters := tk.MasterRotKeys

	isDerived := false
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.RPrime[level], eval.params.RPrime[topLevel], tk.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("PubToRot at level %d: %w", level, err)
		}
		derived, err := eval.ExpandLevel(level, shift0Key, currentMasters, masterRots)
		if err != nil {
			return nil, fmt.Errorf("expand R' level %d: %w", level, err)
		}

		if isDerived {
			for rot := range currentMasters {
				currentMasters[rot] = nil
			}
		}

		currentMasters = derived.Keys
		isDerived = true
	}

	shift0Key0, err := hierkeys.PubToRot(eval.params.RPrime[0], eval.params.RPrime[topLevel], tk.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("PubToRot at level 0: %w", err)
	}
	level0Keys, err := eval.ExpandLevel(0, shift0Key0, currentMasters, targetRotations)
	if err != nil {
		return nil, fmt.Errorf("expand R' level 0: %w", err)
	}

	if isDerived {
		for rot := range currentMasters {
			currentMasters[rot] = nil
		}
	}

	return eval.FinalizeKeys(tk, level0Keys)
}

// FinalizeKey ring-switches one R' MasterKey to R and converts to a standard
// lattigo GaloisKey. Thread-safe.
func (eval *Evaluator) FinalizeKey(rot int, mk *hierkeys.MasterKey, homingKey *rlwe.EvaluationKey) (*rlwe.GaloisKey, error) {
	galElR := eval.params.Eval.GaloisElement(rot)
	rsGK, err := eval.RingSwitchGaloisKey(mk, homingKey, galElR)
	if err != nil {
		return nil, fmt.Errorf("ring switch for rotation %d: %w", rot, err)
	}
	if err = eval.convertToLattigoConvention(rsGK); err != nil {
		return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
	}
	return rsGK, nil
}

// FinalizeKeys ring-switches level-0 R' IntermediateKeys to R and converts
// to standard [rlwe.MemEvaluationKeySet] usable with lattigo evaluators.
func (eval *Evaluator) FinalizeKeys(tk *TransmissionKeys, intermediate *hierkeys.IntermediateKeys) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.HomingKey == nil {
		return nil, fmt.Errorf("transmission keys and homing key must not be nil")
	}

	if intermediate == nil || len(intermediate.Keys) == 0 {
		return nil, fmt.Errorf("intermediate keys must not be nil or empty")
	}

	params := eval.params
	galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))

	for rot, mk := range intermediate.Keys {
		galElR := params.Eval.GaloisElement(rot)
		rsGK, err := eval.RingSwitchGaloisKey(mk, tk.HomingKey, galElR)
		if err != nil {
			return nil, fmt.Errorf("ring switch for rotation %d: %w", rot, err)
		}

		intermediate.Keys[rot] = nil

		if err := eval.convertToLattigoConvention(rsGK); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}

		galoisKeys = append(galoisKeys, rsGK)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}

// RingSwitchGaloisKey ring-switches a MasterKey from R' (degree 2N) to a
// standard GaloisKey in R (degree N) using a homing key. Thread-safe.
func (eval *Evaluator) RingSwitchGaloisKey(
	masterKeyRPrime *hierkeys.MasterKey,
	homingKey *rlwe.EvaluationKey,
	galoisElement uint64,
) (*rlwe.GaloisKey, error) {

	paramsEval := eval.params.Eval
	paramsHK := eval.params.HK
	paramsRPrime := eval.params.RPrime[0]

	if masterKeyRPrime == nil || homingKey == nil {
		return nil, fmt.Errorf("masterKeyRPrime and homingKey must not be nil")
	}

	rpGK := masterKeyRPrime.GaloisKey()

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

	ringQRPrimeQ := paramsRPrime.RingQ()
	ringPRPrime := paramsRPrime.RingP()
	ringQEval := paramsEval.RingQ()
	ringPEval := paramsEval.RingP()

	// Pool-based scratch buffers
	poolRPQ := eval.poolRPQ.AtLevel(paramsRPrime.MaxLevel())
	bQRPrime := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(bQRPrime)
	aQRPrime := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(aQRPrime)
	bQCoeff := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(bQCoeff)
	aQCoeff := poolRPQ.GetBuffPoly()
	defer poolRPQ.RecycleBuffPoly(aQCoeff)

	poolRPP := eval.poolRPP.AtLevel(paramsRPrime.MaxLevelP())
	bPRPrime := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(bPRPrime)
	aPRPrime := poolRPP.GetBuffPoly()
	defer poolRPP.RecycleBuffPoly(aPRPrime)
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

		bQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[0].Q)
		aQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[1].Q)
		ringQRPrimeQ.IMForm(*bQRPrime, *bQRPrime)
		ringQRPrimeQ.IMForm(*aQRPrime, *aQRPrime)
		ringQRPrimeQ.INTT(*bQRPrime, *bQCoeff)
		ringQRPrimeQ.INTT(*aQRPrime, *aQCoeff)

		bPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[0].P)
		aPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[1].P)
		ringPRPrime.IMForm(*bPRPrime, *bPRPrime)
		ringPRPrime.IMForm(*aPRPrime, *aPRPrime)
		ringPRPrime.INTT(*bPRPrime, *bPCoeff)
		ringPRPrime.INTT(*aPRPrime, *aPCoeff)

		for m := 0; m <= paramsRPrime.MaxLevel(); m++ {
			for j := 0; j < N; j++ {
				b0.Coeffs[m][j] = bQCoeff.Coeffs[m][2*j]
				a0.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j]
				a1.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j+1]
			}
		}
		for m := 0; m <= paramsRPrime.MaxLevelP(); m++ {
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

	paramsEval := eval.params.Eval

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
