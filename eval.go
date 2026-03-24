// Package hierkeys implements hierarchical rotation key generation via ring
// switching, based on "Towards Lightweight CKKS: On Client Cost Efficiency"
// (Cheon, Kang, Park) and "Rotation Key Reduction for Client-Server Systems"
// (Lee, Lee, Kim, No).
package hierkeys

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// RingSwitchGaloisKey is a convenience wrapper that creates a temporary
// Evaluator internally. For repeated calls, use [Evaluator.RingSwitchGaloisKey].
//
// Note: allocates a full Evaluator with buffers for all parameter sets.
// The RPrimeMaster placeholder means some buffers are over-sized but unused.
func RingSwitchGaloisKey(
	paramsEval rlwe.Parameters,
	paramsHK rlwe.Parameters,
	paramsRPrime rlwe.Parameters,
	masterKeyRPrime *rlwe.GaloisKey,
	homingKey *rlwe.EvaluationKey,
	galoisElement uint64,
) (*rlwe.GaloisKey, error) {
	params := Parameters{
		Eval:         paramsEval,
		HK:           paramsHK,
		RPrime:       paramsRPrime,
		RPrimeMaster: paramsHK, // placeholder — RotToRot buffers unused by RingSwitchGaloisKey
	}
	eval := NewEvaluator(params)
	return eval.RingSwitchGaloisKey(masterKeyRPrime, homingKey, galoisElement)
}

// RingSwitchGaloisKey ring-switches a GaloisKey from R' (degree 2N) to a
// standard GaloisKey in R (degree N) using a homing key.
//
// PARAMETER REQUIREMENTS:
//   - params.Eval: Q = Q_eval, P = P_eval (evaluation parameters)
//   - params.HK: Q = Q_eval ∪ P_eval, P = P_hk (homing key parameters)
//   - params.RPrime: Q = Q_eval, P = P_eval, degree 2N (extension ring)
//   - params.HK.QCount() must equal params.Eval.QCount() + params.Eval.PCount()
//   - params.RPrime.N() must equal 2 * params.Eval.N()
//
// The master key must use the paper's convention:
//
//	genEvaluationKey(skIn=pi(s_tilde), skOut=s_tilde)
//
// The returned key is in the paper's convention (automorph-then-key-switch).
// Use [Evaluator.DeriveGaloisKeys] which post-converts to lattigo's standard
// convention for transparent compatibility with [rlwe.Evaluator.Automorphism].
func (eval *Evaluator) RingSwitchGaloisKey(
	masterKeyRPrime *rlwe.GaloisKey,
	homingKey *rlwe.EvaluationKey,
	galoisElement uint64,
) (*rlwe.GaloisKey, error) {

	paramsEval := eval.params.Eval
	paramsHK := eval.params.HK
	paramsRPrime := eval.params.RPrime

	// Input validation
	if paramsRPrime.N() != 2*paramsEval.N() {
		return nil, fmt.Errorf("paramsRPrime.N()=%d must be 2*paramsEval.N()=%d", paramsRPrime.N(), 2*paramsEval.N())
	}
	if paramsHK.N() != paramsEval.N() {
		return nil, fmt.Errorf("paramsHK.N()=%d must equal paramsEval.N()=%d", paramsHK.N(), paramsEval.N())
	}
	if paramsHK.QCount() != paramsEval.QCount()+paramsEval.PCount() {
		return nil, fmt.Errorf("paramsHK.QCount()=%d must equal paramsEval.QCount()+PCount()=%d",
			paramsHK.QCount(), paramsEval.QCount()+paramsEval.PCount())
	}
	if masterKeyRPrime == nil || homingKey == nil {
		return nil, fmt.Errorf("masterKeyRPrime and homingKey must not be nil")
	}

	N := paramsEval.N()
	ringQHK := paramsHK.RingQ()

	levelQHK := paramsHK.MaxLevel()
	levelQEval := paramsEval.MaxLevel()
	levelPEval := paramsEval.MaxLevelP()

	gc := &masterKeyRPrime.GadgetCiphertext
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

	// Use pre-allocated buffers
	ringQRPrimeQ := paramsRPrime.RingQ()
	ringPRPrime := paramsRPrime.RingP()
	ringQEval := paramsEval.RingQ()
	ringPEval := paramsEval.RingP()

	bQRPrime := eval.bQRPrime
	aQRPrime := eval.aQRPrime
	bQCoeff := eval.bQCoeff
	aQCoeff := eval.aQCoeff
	bPRPrime := eval.bPRPrime
	aPRPrime := eval.aPRPrime
	bPCoeff := eval.bPCoeff
	aPCoeff := eval.aPCoeff
	b0 := eval.b0RS
	a0 := eval.a0RS
	a1 := eval.a1RS
	Xa1 := eval.Xa1RS
	rsB := eval.rsBRS
	rsA := eval.rsARS
	ctKS := eval.ctKSRS

	pIdx := levelQEval + 1 // start index of P_eval primes in Q_hk

	for i := 0; i < nEvalRNS; i++ {
		component := gc.Value[i][0]

		// --- Extract even/odd from Q and P parts of R' component ---
		bQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[0].Q)
		aQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[1].Q)
		ringQRPrimeQ.IMForm(bQRPrime, bQRPrime)
		ringQRPrimeQ.IMForm(aQRPrime, aQRPrime)
		ringQRPrimeQ.INTT(bQRPrime, bQCoeff)
		ringQRPrimeQ.INTT(aQRPrime, aQCoeff)

		// P parts
		bPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[0].P)
		aPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[1].P)
		ringPRPrime.IMForm(bPRPrime, bPRPrime)
		ringPRPrime.IMForm(aPRPrime, aPRPrime)
		ringPRPrime.INTT(bPRPrime, bPCoeff)
		ringPRPrime.INTT(aPRPrime, aPCoeff)

		// Even/odd extraction into Q_hk-level polynomials
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

		// Multiply a1 by X: X*f(X) mod (X^N+1)
		for m := range a1.Coeffs {
			qi := ringQHK.SubRings[m].Modulus
			Xa1.Coeffs[m][0] = qi - a1.Coeffs[m][N-1]
			for k := 1; k < N; k++ {
				Xa1.Coeffs[m][k] = a1.Coeffs[m][k-1]
			}
		}

		ringQHK.NTT(b0, b0)
		ringQHK.NTT(a0, a0)
		ringQHK.NTT(Xa1, Xa1)

		// --- Key-switch X*a1 with homing key ---
		eval.evalHK.GadgetProduct(levelQHK, Xa1, &homingKey.GadgetCiphertext, ctKS)

		// Ring-switched ciphertext at Q_hk level
		ringQHK.Add(b0, ctKS.Value[0], rsB)
		ringQHK.Add(a0, ctKS.Value[1], rsA)

		// --- Split Q_hk into Q_eval and P_eval parts ---
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
