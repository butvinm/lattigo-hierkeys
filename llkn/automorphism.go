package llkn

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// PaperConventionEvaluator wraps rlwe.Evaluator to apply automorphisms
// using paper convention GaloisKeys (automorph-then-keyswitch).
//
// This is needed because LLKN produces paper convention keys via RotToRot
// (which is the convention used in the Lee-Lee-Kim-No paper), while lattigo's
// standard evaluator expects lattigo convention (keyswitch-then-automorph).
//
// For use with ckks.Evaluator.Rotate, use [WrapCKKSEvaluator] instead.
type PaperConventionEvaluator struct {
	params rlwe.Parameters
	evk    *rlwe.MemEvaluationKeySet
	eval   *rlwe.Evaluator
}

// NewPaperConventionEvaluator creates an evaluator that applies automorphisms
// using paper convention GaloisKeys.
func NewPaperConventionEvaluator(params rlwe.Parameters, evk *rlwe.MemEvaluationKeySet) *PaperConventionEvaluator {
	return &PaperConventionEvaluator{
		params: params,
		evk:    evk,
		eval:   rlwe.NewEvaluator(params, evk),
	}
}

// Automorphism computes phi(ct), where phi is the map X -> X^galEl,
// using paper convention: first apply automorphism, then key-switch.
func (eval *PaperConventionEvaluator) Automorphism(ctIn *rlwe.Ciphertext, galEl uint64, opOut *rlwe.Ciphertext) (err error) {

	if ctIn.Degree() != 1 || opOut.Degree() != 1 {
		return fmt.Errorf("input and output Ciphertext must be of degree 1")
	}

	if galEl == 1 {
		if opOut != ctIn {
			opOut.Copy(ctIn)
		}
		return
	}

	gk, err := eval.eval.CheckAndGetGaloisKey(galEl)
	if err != nil {
		return fmt.Errorf("cannot apply Automorphism: %w", err)
	}

	level := ctIn.Level()
	if opOut.Level() < level {
		level = opOut.Level()
	}
	opOut.Resize(opOut.Degree(), level)

	ringQ := eval.params.RingQ().AtLevel(level)

	// Paper convention: first automorphism, then key-switch
	// 1. Apply automorphism σ_g to the ciphertext
	autIdx, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galEl)
	if err != nil {
		return err
	}

	// Automorph b and a
	bAut := ringQ.NewPoly()
	aAut := ringQ.NewPoly()
	ringQ.AutomorphismNTTWithIndex(ctIn.Value[0], autIdx, bAut)
	ringQ.AutomorphismNTTWithIndex(ctIn.Value[1], autIdx, aAut)

	// 2. Key-switch the automorphed a component using the paper convention GaloisKey
	// GadgetProduct(σ_g(a), gk) gives Enc_s(σ_g(a) · σ_g(s))
	// Adding σ_g(b) gives: σ_g(b) + σ_g(a)·σ_g(s) + noise = σ_g(b + a·s) = σ_g(m)
	ctTmp := rlwe.NewCiphertext(eval.params, 1, level)
	ctTmp.IsNTT = ctIn.IsNTT
	eval.eval.GadgetProduct(level, aAut, &gk.GadgetCiphertext, ctTmp)

	// 3. Add automorphed b component
	ringQ.Add(ctTmp.Value[0], bAut, opOut.Value[0])
	copy(opOut.Value[1].Coeffs[0], ctTmp.Value[1].Coeffs[0])
	for m := 1; m <= level; m++ {
		copy(opOut.Value[1].Coeffs[m], ctTmp.Value[1].Coeffs[m])
	}

	*opOut.MetaData = *ctIn.MetaData

	return nil
}
