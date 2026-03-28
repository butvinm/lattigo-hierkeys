package hierkeys

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// PubToRot generates a shift-0 MasterKey (identity automorphism, GaloisElement=1)
// from a public key at a higher parameter level.
//
// This implements the PubToRot concept from the LLKN paper (Lee-Lee-Kim-No,
// "Rotation Key Reduction for Client-Server Systems"). Instead of the client
// transmitting full shift-0 GaloisKeys, it sends a compact public key at the
// top level, and the server derives shift-0 keys at each lower level.
//
// The construction works as follows. Given a public key (b, a) where
// b = -a*s + e, we build a GadgetCiphertext at paramsLow by setting for each
// gadget component i:
//
//	b_i = b' (public key b reduced to Q_low union P_low moduli)
//	a_i = a' + P * G_i (public key a reduced, plus gadget constant)
//
// Then b_i = -(a' + P*G_i)*s + (a'+P*G_i)*s + b' = -a_i*s + e + P*G_i*s,
// which is a valid encryption of P*G_i*s under s -- exactly the form of a
// shift-0 evaluation key.
//
// PARAMETER REQUIREMENTS:
//   - pk must be a public key generated at paramsHigh (in NTT+Montgomery form)
//   - paramsHigh.QCount() >= paramsLow.QCount() + paramsLow.PCount()
//     (the high-level Q ring must contain all Q and P primes of the low level)
//   - paramsLow.LogN() == paramsHigh.LogN()
func PubToRot(paramsLow, paramsHigh rlwe.Parameters, pk *rlwe.PublicKey) (*MasterKey, error) {

	if pk == nil {
		return nil, fmt.Errorf("public key must not be nil")
	}

	if paramsLow.LogN() != paramsHigh.LogN() {
		return nil, fmt.Errorf("LogN mismatch: paramsLow=%d, paramsHigh=%d",
			paramsLow.LogN(), paramsHigh.LogN())
	}

	if paramsHigh.QCount() < paramsLow.QCount()+paramsLow.PCount() {
		return nil, fmt.Errorf("paramsHigh.QCount()=%d < paramsLow.QCount()+PCount()=%d",
			paramsHigh.QCount(), paramsLow.QCount()+paramsLow.PCount())
	}

	levelQLow := paramsLow.MaxLevel()
	levelPLow := paramsLow.MaxLevelP()

	ringQLow := paramsLow.RingQ()
	ringPLow := paramsLow.RingP()

	// Allocate output shift-0 GaloisKey at paramsLow
	outputKey := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsLow, 1, levelQLow, levelPLow, 0),
		},
		GaloisElement: 1, // identity automorphism
		NthRoot:       ringQLow.NthRoot(),
	}

	gc := &outputKey.GadgetCiphertext

	// Index where P_low primes start in Q_high
	pIdx := paramsLow.QCount()

	// Copy the public key into every gadget component.
	// PublicKey values are in NTT+Montgomery form.
	// pk.Value[0].Q = b part, pk.Value[1].Q = a part (Q-ring coefficients).
	// Q_low primes correspond to indices [0, levelQLow] in Q_high.
	// P_low primes correspond to indices [pIdx, pIdx+levelPLow] in Q_high.
	for i := range gc.Value {
		for j := range gc.Value[i] {
			component := gc.Value[i][j]

			// Copy b' (pk.Value[0].Q) into component[0]
			for m := 0; m <= levelQLow; m++ {
				copy(component[0].Q.Coeffs[m], pk.Value[0].Q.Coeffs[m])
			}
			if ringPLow != nil {
				for m := 0; m <= levelPLow; m++ {
					copy(component[0].P.Coeffs[m], pk.Value[0].Q.Coeffs[pIdx+m])
				}
			}

			// Copy a' (pk.Value[1].Q) into component[1]
			for m := 0; m <= levelQLow; m++ {
				copy(component[1].Q.Coeffs[m], pk.Value[1].Q.Coeffs[m])
			}
			if ringPLow != nil {
				for m := 0; m <= levelPLow; m++ {
					copy(component[1].P.Coeffs[m], pk.Value[1].Q.Coeffs[pIdx+m])
				}
			}
		}
	}

	// Add the gadget constants P * G_i to the 'a' part (component[1]).
	if err := addGadgetToAPart(paramsLow, gc); err != nil {
		return nil, fmt.Errorf("addGadgetToAPart: %w", err)
	}

	return &MasterKey{gk: outputKey}, nil
}

// addGadgetToAPart adds P * G_i to the Q-part of the 'a' component
// (component[1]) of each gadget slot.
//
// This mirrors AddPolyTimesGadgetVectorToGadgetCiphertext but:
//   - Operates on the 'a' part (index 1) instead of 'b' (index 0)
//   - Uses the identity polynomial (constant 1) as the plaintext
//
// The values in the GadgetCiphertext are in NTT+Montgomery form.
func addGadgetToAPart(params rlwe.Parameters, gc *rlwe.GadgetCiphertext) error {

	levelQ := gc.LevelQ()
	levelP := gc.LevelP()

	ringQ := params.RingQ().AtLevel(levelQ)
	ringP := params.RingP()

	N := ringQ.N()

	// Number of P primes (determines RNS decomposition grouping)
	nP := levelP + 1
	if levelP == -1 {
		nP = 1
	}

	var pBig *big.Int
	if levelP >= 0 {
		pBig = ringP.AtLevel(levelP).Modulus()
	} else {
		pBig = big.NewInt(1)
	}

	// Precompute P mod Q_k in Montgomery form for each Q prime
	pMontPerQ := make([]uint64, levelQ+1)
	for k := 0; k <= levelQ; k++ {
		s := ringQ.SubRings[k]
		pModQk := new(big.Int).Mod(pBig, bignum.NewInt(s.Modulus))
		pMontPerQ[k] = ring.MForm(pModQk.Uint64(), s.Modulus, s.BRedConstant)
	}

	buff := make([]uint64, levelQ+1)
	copy(buff, pMontPerQ)

	BaseRNSDecompositionVectorSize := len(gc.Value)
	BaseTwoDecompositionVectorSize := make([]int, BaseRNSDecompositionVectorSize)
	for i := range BaseTwoDecompositionVectorSize {
		BaseTwoDecompositionVectorSize[i] = len(gc.Value[i])
	}

	for j := 0; j < slices.Max(BaseTwoDecompositionVectorSize); j++ {

		for i := 0; i < BaseRNSDecompositionVectorSize; i++ {

			if j < BaseTwoDecompositionVectorSize[i] {

				for k := 0; k < nP; k++ {
					index := i*nP + k

					if index > levelQ {
						break
					}

					qi := ringQ.SubRings[index].Modulus
					pVal := buff[index]
					aBuf := gc.Value[i][j][1].Q.Coeffs[index]

					for n := 0; n < N; n++ {
						aBuf[n] = ring.CRed(aBuf[n]+pVal, qi)
					}
				}
			}
		}

		if gc.BaseTwoDecomposition > 0 {
			w := uint64(1 << gc.BaseTwoDecomposition)
			for k := 0; k <= levelQ; k++ {
				s := ringQ.SubRings[k]
				buff[k] = ring.BRed(buff[k], w, s.Modulus, s.BRedConstant)
			}
		}
	}

	return nil
}
