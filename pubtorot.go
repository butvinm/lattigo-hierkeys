package hierkeys

import (
	"fmt"
	"math/big"
	"slices"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
)

// PubToRot derives a shift-0 [MasterKey] (GaloisElement=1) from a public key.
// The server calls this at each hierarchy level to obtain the identity key
// needed by [RotToRot].
//
// Requires paramsPK.QCount() >= paramsTarget.QCount() + paramsTarget.PCount().
func PubToRot(paramsTarget, paramsPK rlwe.Parameters, pk *rlwe.PublicKey) (*MasterKey, error) {

	if pk == nil {
		return nil, fmt.Errorf("public key must not be nil")
	}

	if paramsTarget.LogN() != paramsPK.LogN() {
		return nil, fmt.Errorf("LogN mismatch: paramsTarget=%d, paramsPK=%d",
			paramsTarget.LogN(), paramsPK.LogN())
	}

	if paramsPK.QCount() < paramsTarget.QCount()+paramsTarget.PCount() {
		return nil, fmt.Errorf("paramsPK.QCount()=%d < paramsTarget.QCount()+PCount()=%d",
			paramsPK.QCount(), paramsTarget.QCount()+paramsTarget.PCount())
	}

	// Construction: given pk = (b, a) where b = -a*s + e, set for each gadget component i:
	//   b_i = b' (pk b reduced to Q_target ∪ P_target)
	//   a_i = a' + P*G_i (pk a reduced + gadget constant)
	// Then b_i + a_i*s = e + P*G_i*s — a valid shift-0 evaluation key component.

	levelQLow := paramsTarget.MaxLevel()
	levelPLow := paramsTarget.MaxLevelP()

	ringQLow := paramsTarget.RingQ()
	ringPLow := paramsTarget.RingP()

	// Allocate output shift-0 GaloisKey at paramsTarget
	outputKey := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsTarget, 1, levelQLow, levelPLow, 0),
		},
		GaloisElement: 1, // identity automorphism
		NthRoot:       ringQLow.NthRoot(),
	}

	gc := &outputKey.GadgetCiphertext

	// Index where P_low primes start in Q_high
	pIdx := paramsTarget.QCount()

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
	if err := addGadgetToAPart(paramsTarget, gc); err != nil {
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
