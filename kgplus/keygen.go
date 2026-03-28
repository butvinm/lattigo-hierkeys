package kgplus

import (
	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// TransmissionKeys holds everything the client sends to the server.
// This is the only data that crosses the client-server boundary.
type TransmissionKeys struct {
	// HomingKey switches from s̃₁ to s in R (at HK parameter level).
	HomingKey *rlwe.EvaluationKey

	// PublicKey in R' at the top RPrime level, for PubToRot.
	PublicKey *rlwe.PublicKey

	// MasterRotKeys are rotation keys in R' at the top RPrime level in paper
	// convention. Indexed by rotation index (not Galois element).
	MasterRotKeys map[int]*hierkeys.MasterKey
}

// ConstructExtendedSK builds the extended secret key s̃ = s + Y·s̃₁ in the
// extension ring R' (degree 2N) from two secret keys at the homing-key level.
//
// paramsHK: the homing-key parameters (Q = Q_eval ∪ P_eval, P = P_hk)
// paramsRP: the target R' parameters (degree 2N)
// skS, skS1: secret keys at paramsHK level
//
// For k>2, paramsRP.Q may include primes beyond paramsHK.Q (e.g., the HK P primes).
// In that case, the additional coefficient slots are filled from skS.P and skS1.P.
func ConstructExtendedSK(paramsHK, paramsRP rlwe.Parameters, skS, skS1 *rlwe.SecretKey) *rlwe.SecretKey {
	N := paramsHK.N()
	ringQHK := paramsHK.RingQ()
	ringPHK := paramsHK.RingP()
	ringQRP := paramsRP.RingQ()

	skTilde := rlwe.NewSecretKey(paramsRP)

	// Convert s and s̃₁ Q-part from NTT+Montgomery to coefficient domain.
	sCoeffsQ := ringQHK.NewPoly()
	s1CoeffsQ := ringQHK.NewPoly()
	ringQHK.IMForm(skS.Value.Q, sCoeffsQ)
	ringQHK.INTT(sCoeffsQ, sCoeffsQ)
	ringQHK.IMForm(skS1.Value.Q, s1CoeffsQ)
	ringQHK.INTT(s1CoeffsQ, s1CoeffsQ)

	// Interleave into R' (degree 2N): even = s, odd = s̃₁
	sTildeCoeffs := ringQRP.NewPoly()

	// Fill from HK Q primes
	nQFromQ := paramsRP.QCount()
	if nQFromQ > paramsHK.QCount() {
		nQFromQ = paramsHK.QCount()
	}
	for m := 0; m < nQFromQ; m++ {
		for j := 0; j < N; j++ {
			sTildeCoeffs.Coeffs[m][2*j] = sCoeffsQ.Coeffs[m][j]
			sTildeCoeffs.Coeffs[m][2*j+1] = s1CoeffsQ.Coeffs[m][j]
		}
	}

	// Fill additional Q primes from HK P primes (for k>2 where RPrime.Q > HK.Q)
	if paramsRP.QCount() > paramsHK.QCount() && ringPHK != nil {
		sCoeffsP := ringPHK.NewPoly()
		s1CoeffsP := ringPHK.NewPoly()
		ringPHK.IMForm(skS.Value.P, sCoeffsP)
		ringPHK.INTT(sCoeffsP, sCoeffsP)
		ringPHK.IMForm(skS1.Value.P, s1CoeffsP)
		ringPHK.INTT(s1CoeffsP, s1CoeffsP)

		nExtra := paramsRP.QCount() - paramsHK.QCount()
		if nExtra > paramsHK.PCount() {
			nExtra = paramsHK.PCount()
		}
		for m := 0; m < nExtra; m++ {
			rpIdx := paramsHK.QCount() + m
			for j := 0; j < N; j++ {
				sTildeCoeffs.Coeffs[rpIdx][2*j] = sCoeffsP.Coeffs[m][j]
				sTildeCoeffs.Coeffs[rpIdx][2*j+1] = s1CoeffsP.Coeffs[m][j]
			}
		}
	}

	ringQRP.NTT(sTildeCoeffs, skTilde.Value.Q)
	ringQRP.MForm(skTilde.Value.Q, skTilde.Value.Q)

	// Extend to P basis
	if paramsRP.PCount() > 0 {
		ringQP := paramsRP.RingQP().AtLevel(skTilde.LevelQ(), skTilde.LevelP())
		ringQP.ExtendBasisSmallNormAndCenter(sTildeCoeffs, skTilde.LevelP(), sTildeCoeffs, skTilde.Value.P)
		paramsRP.RingP().NTT(skTilde.Value.P, skTilde.Value.P)
		paramsRP.RingP().MForm(skTilde.Value.P, skTilde.Value.P)
	}

	return skTilde
}
