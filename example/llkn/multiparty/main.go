// Package main demonstrates LLKN hierarchical rotation keys for CKKS in
// an N-out-of-N multiparty setting.
//
// N parties collectively generate transmission keys (EncZero + master rotation
// keys) without any single party knowing the full secret key. The server then
// derives evaluation keys exactly as in the single-party case.
//
// The multiparty protocol uses lattigo's EvaluationKeyGenProtocol to generate
// paper-convention master keys and PublicKeyGenProtocol for EncZero. The ideal
// secret key s = sum(s_i) is computed only for verification.
//
// Parameters are 128-bit secure (HE Standard, LogN=14, eval QP=350 ≤ 438).
package main

import (
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const nParties = 3

func main() {
	var err error

	// 128-bit secure CKKS parameters (same as simple example).
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
	}); err != nil {
		panic(err)
	}

	// LLKN k=2: one level of P primes for the master keys.
	var llknParams llkn.Parameters
	if llknParams, err = llkn.NewParameters(params.Parameters, [][]int{
		{56},
	}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	topParams := llknParams.Top()
	fmt.Printf("LLKN CKKS multiparty (N=%d, k=%d): LogN=%d, %d slots\n",
		nParties, llknParams.NumLevels(), params.LogN(), slots)

	// Common reference string shared by all parties.
	crs, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}

	// --- PARTIES: each generates a secret key at top level ---
	kgen := llkn.NewKeyGenerator(llknParams)
	sks := make([]*rlwe.SecretKey, nParties)
	for i := range sks {
		sks[i] = kgen.GenSecretKeyNew()
	}

	// Compute ideal secret key (sum of all shares) for verification only.
	// In a real deployment, no single entity holds this.
	skIdeal := rlwe.NewSecretKey(topParams)
	for _, sk := range sks {
		topParams.RingQP().Add(skIdeal.Value, sk.Value, skIdeal.Value)
	}

	// --- PHASE 1: Collective public key → EncZero ---
	cpkProto := multiparty.NewPublicKeyGenProtocol(topParams)
	cpkCRP := cpkProto.SampleCRP(crs)
	cpkAgg := cpkProto.AllocateShare()

	for _, sk := range sks {
		share := cpkProto.AllocateShare()
		cpkProto.GenShare(sk, cpkCRP, &share)
		cpkProto.AggregateShares(cpkAgg, share, &cpkAgg)
	}

	collectivePK := rlwe.NewPublicKey(topParams)
	cpkProto.GenPublicKey(cpkAgg, cpkCRP, collectivePK)

	// Encrypt zero using collective public key.
	encZero := rlwe.NewCiphertext(topParams, 1, topParams.MaxLevel())
	encZero.IsNTT = true
	encZero.IsMontgomery = true
	pkEnc := rlwe.NewEncryptor(topParams, collectivePK)
	if err = pkEnc.EncryptZero(encZero); err != nil {
		panic(err)
	}
	fmt.Println("Collective EncZero generated")

	// --- PHASE 2: Collective master rotation keys (paper convention) ---
	//
	// LLKN's RotToRot expects paper convention: EvalKey(skIn=σ_r(s), skOut=s).
	// We use EvaluationKeyGenProtocol directly (not GaloisKeyGenProtocol) so we
	// can pass skIn=σ_r(s_i), skOut=s_i per party.
	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	evkgProto := multiparty.NewEvaluationKeyGenProtocol(topParams)
	masterRotKeys := make(map[int]*rlwe.GaloisKey, len(masterRots))

	ringQ := topParams.RingQ()
	ringP := topParams.RingP()

	for _, rot := range masterRots {
		galEl := topParams.GaloisElement(rot)

		autIdxQ, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galEl)
		if err != nil {
			panic(err)
		}
		autIdxP, err := ring.AutomorphismNTTIndex(ringP.N(), ringP.NthRoot(), galEl)
		if err != nil {
			panic(err)
		}

		crpEvk := evkgProto.SampleCRP(crs)
		accShare := evkgProto.AllocateShare()

		for _, sk := range sks {
			// Paper convention: skIn = σ_r(s_i), skOut = s_i
			skAut := rlwe.NewSecretKey(topParams)
			ringQ.AutomorphismNTTWithIndex(sk.Value.Q, autIdxQ, skAut.Value.Q)
			ringP.AutomorphismNTTWithIndex(sk.Value.P, autIdxP, skAut.Value.P)

			share := evkgProto.AllocateShare()
			if err = evkgProto.GenShare(skAut, sk, crpEvk, &share); err != nil {
				panic(err)
			}
			if err = evkgProto.AggregateShares(accShare, share, &accShare); err != nil {
				panic(err)
			}
		}

		gk := rlwe.NewGaloisKey(topParams)
		if err = evkgProto.GenEvaluationKey(accShare, crpEvk, &gk.EvaluationKey); err != nil {
			panic(err)
		}
		gk.GaloisElement = galEl
		gk.NthRoot = ringQ.NthRoot()

		masterRotKeys[rot] = gk
	}
	fmt.Printf("Collective master keys generated: %d keys for rotations %v\n", len(masterRots), masterRots)

	// --- SERVER: derive evaluation keys (identical to single-party) ---
	tk := &llkn.TransmissionKeys{
		MasterRotKeys: masterRotKeys,
		EncZero:       encZero,
	}
	fmt.Printf("TX size = %d bytes (%.1f MB)\n", tk.BinarySize(), float64(tk.BinarySize())/(1024*1024))

	eval := llkn.NewEvaluator(llknParams)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.DeriveGaloisKeys(tk, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// --- VERIFY: encrypt, rotate, check precision ---
	skEval := kgen.ProjectToEvalKey(skIdeal)
	ecd := ckks.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, skEval)
	dec := rlwe.NewDecryptor(params, skEval)
	ckksEval := ckks.NewEvaluator(params, evk)

	values := make([]complex128, slots)
	for i := range values {
		values[i] = complex(float64(i+1), 0)
	}

	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	var ct *rlwe.Ciphertext
	if ct, err = enc.EncryptNew(pt); err != nil {
		panic(err)
	}

	fmt.Println()
	for _, rot := range targetRots {
		ctRot := ckks.NewCiphertext(params, 1, ct.Level())
		if err = ckksEval.Rotate(ct, rot, ctRot); err != nil {
			panic(err)
		}

		want := make([]complex128, slots)
		for i := range want {
			want[i] = values[(i+rot)%slots]
		}

		printPrecision(params, ctRot, want, rot, ecd, dec)
	}
}

func printPrecision(params ckks.Parameters, ct *rlwe.Ciphertext, want []complex128, rot int, ecd *ckks.Encoder, dec *rlwe.Decryptor) {
	pt := dec.DecryptNew(ct)
	have := make([]complex128, ct.Slots())
	if err := ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	var maxErr float64
	for i := range have {
		if e := cmplx.Abs(have[i] - want[i]); e > maxErr {
			maxErr = e
		}
	}

	fmt.Printf("Rot %3d: [%.0f, %.0f, %.0f, ...] -> [%.1f, %.1f, %.1f, ...]  maxErr: %.2e\n",
		rot,
		real(want[0]), real(want[1]), real(want[2]),
		real(have[0]), real(have[1]), real(have[2]),
		maxErr)
}
