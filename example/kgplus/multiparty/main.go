// Package main demonstrates KG+ hierarchical rotation keys for CKKS in
// an N-out-of-N multiparty setting with a 3-level hierarchy (k=3).
//
// N parties collectively generate transmission keys (HomingKey, PublicKey,
// master rotation keys) without any single party knowing the full secret.
// Each party independently constructs their extended secret s̃_i = s_i + Y·s̃₁_i
// in R' (degree 2N). The ideal extended secret s̃ = sum(s̃_i) is never materialized.
//
// The multiparty protocol uses:
//   - PublicKeyGenProtocol at top RPrime level for the collective public key
//   - GaloisKeyGenProtocol at top RPrime level for master rotation keys
//   - EvaluationKeyGenProtocol at HK level for the homing key (s̃₁ → s)
//
// Parameters are 128-bit secure (HE Standard, LogN=14, eval QP=350 ≤ 438,
// KG+ top R' QP=462 ≤ Q_max(2N)=881).
package main

import (
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const nParties = 3

func main() {
	var err error

	// 128-bit secure CKKS parameters (same as simple example).
	// LogNthRoot=16 ensures primes are NTT-friendly for degree 2N.
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
		LogNthRoot:      16,
	}); err != nil {
		panic(err)
	}

	// KG+ k=3: two levels of P primes in R' (degree 2N).
	var hkParams kgplus.Parameters
	if hkParams, err = kgplus.NewParameters(params.Parameters,
		[]int{56}, // P for RPrime[1] (also HK P)
		[]int{56}, // P for RPrime[2] (top level)
	); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	topLevel := hkParams.NumLevels() - 1
	topParams := hkParams.RPrime[topLevel]
	fmt.Printf("KG+ CKKS multiparty (N=%d, k=%d): LogN=%d, %d slots\n",
		nParties, hkParams.NumLevels(), params.LogN(), slots)

	// CRS shared by all parties.
	crs, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}

	// --- PARTIES: each generates s_i and s̃₁_i, constructs s̃_i in R' ---
	kgenHK := rlwe.NewKeyGenerator(hkParams.HK)

	// Secret keys at HK level (degree N)
	sks := make([]*rlwe.SecretKey, nParties)    // s_i
	skS1s := make([]*rlwe.SecretKey, nParties)  // s̃₁_i
	skExts := make([]*rlwe.SecretKey, nParties) // s̃_i in R' at top level

	for i := range sks {
		sks[i] = kgenHK.GenSecretKeyNew()
		skS1s[i] = kgenHK.GenSecretKeyNew()
		skExts[i] = kgplus.ConstructExtendedSK(hkParams.HK, topParams, sks[i], skS1s[i])
	}

	// Ideal secret keys for verification only.
	skIdealHK := rlwe.NewSecretKey(hkParams.HK)
	for _, sk := range sks {
		hkParams.HK.RingQP().Add(skIdealHK.Value, sk.Value, skIdealHK.Value)
	}

	// --- PHASE 1: Collective homing key (s̃₁ → s at HK level) ---
	hkProto := multiparty.NewEvaluationKeyGenProtocol(hkParams.HK)
	hkCRP := hkProto.SampleCRP(crs)
	hkAcc := hkProto.AllocateShare()

	for i := range sks {
		share := hkProto.AllocateShare()
		// HomingKey = EvalKey(skIn=s̃₁, skOut=s): each party contributes (s̃₁_i, s_i)
		if err = hkProto.GenShare(skS1s[i], sks[i], hkCRP, &share); err != nil {
			panic(err)
		}
		if err = hkProto.AggregateShares(hkAcc, share, &hkAcc); err != nil {
			panic(err)
		}
	}

	homingKey := rlwe.NewEvaluationKey(hkParams.HK)
	if err = hkProto.GenEvaluationKey(hkAcc, hkCRP, homingKey); err != nil {
		panic(err)
	}
	fmt.Println("Collective homing key generated")

	// --- PHASE 2: Collective public key in R' at top level ---
	cpkProto := multiparty.NewPublicKeyGenProtocol(topParams)
	cpkCRP := cpkProto.SampleCRP(crs)
	cpkAgg := cpkProto.AllocateShare()

	for _, ske := range skExts {
		share := cpkProto.AllocateShare()
		cpkProto.GenShare(ske, cpkCRP, &share)
		cpkProto.AggregateShares(cpkAgg, share, &cpkAgg)
	}

	collectivePK := rlwe.NewPublicKey(topParams)
	cpkProto.GenPublicKey(cpkAgg, cpkCRP, collectivePK)
	fmt.Println("Collective public key generated")

	// --- PHASE 3: Collective master rotation keys in R' via GaloisKeyGenProtocol ---
	k3Masters := []int{1, 4}
	gkg := multiparty.NewGaloisKeyGenProtocol(topParams)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(k3Masters))

	for _, rot := range k3Masters {
		galEl := topParams.GaloisElement(rot)
		crp := gkg.SampleCRP(crs)
		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl

		for _, ske := range skExts {
			share := gkg.AllocateShare()
			if err = gkg.GenShare(ske, galEl, crp, &share); err != nil {
				panic(err)
			}
			if err = gkg.AggregateShares(acc, share, &acc); err != nil {
				panic(err)
			}
		}

		gk := rlwe.NewGaloisKey(topParams)
		gkg.GenGaloisKey(acc, crp, gk)
		masterKeys[rot], err = hierkeys.NewMasterKeyFromGaloisKey(topParams, gk)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("Collective master keys generated: %d keys for rotations %v\n", len(k3Masters), k3Masters)

	// --- SERVER: per-level expansion (identical to single-party) ---
	tk := &kgplus.TransmissionKeys{
		HomingKey:     homingKey,
		PublicKey:     collectivePK,
		MasterRotKeys: masterKeys,
	}
	fmt.Printf("TX size = %d bytes (%.1f MB)\n", tk.BinarySize(), float64(tk.BinarySize())/(1024*1024))

	eval := kgplus.NewEvaluator(hkParams)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	// Phase 1 (inactive): derive full master rotation set at intermediate level
	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(hkParams.RPrime[1], hkParams.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level1Keys *kgplus.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): derived %d intermediate keys in R'\n", len(level1Keys.Keys))

	// Phase 2 (active): derive target rotation keys at level 0
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(hkParams.RPrime[0], hkParams.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level0Keys *kgplus.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server (active): derived %d level-0 keys in R'\n", len(level0Keys.Keys))

	// Phase 3: ring-switch R' keys to eval ring and convert to lattigo convention
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk, level0Keys); err != nil {
		panic(err)
	}
	fmt.Printf("Server: finalized %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// --- VERIFY: encrypt, rotate, check precision ---
	var skEval *rlwe.SecretKey
	if skEval, err = hkParams.ProjectToEvalKey(skIdealHK); err != nil {
		panic(err)
	}
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
