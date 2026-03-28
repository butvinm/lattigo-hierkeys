// Package main demonstrates KG+ hierarchical rotation keys for CKKS using a
// 3-level hierarchy (k=3) with the per-level ExpandLevel API.
//
// KG+ uses ring switching (extension ring R' of degree 2N) to reduce
// transmission key sizes. Only supports Standard ring type.
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
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// 128-bit secure CKKS parameters.
	// LogN=14: Q_max=438, eval QP = 5×50 + 2×50 = 350.
	// LogNthRoot=16 ensures primes are NTT-friendly for degree 2N (KG+ requirement).
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
		LogNthRoot:      16, // q ≡ 1 mod 4N for KG+
	}); err != nil {
		panic(err)
	}

	// KG+ k=3: two levels of P primes in R' (degree 2N).
	// Top R' QP = 350 + 56 + 56 = 462 ≤ Q_max(2N=2^15) = 881.
	var hkParams kgplus.Parameters
	if hkParams, err = kgplus.NewParameters(params.Parameters,
		[]int{56}, // P for RPrime[1] (also HK P)
		[]int{56}, // P for RPrime[2] (top level)
	); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("KG+ CKKS (k=%d): LogN=%d, %d slots, %d Q primes\n",
		hkParams.NumLevels(), params.LogN(), slots, params.QCount())
	for i, rp := range hkParams.RPrime {
		fmt.Printf("  RPrime[%d]: Q=%d, P=%d primes (degree 2N=%d)\n",
			i, rp.QCount(), rp.PCount(), rp.N())
	}

	// CLIENT: generate keys and assemble transmission keys
	kgenHK := rlwe.NewKeyGenerator(hkParams.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	topLevel := hkParams.NumLevels() - 1
	topParams := hkParams.RPrime[topLevel]
	skExt := kgplus.ConstructExtendedSK(hkParams.HK, topParams, sk, sk1)

	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)

	k3Masters := []int{1, 4}
	masterKeys := make(map[int]*hierkeys.MasterKey)
	for _, rot := range k3Masters {
		gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
		masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			panic(err)
		}
	}

	tk := &kgplus.TransmissionKeys{
		HomingKey:     homingKey,
		PublicKey:     pk,
		MasterRotKeys: masterKeys,
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(k3Masters), k3Masters)
	fmt.Printf("Client: TX size = %d bytes (%.1f MB)\n", tk.BinarySize(), float64(tk.BinarySize())/(1024*1024))

	// SERVER: per-level expansion
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

	// SERVER: use derived keys with standard CKKS evaluator
	var skEval *rlwe.SecretKey
	if skEval, err = hkParams.ProjectToEvalKey(sk); err != nil {
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
