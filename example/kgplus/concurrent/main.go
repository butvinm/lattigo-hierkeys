// KG+ hierarchical rotation keys — concurrent derivation.
//
// Demonstrates concurrent key derivation with ring switching. The evaluator
// is thread-safe — pool-based scratch buffers for both RotToRot and
// RingSwitchGaloisKey operations.
//
// Uses k=3 with per-level expansion:
//   - Phase 1 (sequential): expand {1,4} → full base-4 set at R' level 1
//   - Phase 2 (concurrent): derive target rotations at R' level 0
//   - Phase 3: ring-switch + finalize
package main

import (
	"fmt"
	"math/cmplx"
	"sync"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// --- CKKS + KG+ parameters ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
		LogNthRoot:      16, // q ≡ 1 mod 4N for KG+
	}); err != nil {
		panic(err)
	}

	var params kgplus.Parameters
	if params, err = kgplus.NewParameters(ckksParams.Parameters,
		[]int{55}, // LogPHK for RPrime[1]
		[]int{55, 55, 55, 55, 55, 55, 55}, // LogPExtra for RPrime[2]
	); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	fmt.Printf("KG+ concurrent (k=%d): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: generate keys (same as simple example)
	// =========================================================================

	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)
	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)

	k3Masters := []int{1, 4}
	masterKeys := make(map[int]*hierkeys.MasterKey, len(k3Masters))
	for _, rot := range k3Masters {
		gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}

	tk := &kgplus.TransmissionKeys{
		HomingKey:     homingKey,
		PublicKey:     pk,
		MasterRotKeys: masterKeys,
	}
	fmt.Printf("Client: %d master keys\n", len(k3Masters))

	// =========================================================================
	// SERVER: single evaluator, thread-safe
	// =========================================================================

	eval := kgplus.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	// Phase 1 (sequential): expand at intermediate R' level.
	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level1Keys *hierkeys.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("Phase 1 (sequential): %d intermediate keys in R'\n", len(level1Keys.Keys))

	// Phase 2 (concurrent): derive target rotations at R' level 0.
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}

	exp := eval.NewLevelExpansion(0, shift0L0, level1Keys.Keys)

	var wg sync.WaitGroup
	errs := make([]error, len(targetRots))
	for i, rot := range targetRots {
		wg.Add(1)
		go func(idx, r int) {
			defer wg.Done()
			_, errs[idx] = exp.Derive(r)
		}(i, rot)
	}
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			panic(fmt.Sprintf("derive rotation %d: %v", targetRots[i], e))
		}
	}

	level0Keys := exp.IntermediateKeys(targetRots)
	fmt.Printf("Phase 2 (concurrent): %d level-0 keys in R'\n", len(level0Keys.Keys))

	// Phase 3 (concurrent): ring-switch R' → R and convert each key in parallel.
	// FinalizeKey is thread-safe (pool-based scratch buffers).
	galoisKeys := make([]*rlwe.GaloisKey, len(targetRots))
	finalizeErrs := make([]error, len(targetRots))
	for i, rot := range targetRots {
		wg.Add(1)
		go func(idx, r int) {
			defer wg.Done()
			mk := level0Keys.Keys[r]
			galoisKeys[idx], finalizeErrs[idx] = eval.FinalizeKey(r, mk, tk.HomingKey)
		}(i, rot)
	}
	wg.Wait()

	for i, e := range finalizeErrs {
		if e != nil {
			panic(fmt.Sprintf("finalize rotation %d: %v", targetRots[i], e))
		}
	}

	evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	fmt.Printf("Phase 3 (concurrent): finalized %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// =========================================================================
	// VERIFY
	// =========================================================================

	var skEval *rlwe.SecretKey
	if skEval, err = params.ProjectToEvalKey(sk); err != nil {
		panic(err)
	}
	ecd := ckks.NewEncoder(ckksParams)
	enc := rlwe.NewEncryptor(ckksParams, skEval)
	dec := rlwe.NewDecryptor(ckksParams, skEval)
	ckksEval := ckks.NewEvaluator(ckksParams, evk)

	values := make([]complex128, slots)
	for i := range values {
		values[i] = complex(float64(i+1), 0)
	}

	pt := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	var ct *rlwe.Ciphertext
	if ct, err = enc.EncryptNew(pt); err != nil {
		panic(err)
	}

	fmt.Println()
	for _, rot := range targetRots {
		ctRot := ckks.NewCiphertext(ckksParams, 1, ct.Level())
		if err = ckksEval.Rotate(ct, rot, ctRot); err != nil {
			panic(err)
		}

		want := make([]complex128, slots)
		for i := range want {
			want[i] = values[(i+rot)%slots]
		}

		printPrecision(ckksParams, ctRot, want, rot, ecd, dec)
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
