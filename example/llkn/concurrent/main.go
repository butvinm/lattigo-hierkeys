// LLKN hierarchical rotation keys — concurrent derivation.
//
// Demonstrates concurrent key derivation using LevelExpansion.Derive from
// goroutines. The evaluator is thread-safe — a single instance handles all
// concurrent calls via pool-based scratch buffers (no ConcurrentCopy needed).
//
// The concurrency model is the same as lattigo v6.2: one evaluator, multiple
// goroutines, each goroutine allocates its own output.
//
// Uses 3-level to show two-phase expansion: intermediate level first (sequential),
// then target rotations at level 0 (concurrent).
package main

import (
	"fmt"
	"math/cmplx"
	"sync"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// --- CKKS + LLKN parameters ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
	}); err != nil {
		panic(err)
	}

	// 3-level to demonstrate two-phase expansion.
	var params llkn.Parameters
	if params, err = llkn.NewParameters(ckksParams.Parameters, [][]int{
		{55}, // P for level 1
		{55}, // P for level 2 (top)
	}); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topParams := params.Top()
	topLevel := params.NumLevels() - 1
	fmt.Printf("LLKN concurrent (%d-level): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: generate keys (same as simple example)
	// =========================================================================

	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	k3Masters := []int{1, 4}
	masterKeys := make(map[int]*hierkeys.MasterKey, len(k3Masters))
	for _, rot := range k3Masters {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}

	tk := &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}
	fmt.Printf("Client: %d master keys\n", len(k3Masters))

	// =========================================================================
	// SERVER: single evaluator, thread-safe
	// =========================================================================

	eval := llkn.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	// Phase 1 (sequential): expand {1,4} → full base-4 set at level 1.
	// This is typically done once during an offline phase.
	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.Levels[1], params.Levels[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level1Keys *hierkeys.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("Phase 1 (sequential): %d intermediate keys at level 1\n", len(level1Keys.Keys))

	// Phase 2 (concurrent): derive target rotations at level 0.
	// Create a LevelExpansion session and call Derive from goroutines.
	// Each rotation is computed at most once — concurrent requests for the
	// same rotation (as target or dependency) coordinate automatically.
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.Levels[0], params.Levels[topLevel], tk.PublicKey); err != nil {
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
	fmt.Printf("Phase 2 (concurrent): %d level-0 keys from %d goroutines\n",
		len(level0Keys.Keys), len(targetRots))

	// Phase 3 (concurrent): finalize — convert each key in parallel.
	// FinalizeKey is thread-safe.
	galoisKeys := make([]*rlwe.GaloisKey, len(targetRots))
	finalizeErrs := make([]error, len(targetRots))
	for i, rot := range targetRots {
		wg.Add(1)
		go func(idx, r int) {
			defer wg.Done()
			mk := level0Keys.Keys[r]
			galoisKeys[idx], finalizeErrs[idx] = eval.FinalizeKey(mk)
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
