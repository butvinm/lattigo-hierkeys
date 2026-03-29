// LLKN hierarchical rotation keys — per-level ExpandLevel API.
//
// Shows the inactive/active pattern: the server derives keys level by level,
// allowing intermediate results to be serialized and stored between phases.
// This is useful when:
//   - The server pre-computes keys during an offline (inactive) phase
//   - Target rotations are only known later, during the online (active) phase
//
// For the simpler one-shot API, see ../simple.
package main

import (
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// --- CKKS + LLKN parameters (same as simple example) ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
	}); err != nil {
		panic(err)
	}

	// k=3: two extra P levels — enables a 3-tier hierarchy with an intermediate
	// level between eval and master. With k=2 this example would be trivial
	// (only one ExpandLevel call), so we use k=3 to show the cascade.
	var params llkn.Parameters
	if params, err = llkn.NewParameters(ckksParams.Parameters, [][]int{
		{56}, // P for level 1 (intermediate)
		{56}, // P for level 2 (top master)
	}); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topParams := params.Top()
	topLevel := params.NumLevels() - 1
	fmt.Printf("LLKN CKKS (k=%d): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: same key generation as simple example
	// =========================================================================

	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	// With k=3, only {1, base} master rotations are needed at the top level.
	// The full base-4 set is derived at the intermediate level by the server.
	k3Masters := []int{1, 4}
	masterKeys := make(map[int]*hierkeys.MasterKey, len(k3Masters))
	for _, rot := range k3Masters {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}

	tk := &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}
	fmt.Printf("Client: %d master keys, TX = %.1f MB\n",
		len(k3Masters), float64(tk.BinarySize())/(1024*1024))

	// =========================================================================
	// SERVER PHASE 1 (inactive): expand master set at intermediate level
	// =========================================================================
	// PubToRot derives a shift-0 (identity) key at the target level from the
	// client's public key. This is the starting point for RotToRot combinations.
	eval := llkn.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.Levels[1], params.Levels[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}

	// ExpandLevel uses RotToRot to combine shift-0 with master keys, producing
	// the full base-4 rotation set at level 1. These intermediate keys can be
	// serialized and stored for later use.
	var level1Keys *llkn.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): derived %d intermediate keys at level 1\n", len(level1Keys.Keys))

	// =========================================================================
	// SERVER PHASE 2 (active): derive target rotations at eval level
	// =========================================================================
	// Target rotations are now known. Derive them at level 0 using the
	// intermediate keys from phase 1 as the new master set.
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.Levels[0], params.Levels[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}

	var level0Keys *llkn.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server (active): derived %d level-0 keys\n", len(level0Keys.Keys))

	// =========================================================================
	// SERVER PHASE 3: finalize — convert to standard lattigo evaluation keys
	// =========================================================================
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(level0Keys); err != nil {
		panic(err)
	}
	fmt.Printf("Server: finalized %d evaluation keys\n", len(evk.GetGaloisKeysList()))

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
