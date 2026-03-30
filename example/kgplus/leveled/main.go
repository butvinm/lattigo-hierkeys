// KG+ hierarchical rotation keys — per-level ExpandLevel API.
//
// Shows the inactive/active pattern with ring switching:
//   - Phase 1 (inactive): expand {1, base} masters into the full base-4 set
//     at an intermediate R' level. These can be stored for reuse.
//   - Phase 2 (active): derive target rotations at R' level 0 using the
//     intermediate keys.
//   - Phase 3: ring-switch R' keys to R and finalize as standard lattigo keys.
//
// For a simpler k=3 example, see ../simple.
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

	// --- CKKS + KG+ parameters (same as simple example) ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
		LogNthRoot:      16,
	}); err != nil {
		panic(err)
	}

	var params kgplus.Parameters
	if params, err = kgplus.NewParameters(ckksParams.Parameters,
		[]int{56},
		[]int{56},
	); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	fmt.Printf("KG+ CKKS (k=%d): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: same key generation as simple example
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
	fmt.Printf("Client: %d master keys, TX = %.1f MB\n",
		len(k3Masters), float64(tk.BinarySize())/(1024*1024))

	// =========================================================================
	// SERVER PHASE 1 (inactive): expand {1,4} → full base-4 set at level 1
	// =========================================================================
	// PubToRot derives a shift-0 key from the public key. In KG+ this operates
	// in R' (degree 2N) — the extension ring where all intermediate keys live.
	eval := kgplus.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}

	// ExpandLevel combines shift-0 with the 2 master keys to produce the full
	// set of 7+ rotation keys at this level. The intermediate keys can be
	// serialized and stored between phases.
	var level1Keys *hierkeys.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): derived %d intermediate keys in R'\n", len(level1Keys.Keys))

	// =========================================================================
	// SERVER PHASE 2 (active): derive target rotations at R' level 0
	// =========================================================================
	// Now that target rotations are known, derive them using the level-1 keys
	// as the new master set.
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}

	var level0Keys *hierkeys.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server (active): derived %d level-0 keys in R'\n", len(level0Keys.Keys))

	// =========================================================================
	// SERVER PHASE 3: ring-switch R' → R and convert to lattigo convention
	// =========================================================================
	// FinalizeKeys uses the homing key to ring-switch each level-0 key from
	// R' (degree 2N) back to R (degree N), then converts to standard lattigo
	// GaloisKeys usable with ckks.Evaluator.
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk, level0Keys); err != nil {
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
