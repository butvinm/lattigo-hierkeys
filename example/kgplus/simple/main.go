// KG+ hierarchical rotation keys — leveled server-side derivation example.
//
// KG+ uses ring switching (extension ring R' of degree 2N) to further reduce
// transmission key sizes compared to LLKN. The trade-off: only supports
// Standard ring type, and primes must satisfy q ≡ 1 mod 4N.
//
// The client generates two independent secrets (sk, sk1), constructs an
// extended secret in R', and sends a homing key for ring switching.
// The server derives evaluation keys using PubToRot + ExpandLevel + FinalizeKeys.
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

	// --- CKKS parameters ---
	// 128-bit secure (FHE Security Guidelines 2024, LogN=14, Q_max=430).
	// LogNthRoot=16 ensures primes are NTT-friendly for degree 2N (KG+ requirement).
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

	// --- KG+ parameters ---
	// 3-level: two extra P levels in R' (degree 2N).
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
	fmt.Printf("KG+ CKKS (%d-level): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: generate keys
	// =========================================================================

	// Two independent secrets at the homing-key (HK) level.
	// sk is the main secret; sk1 is auxiliary, used only for ring switching.
	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()

	// Homing key: EvalKey(sk1 → sk) at HK level. Enables the server to
	// ring-switch derived keys from R' (degree 2N) back to R (degree N).
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	// Extended secret s̃ = sk + Y·sk1 in R' (degree 2N). This is the secret
	// under which master keys and the public key are generated in R'.
	skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)

	// Public key and master rotation keys in R' at the top level.
	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)

	// With 3-level, only {1, middle} masters are needed — the server derives the
	// full base-4 set at the intermediate level.
	k3Masters := []int{1, 64}
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
	// SERVER: per-level derivation via PubToRot + ExpandLevel + FinalizeKeys
	// =========================================================================

	eval := kgplus.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	// Level 1: expand {1,4} masters into the full base-4 set at intermediate level.
	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level1Keys *hierkeys.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}

	// Level 0: derive target rotations from the expanded set.
	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level0Keys *hierkeys.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots); err != nil {
		panic(err)
	}

	// FinalizeKeys ring-switches R' keys to R and converts to lattigo convention.
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk, level0Keys); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

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
