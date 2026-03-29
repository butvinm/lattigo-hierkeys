// KG+ hierarchical rotation keys — one-shot DeriveGaloisKeys API.
//
// KG+ uses ring switching (extension ring R' of degree 2N) to further reduce
// transmission key sizes compared to LLKN. The trade-off: only supports
// Standard ring type, and primes must satisfy q ≡ 1 mod 4N.
//
// The client generates two independent secrets (sk, sk1), constructs an
// extended secret in R', and sends a homing key for ring switching.
// The server derives evaluation keys in one call.
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
	// 128-bit secure (HE Standard, LogN=14, Q_max=438).
	// LogNthRoot=16 ensures primes are NTT-friendly for degree 2N (KG+ requirement).
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
		LogNthRoot:      16, // q ≡ 1 mod 4N for KG+
	}); err != nil {
		panic(err)
	}

	// --- KG+ parameters ---
	// k=3: two extra P levels in R' (degree 2N).
	// Top R' QP = 350 + 56 + 56 = 462 ≤ Q_max(2N=2^15) = 881.
	var params kgplus.Parameters
	if params, err = kgplus.NewParameters(ckksParams.Parameters,
		[]int{56}, // P for RPrime[1] (also homing key P)
		[]int{56}, // P for RPrime[2] (top level)
	); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	fmt.Printf("KG+ CKKS (k=%d): LogN=%d, %d slots\n",
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

	// With k=3, only {1, base} masters are needed — the server derives the
	// full base-4 set at the intermediate level.
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
	// SERVER: one-shot derivation
	// =========================================================================

	eval := kgplus.NewEvaluator(params)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	// DeriveGaloisKeys handles all levels internally:
	// PubToRot → ExpandLevel (per level) → FinalizeKeys (ring-switch + convert).
	// For per-level control, see ../leveled.
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.DeriveGaloisKeys(tk, targetRots); err != nil {
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
