// LLKN hierarchical rotation keys — minimal server-side derivation example.
//
// Shows the simplest usage: client generates master keys and a public key,
// server derives all target rotation keys using PubToRot + ExpandLevel + FinalizeKeys.
//
// LLKN operates entirely in the evaluation ring (no ring switching),
// making it simpler than KG+ and compatible with any ring type.
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

	// --- CKKS parameters ---
	// 128-bit secure (HE Standard, LogN=14, Q_max=438).
	// Eval QP = 5×50 + 2×50 = 350 ≤ 438.
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
	}); err != nil {
		panic(err)
	}

	// --- LLKN parameters ---
	// k=2: one extra level of P primes for master keys.
	// Master level: Q = Q_eval ∪ P_eval (7 primes), P = {56-bit} (1 prime).
	// Total master QP = 350 + 56 = 406 ≤ 438.
	var params llkn.Parameters
	if params, err = llkn.NewParameters(ckksParams.Parameters, [][]int{
		{56}, // P for master level (one 56-bit prime)
	}); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topParams := params.Top()
	fmt.Printf("LLKN CKKS (k=%d): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// CLIENT: generate keys with standard lattigo, convert to hierkeys types
	// =========================================================================

	kgen := rlwe.NewKeyGenerator(topParams)

	// Secret key at the top (master) level — has more Q primes than eval level.
	// Use params.ProjectToEvalKey(sk) to get the eval-level key for encryption.
	sk := kgen.GenSecretKeyNew()

	// Public key at the top level — used by server's PubToRot to derive
	// shift-0 (identity) keys at each hierarchy level.
	pk := kgen.GenPublicKeyNew(sk)

	// Master rotation keys: a small set of GaloisKeys covering base-4 powers
	// {1, 4, 16, 64, ...}. Any target rotation can be decomposed as a sum of
	// these masters and derived server-side via RotToRot.
	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		// Generate a standard lattigo GaloisKey, then convert to MasterKey.
		// GaloisKeyToMasterKey applies a convention transformation needed by
		// the RotToRot algorithm — the user doesn't need to know the details.
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}

	// Bundle and send to server.
	tk := &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}
	fmt.Printf("Client: %d master keys, TX = %.1f MB\n",
		len(masterRots), float64(tk.BinarySize())/(1024*1024))

	// =========================================================================
	// SERVER: derive target rotation keys via PubToRot + ExpandLevel + FinalizeKeys
	// =========================================================================

	eval := llkn.NewEvaluator(params)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	// PubToRot derives a shift-0 (identity) key from the public key.
	// ExpandLevel combines it with master keys to produce all target rotations.
	// FinalizeKeys converts to standard lattigo GaloisKeys.
	var shift0 *hierkeys.MasterKey
	if shift0, err = hierkeys.PubToRot(params.Levels[0], params.Top(), tk.PublicKey); err != nil {
		panic(err)
	}
	var level0 *hierkeys.IntermediateKeys
	if level0, err = eval.ExpandLevel(0, shift0, tk.MasterRotKeys, targetRots); err != nil {
		panic(err)
	}
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(level0); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// =========================================================================
	// VERIFY: encrypt, rotate, check precision
	// (In a real system, client encrypts and server evaluates — here we do
	// both locally for demonstration.)
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
