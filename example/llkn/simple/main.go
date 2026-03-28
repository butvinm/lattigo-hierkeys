// Package main demonstrates LLKN hierarchical rotation keys for CKKS
// using a 2-level hierarchy (k=2) with the one-shot DeriveGaloisKeys API.
//
// LLKN operates entirely in the evaluation ring (no extension ring, no ring
// switching). This makes it simpler than KG+ and compatible with any ring type.
// Derived keys work with standard ckks.Evaluator — no special wrappers needed.
//
// Parameters are 128-bit secure (HE Standard, LogN=14, eval QP=350 ≤ 438).
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

	// 128-bit secure CKKS parameters.
	// LogN=14: Q_max=438, eval QP = 5×50 + 2×50 = 350.
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
	// Master level QP = eval QP + P_hk = 350 + 56 = 406 ≤ 438.
	var llknParams llkn.Parameters
	if llknParams, err = llkn.NewParameters(params.Parameters, [][]int{
		{56}, // P for master level
	}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("LLKN CKKS (k=%d): LogN=%d, %d slots, %d Q primes\n",
		llknParams.NumLevels(), params.LogN(), slots, params.QCount())
	for i, lvl := range llknParams.Levels {
		fmt.Printf("  Level[%d]: Q=%d, P=%d primes\n", i, lvl.QCount(), lvl.PCount())
	}

	// CLIENT: generate and send transmission keys
	kgen := llkn.NewKeyGenerator(llknParams)
	sk := kgen.GenSecretKeyNew()
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *llkn.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(masterRots), masterRots)
	fmt.Printf("Client: TX size = %d bytes (%.1f MB)\n", tk.BinarySize(), float64(tk.BinarySize())/(1024*1024))

	// SERVER: one-shot derivation
	eval := llkn.NewEvaluator(llknParams)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.DeriveGaloisKeys(tk, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// SERVER: use derived keys with standard CKKS evaluator
	var skEval *rlwe.SecretKey
	if skEval, err = kgen.ProjectToEvalKey(sk); err != nil {
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
