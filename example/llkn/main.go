// Package main demonstrates LLKN hierarchical rotation keys for CKKS.
//
// LLKN operates entirely in the evaluation ring (no extension ring, no ring
// switching). This makes it simpler than KG+ and compatible with any ring type.
// Derived keys work with standard ckks.Evaluator — no special wrappers needed.
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

	// CKKS parameters. No NTT-for-2N constraint needed (unlike KG+).
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		Q:               []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff380001},
		P:               []uint64{0x1ffffffff6c80001},
		LogDefaultScale: 45,
	}); err != nil {
		panic(err)
	}

	var llknParams llkn.Parameters
	if llknParams, err = llkn.NewParameters(params.Parameters, []int{61}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("LLKN CKKS: LogN=%d, %d slots, %d Q primes\n", params.LogN(), slots, params.QCount())

	// CLIENT: generate and send master keys
	kgen := llkn.NewKeyGenerator(llknParams)
	sk := kgen.GenSecretKeyNew()
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *llkn.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(masterRots), masterRots)

	// SERVER: derive all needed rotation keys (single phase, no intermediate step)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	eval := llkn.NewEvaluator(llknParams)

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.DeriveGaloisKeys(tk, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// SERVER: use derived keys with standard CKKS evaluator
	skEval := kgen.ProjectToEvalKey(sk)
	ecd := ckks.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, skEval)
	dec := rlwe.NewDecryptor(params, skEval)
	ckksEval := ckks.NewEvaluator(params, evk)

	// Encode [1, 2, 3, ..., N/2]
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

	// Rotate and verify — standard ckks.Evaluator, no special wrappers
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
