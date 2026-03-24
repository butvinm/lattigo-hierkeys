// Package main demonstrates hierarchical rotation keys for CKKS slot permutation.
//
// A client sends a small set of master rotation keys (5 keys), and the server
// derives all needed rotation keys (8 keys) via RotToRot expansion + ring switching.
// The derived keys work with the standard ckks.Evaluator.Rotate — no special wrappers.
//
// This mirrors real workloads like convolution, matrix multiplication, and
// bootstrapping where many distinct rotations are needed.
package main

import (
	"fmt"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// CKKS parameters. Primes must be NTT-friendly for degree 2N (the extension
	// ring used internally), so we use explicit primes rather than LogQ/LogP.
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		Q:               []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff380001},
		P:               []uint64{0x1ffffffff6c80001},
		LogDefaultScale: 45,
	}); err != nil {
		panic(err)
	}

	// Hierarchical key parameters (adds one auxiliary prime for ring switching)
	var hkParams hierkeys.Parameters
	if hkParams, err = hierkeys.NewParameters(params.Parameters, []int{61}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("CKKS: LogN=%d, %d slots, %d Q primes\n\n", params.LogN(), slots, params.QCount())

	// Client: generate master keys
	kgen := hierkeys.NewKeyGenerator(hkParams)
	sk := kgen.GenSecretKeyNew()

	// Base-4 master rotations: {1, 4, 16, 64, 256}
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *hierkeys.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("Client: %d master keys for rotations %v\n", len(masterRots), masterRots)

	// Server: derive the rotation keys it needs
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = hierkeys.DeriveGaloisKeys(hkParams, tk, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d keys for rotations %v\n\n", len(evk.GetGaloisKeysList()), targetRots)

	// Encrypt a test vector: slot i = i + 1
	skEval := kgen.ProjectToEvalKey(sk)
	ecd := ckks.NewEncoder(params)
	enc := rlwe.NewEncryptor(params, skEval)
	dec := rlwe.NewDecryptor(params, skEval)
	eval := ckks.NewEvaluator(params, evk)

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

	// Rotate and verify each shift
	for _, rot := range targetRots {
		ctRot := ckks.NewCiphertext(params, 1, ct.Level())
		if err = eval.Rotate(ct, rot, ctRot); err != nil {
			panic(err)
		}

		// Expected: cyclic left shift by rot
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

	fmt.Printf("Rot %3d: [%.0f, %.0f, %.0f, %.0f, ...] -> [%.1f, %.1f, %.1f, %.1f, ...]  maxErr: %.2e\n",
		rot,
		real(want[0]), real(want[1]), real(want[2]), real(want[3]),
		real(have[0]), real(have[1]), real(have[2]), real(have[3]),
		maxErr)
}
