// Package main demonstrates KG+ hierarchical rotation keys for CKKS using the
// "inactive" key management pattern from Lee-Lee-Kim-No (Section 2.2).
//
// KG+ uses ring switching (extension ring R' of degree 2N) to reduce
// transmission key sizes. Only supports Standard ring type.
package main

import (
	"bytes"
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// CKKS parameters. Primes must be NTT-friendly for degree 2N (KG+ requirement).
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		Q:               []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff380001},
		P:               []uint64{0x1ffffffff6c80001},
		LogDefaultScale: 45,
	}); err != nil {
		panic(err)
	}

	var hkParams kgplus.Parameters
	if hkParams, err = kgplus.NewParameters(params.Parameters, []int{61}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("KG+ CKKS: LogN=%d, %d slots, %d Q primes\n", params.LogN(), slots, params.QCount())

	// CLIENT: generate and send master keys
	kgen := kgplus.NewKeyGenerator(hkParams)
	sk := kgen.GenSecretKeyNew()
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *kgplus.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(masterRots), masterRots)

	// Serialize transmission keys
	var tkBuf bytes.Buffer
	if _, err = tk.WriteTo(&tkBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Client: transmitted %d bytes (%.1f KB)\n", tkBuf.Len(), float64(tkBuf.Len())/1024)

	// SERVER (inactive phase): expand and store intermediates
	tk2 := new(kgplus.TransmissionKeys)
	if _, err = tk2.ReadFrom(&tkBuf); err != nil {
		panic(err)
	}

	allPossibleRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	eval := kgplus.NewEvaluator(hkParams)

	var intermediate *kgplus.IntermediateKeys
	if intermediate, err = eval.Expand(tk2, allPossibleRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): expanded %d intermediate keys in R'\n", len(intermediate.Keys))

	// Serialize intermediates
	var ikBuf bytes.Buffer
	if _, err = intermediate.WriteTo(&ikBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Server (inactive): stored %d bytes (%.1f KB) to disk\n", ikBuf.Len(), float64(ikBuf.Len())/1024)

	// SERVER (active phase): finalize on demand
	intermediate2 := new(kgplus.IntermediateKeys)
	if _, err = intermediate2.ReadFrom(&ikBuf); err != nil {
		panic(err)
	}

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk2, intermediate2); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (active): finalized %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// SERVER: use derived keys with standard CKKS evaluator
	skEval := kgen.ProjectToEvalKey(sk)
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
	for _, rot := range allPossibleRots {
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
