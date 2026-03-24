// Package main demonstrates hierarchical rotation keys for CKKS using the
// "inactive" key management pattern from Lee-Lee-Kim-No (Section 2.2).
//
// The server pre-expands master keys into R' intermediates (expensive, done once)
// and serializes them to disk. When a client requests a service, the server
// loads the intermediates and finalizes them to evaluation keys (cheap, on demand).
//
// This pattern minimizes both RAM usage and latency: intermediates are smaller
// than full evaluation keys, and finalization is ~5x faster than full derivation.
package main

import (
	"bytes"
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// CKKS parameters. Primes must be NTT-friendly for degree 2N.
	var params ckks.Parameters
	if params, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            10,
		Q:               []uint64{0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001, 0x1fffffffff500001, 0x1fffffffff380001},
		P:               []uint64{0x1ffffffff6c80001},
		LogDefaultScale: 45,
	}); err != nil {
		panic(err)
	}

	var hkParams hierkeys.Parameters
	if hkParams, err = hierkeys.NewParameters(params.Parameters, []int{61}); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("CKKS: LogN=%d, %d slots, %d Q primes\n", params.LogN(), slots, params.QCount())

	// CLIENT: generate and send master keys

	kgen := hierkeys.NewKeyGenerator(hkParams)
	sk := kgen.GenSecretKeyNew()
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *hierkeys.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(masterRots), masterRots)

	// Serialize transmission keys (simulates network send)
	var tkBuf bytes.Buffer
	if _, err = tk.WriteTo(&tkBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Client: transmitted %d bytes (%.1f KB)\n", tkBuf.Len(), float64(tkBuf.Len())/1024)

	// SERVER (inactive phase): expand and store intermediates

	// Deserialize transmission keys
	tk2 := new(hierkeys.TransmissionKeys)
	if _, err = tk2.ReadFrom(&tkBuf); err != nil {
		panic(err)
	}

	// Expand master keys to R' intermediates for all POSSIBLE rotations
	// the server might need. This is the expensive step.
	allPossibleRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	eval := hierkeys.NewEvaluator(hkParams)

	var intermediate *hierkeys.IntermediateKeys
	if intermediate, err = eval.ExpandInRPrime(tk2, allPossibleRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): expanded %d intermediate keys in R'\n", len(intermediate.Keys))

	// Serialize intermediates to "disk" (simulates persistent storage)
	var ikBuf bytes.Buffer
	if _, err = intermediate.WriteTo(&ikBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Server (inactive): stored %d bytes (%.1f KB) to disk\n", ikBuf.Len(), float64(ikBuf.Len())/1024)

	// SERVER (active phase): finalize on demand when service requested

	// Load intermediates from "disk"
	intermediate2 := new(hierkeys.IntermediateKeys)
	if _, err = intermediate2.ReadFrom(&ikBuf); err != nil {
		panic(err)
	}

	// Finalize to standard evaluation keys (cheap — ring switch + post-convert only)
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk2, intermediate2); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (active): finalized %d evaluation keys from stored intermediates\n",
		len(evk.GetGaloisKeysList()))

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

	// Rotate and verify
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

	fmt.Printf("Rot %3d: [%.0f, %.0f, %.0f, %.0f, ...] -> [%.1f, %.1f, %.1f, %.1f, ...]  maxErr: %.2e\n",
		rot,
		real(want[0]), real(want[1]), real(want[2]), real(want[3]),
		real(have[0]), real(have[1]), real(have[2]), real(have[3]),
		maxErr)
}
