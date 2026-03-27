// Package main demonstrates KG+ hierarchical rotation keys for CKKS using the
// "inactive" key management pattern with a 3-level hierarchy (k=3).
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

	// k=3 hierarchy: needs enough P primes at each intermediate level
	// for noise control when derived keys are used as masters.
	var hkParams kgplus.Parameters
	logPHK := []int{61, 61, 61, 61, 61, 61}    // P for RPrime[1] (also HK P)
	logPExtra := []int{61, 61, 61, 61, 61, 61} // P for RPrime[2]
	if hkParams, err = kgplus.NewParameters(params.Parameters, logPHK, logPExtra); err != nil {
		panic(err)
	}

	slots := params.MaxSlots()
	fmt.Printf("KG+ CKKS (k=%d): LogN=%d, %d slots, %d Q primes\n",
		hkParams.NumLevels(), params.LogN(), slots, params.QCount())
	for i, rp := range hkParams.RPrime {
		fmt.Printf("  RPrime[%d]: Q=%d, P=%d primes\n", i, rp.QCount(), rp.PCount())
	}

	// CLIENT: generate and send master keys
	kgen := kgplus.NewKeyGenerator(hkParams)
	sk := kgen.GenSecretKeyNew()
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var tk *kgplus.TransmissionKeys
	if tk, err = kgen.GenTransmissionKeys(sk, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nClient: %d master keys for rotations %v\n", len(masterRots), masterRots)
	fmt.Printf("Client: EncZero at top RPrime level (degree %d)\n", tk.EncZero.Degree())

	// Serialize transmission keys
	var tkBuf bytes.Buffer
	if _, err = tk.WriteTo(&tkBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Client: transmitted %d bytes (%.1f KB)\n", tkBuf.Len(), float64(tkBuf.Len())/1024)

	// SERVER: gradual expansion using per-level ExpandLevel
	tk2 := new(kgplus.TransmissionKeys)
	if _, err = tk2.ReadFrom(&tkBuf); err != nil {
		panic(err)
	}

	eval := kgplus.NewEvaluator(hkParams)

	// Phase 1 (rare): derive level-1 keys from top masters
	topLevel := hkParams.NumLevels() - 1
	var shift0L1 *rlwe.GaloisKey
	if shift0L1, err = hierkeys.PubToRot(hkParams.RPrime[1], hkParams.RPrime[topLevel], tk2.EncZero); err != nil {
		panic(err)
	}
	var level1Keys *kgplus.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk2.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (phase 1): derived %d level-1 keys in R'\n", len(level1Keys.Keys))

	// Serialize level-1 intermediates to disk
	var l1Buf bytes.Buffer
	if _, err = level1Keys.WriteTo(&l1Buf); err != nil {
		panic(err)
	}
	fmt.Printf("Server (phase 1): stored %d bytes (%.1f KB)\n", l1Buf.Len(), float64(l1Buf.Len())/1024)

	// Phase 2 (occasional): derive level-0 keys from level-1 keys
	level1Loaded := new(kgplus.IntermediateKeys)
	if _, err = level1Loaded.ReadFrom(&l1Buf); err != nil {
		panic(err)
	}

	allPossibleRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	var shift0L0 *rlwe.GaloisKey
	if shift0L0, err = hierkeys.PubToRot(hkParams.RPrime[0], hkParams.RPrime[topLevel], tk2.EncZero); err != nil {
		panic(err)
	}
	var level0Keys *kgplus.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Loaded.Keys, allPossibleRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server (phase 2): derived %d level-0 keys in R'\n", len(level0Keys.Keys))

	// Serialize level-0 intermediates
	var ikBuf bytes.Buffer
	if _, err = level0Keys.WriteTo(&ikBuf); err != nil {
		panic(err)
	}
	fmt.Printf("Server (phase 2): stored %d bytes (%.1f KB)\n", ikBuf.Len(), float64(ikBuf.Len())/1024)

	// Phase 3 (on-demand): finalize from stored level-0 intermediates
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
