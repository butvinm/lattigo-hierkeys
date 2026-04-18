// LLKN hierarchical rotation keys — concurrent streaming derivation.
//
// Demonstrates concurrent key derivation. The evaluator is thread-safe — a
// single instance handles all concurrent calls via pool-based scratch buffers.
//
// 2-level LLKN: no intermediate-level expansion; targets derive directly from
// the transmitted master set. Each goroutine runs Derive + FinalizeKey in a
// single pass and writes the finalized key to a pre-sized []*rlwe.GaloisKey
// at its own index — no shared map, no mutex.
package main

import (
	"fmt"
	"math/cmplx"
	"sync"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func main() {
	var err error

	// --- CKKS + LLKN parameters --- 128-bit secure (FHE Security Guidelines 2024, LogN=14, Q_max=430).
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{55, 40, 40, 40, 40},
		LogP:            []int{55, 55},
		LogDefaultScale: 40,
	}); err != nil {
		panic(err)
	}

	// LLKN 2-level: one extra level of P primes for master keys.
	var params llkn.Parameters
	if params, err = llkn.NewParameters(ckksParams.Parameters, [][]int{
		{55}, // P for master level
	}); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topParams := params.Top()
	fmt.Printf("LLKN concurrent (%d-level): LogN=%d, %d slots\n",
		params.NumLevels(), ckksParams.LogN(), slots)

	// CLIENT: generate keys (same as simple example)

	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}

	tk := &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}
	fmt.Printf("Client: %d master keys, TX = %.1f MB\n",
		len(masterRots), float64(tk.BinarySize())/(1024*1024))

	// SERVER: concurrent streaming derive + finalize.
	// Each rotation is computed at most once — concurrent Derive calls for the
	// same rotation (as a target or a chain dependency) coordinate automatically
	// via LevelExpansion's internal sync.Once per rotation.

	eval := llkn.NewEvaluator(params)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0 *hierkeys.MasterKey
	if shift0, err = hierkeys.PubToRot(params.Levels()[0], params.Top(), tk.PublicKey); err != nil {
		panic(err)
	}
	exp := eval.NewLevelExpansion(0, shift0, tk.MasterRotKeys, targetRots)

	galoisKeys := make([]*rlwe.GaloisKey, len(targetRots))
	errs := make([]error, len(targetRots))
	var wg sync.WaitGroup
	for i, rot := range targetRots {
		wg.Add(1)
		go func(idx, r int) {
			defer wg.Done()
			mk, err := exp.Derive(r)
			if err != nil {
				errs[idx] = err
				return
			}
			galoisKeys[idx], errs[idx] = eval.FinalizeKey(mk)
		}(i, rot)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			panic(fmt.Sprintf("derive/finalize rotation %d: %v", targetRots[i], e))
		}
	}

	evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
	fmt.Printf("Server: derived + finalized %d evaluation keys (%d goroutines)\n",
		len(evk.GetGaloisKeysList()), len(targetRots))

	// VERIFY

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
