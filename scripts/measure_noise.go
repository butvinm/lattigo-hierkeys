// Measure actual noise in derived rotation keys, and verify by encrypting+rotating.
//
// Two measurements per config:
//  1. log2(noise) inside the GaloisKey itself (via NoiseGaloisKey)
//  2. log2(error) of the result after encrypting Δ·v, rotating with the key,
//     and decrypting — this is the noise that an application would see
//
// Compares fresh / LLKN k=2 / KG+ k=3 derived keys.
//
// Run: go run scripts/measure_noise.go
package main

import (
	"fmt"
	"math"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

type config struct {
	Name      string
	LogN      int
	LogQ      []int
	LogP      []int
	LogPHK    []int // LLKN level-1 P (and KG+ HK/intermediate P)
	LogPExtra []int // KG+ master level P
	TargetRot int   // a rotation we'll derive and measure
}

func rep(n, v int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func main() {
	// Final benchmark scenarios from benchmark_test.go.
	// Hierarchy P primes are ≥ 55b to satisfy lattigo's gadget product noise rule:
	// each digit's bit-product must be ≤ total P bit-product.
	configs := []config{
		{
			Name:      "LogN14 (q0=55, qi=40, Pi=55, PHK=55, PExtra=55)",
			LogN:      14,
			LogQ:      append([]int{55}, rep(4, 40)...),
			LogP:      rep(2, 55),
			LogPHK:    rep(1, 55),
			LogPExtra: rep(7, 55),
			TargetRot: 5,
		},
		{
			Name:      "LogN15 (q0=55, qi=40, Pi=55, PHK=5×55, PExtra=10×55)",
			LogN:      15,
			LogQ:      append([]int{55}, rep(9, 40)...),
			LogP:      rep(3, 55),
			LogPHK:    rep(5, 55),
			LogPExtra: rep(10, 55),
			TargetRot: 5,
		},
		// LogN=16 takes too long for casual sanity checks; uncomment when needed.
		// {
		//     Name:      "LogN16 (q0=55, qi=40, Pi=55, PHK=6×55, PExtra=25×55)",
		//     LogN:      16,
		//     LogQ:      append([]int{55}, rep(27, 40)...),
		//     LogP:      rep(4, 55),
		//     LogPHK:    rep(6, 55),
		//     LogPExtra: rep(25, 55),
		//     TargetRot: 5,
		// },
	}

	for _, c := range configs {
		fmt.Println()
		fmt.Println("================================================================")
		fmt.Println("  " + c.Name)
		fmt.Println("================================================================")

		// Build CKKS params first, then use its underlying RLWE params everywhere
		// so the ring/primes are identical across encryption, key gen, and rotation.
		ckksParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            c.LogN,
			LogQ:            c.LogQ,
			LogP:            c.LogP,
			LogDefaultScale: 40,
			LogNthRoot:      c.LogN + 2, // for KG+ compatibility
		})
		if err != nil {
			fmt.Printf("  ckks params error: %v\n", err)
			continue
		}
		paramsEval := ckksParams.Parameters

		// Fresh baseline
		kgen := rlwe.NewKeyGenerator(paramsEval)
		sk := kgen.GenSecretKeyNew()
		freshGk := kgen.GenGaloisKeyNew(paramsEval.GaloisElement(c.TargetRot), sk)
		freshNoise := rlwe.NoiseGaloisKey(freshGk, sk, paramsEval)
		freshErr := rotateAndMeasure(ckksParams, sk, freshGk, c.TargetRot)
		fmt.Printf("  Fresh:      log2(key noise) = %5.1f   log2(rot err) = %5.1f\n", freshNoise, freshErr)

		// ── LLKN k=2 ──
		llknParams, err := llkn.NewParameters(paramsEval, [][]int{c.LogPHK})
		if err != nil {
			fmt.Printf("  LLKN params error: %v\n", err)
		} else {
			n, e := measureLLKN(llknParams, ckksParams, c.TargetRot)
			fmt.Printf("  LLKN k=2:   log2(key noise) = %5.1f   log2(rot err) = %5.1f\n", n, e)
		}

		// ── KG+ k=3 ──
		if c.LogPExtra != nil {
			kgpParams, err := kgplus.NewParameters(paramsEval, c.LogPHK, c.LogPExtra)
			if err != nil {
				fmt.Printf("  KG+ params error: %v\n", err)
			} else {
				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Printf("  KG+ k=3:    PANIC: %v\n", r)
						}
					}()
					n, e := measureKGPlus(kgpParams, ckksParams, c.TargetRot)
					fmt.Printf("  KG+ k=3:    log2(key noise) = %5.1f   log2(rot err) = %5.1f\n", n, e)
				}()
			}
		}
	}
}

// rotateAndMeasure encrypts a known vector, rotates it using gk, decrypts,
// and returns log2 of the maximum error magnitude in the recovered slots.
// Uses the SAME secret key sk for encryption and decryption.
func rotateAndMeasure(params ckks.Parameters, sk *rlwe.SecretKey, gk *rlwe.GaloisKey, rot int) float64 {
	enc := rlwe.NewEncryptor(params, sk)
	dec := rlwe.NewDecryptor(params, sk)
	encoder := ckks.NewEncoder(params)

	// Plaintext: simple integer values 1, 2, 3, ...
	slots := params.MaxSlots()
	values := make([]float64, slots)
	for i := range values {
		values[i] = float64(i + 1)
	}
	pt := ckks.NewPlaintext(params, params.MaxLevel())
	if err := encoder.Encode(values, pt); err != nil {
		return math.NaN()
	}
	ct, err := enc.EncryptNew(pt)
	if err != nil {
		return math.NaN()
	}

	// Rotate using the provided GaloisKey via a fresh evaluator
	evk := rlwe.NewMemEvaluationKeySet(nil, gk)
	eval := ckks.NewEvaluator(params, evk)
	rotated, err := eval.RotateNew(ct, rot)
	if err != nil {
		return math.NaN()
	}

	// Decrypt
	ptOut := dec.DecryptNew(rotated)
	out := make([]float64, slots)
	if err := encoder.Decode(ptOut, out); err != nil {
		return math.NaN()
	}

	maxErr := 0.0
	for i := 0; i < slots; i++ {
		expected := values[(i+rot)%slots]
		diff := math.Abs(out[i] - expected)
		if diff > maxErr {
			maxErr = diff
		}
	}
	if maxErr == 0 {
		return math.Inf(-1)
	}
	return math.Log2(maxErr)
}

func measureLLKN(params llkn.Parameters, ckksParams ckks.Parameters, targetRot int) (float64, float64) {
	topParams := params.Top()
	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	slots := topParams.N() / 2
	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		mk, _ := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		masterKeys[rot] = mk
	}

	eval := llkn.NewEvaluator(params)
	shift0, err := hierkeys.PubToRot(params.Levels[0], topParams, pk)
	if err != nil {
		return math.NaN(), math.NaN()
	}
	level0, err := eval.ExpandLevel(0, shift0, masterKeys, []int{targetRot})
	if err != nil {
		return math.NaN(), math.NaN()
	}
	derivedGk, err := eval.FinalizeKey(level0.Keys[targetRot])
	if err != nil {
		return math.NaN(), math.NaN()
	}

	skEval, err := params.ProjectToEvalKey(sk)
	if err != nil {
		return math.NaN(), math.NaN()
	}
	keyNoise := rlwe.NoiseGaloisKey(derivedGk, skEval, params.Eval())
	rotErr := rotateAndMeasure(ckksParams, skEval, derivedGk, targetRot)
	return keyNoise, rotErr
}

func measureKGPlus(params kgplus.Parameters, ckksParams ckks.Parameters, targetRot int) (float64, float64) {
	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)

	slots := topParams.N() / 2
	fullSet := hierkeys.MasterRotationsForBase(4, slots)
	bigMaster := fullSet[len(fullSet)/2]
	masterRots := []int{1, bigMaster}

	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
		mk, _ := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		masterKeys[rot] = mk
	}

	tk := &kgplus.TransmissionKeys{HomingKey: homingKey, PublicKey: pk, MasterRotKeys: masterKeys}
	eval := kgplus.NewEvaluator(params)
	currentMasters := tk.MasterRotKeys

	for level := topLevel - 1; level >= 1; level-- {
		shift0, err := hierkeys.PubToRot(params.RPrime[level], topParams, tk.PublicKey)
		if err != nil {
			return math.NaN(), math.NaN()
		}
		intermediate, err := eval.ExpandLevel(level, shift0, currentMasters, fullSet)
		if err != nil {
			return math.NaN(), math.NaN()
		}
		currentMasters = intermediate.Keys
	}

	shift0, err := hierkeys.PubToRot(params.RPrime[0], topParams, tk.PublicKey)
	if err != nil {
		return math.NaN(), math.NaN()
	}
	level0, err := eval.ExpandLevel(0, shift0, currentMasters, []int{targetRot})
	if err != nil {
		return math.NaN(), math.NaN()
	}

	galoisKeys, err := eval.FinalizeKeys(tk, level0)
	if err != nil {
		return math.NaN(), math.NaN()
	}

	galEl := params.Eval.GaloisElement(targetRot)
	derivedGk, err := galoisKeys.GetGaloisKey(galEl)
	if err != nil {
		return math.NaN(), math.NaN()
	}

	skEval, err := params.ProjectToEvalKey(sk)
	if err != nil {
		return math.NaN(), math.NaN()
	}
	keyNoise := rlwe.NoiseGaloisKey(derivedGk, skEval, params.Eval)
	rotErr := rotateAndMeasure(ckksParams, skEval, derivedGk, targetRot)
	return keyNoise, rotErr
}

// silence unused imports if they slip in
var _ = ring.NewPoly
