package hierkeys_test

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Micro-benchmarks for individual operations at LogN=14.
// Run: go test -bench BenchmarkMicro -run ^$ -v -timeout 10m .

func microLLKNSetup(b *testing.B) (llkn.Parameters, *llkn.Evaluator, *rlwe.PublicKey, map[int]*hierkeys.MasterKey) {
	paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN: 14, LogQ: []int{50, 50, 50, 50, 50}, LogP: []int{50, 50},
		NTTFlag: true,
	})
	if err != nil {
		b.Fatal(err)
	}
	params, err := llkn.NewParameters(paramsEval, [][]int{{56}})
	if err != nil {
		b.Fatal(err)
	}

	topParams := params.Top()
	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)

	masterKeys := make(map[int]*hierkeys.MasterKey)
	for _, rot := range []int{1, 4} {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			b.Fatal(err)
		}
		masterKeys[rot] = mk
	}

	eval := llkn.NewEvaluator(params)
	return params, eval, pk, masterKeys
}

func microKGPlusSetup(b *testing.B) (kgplus.Parameters, *kgplus.Evaluator, *kgplus.TransmissionKeys) {
	paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN: 14, LogQ: []int{50, 50, 50, 50, 50}, LogP: []int{50, 50},
		NTTFlag: true, LogNthRoot: 16,
	})
	if err != nil {
		b.Fatal(err)
	}
	params, err := kgplus.NewParameters(paramsEval, []int{56}, []int{56})
	if err != nil {
		b.Fatal(err)
	}

	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)
	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)

	masterKeys := make(map[int]*hierkeys.MasterKey)
	for _, rot := range []int{1, 4} {
		gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			b.Fatal(err)
		}
		masterKeys[rot] = mk
	}

	tk := &kgplus.TransmissionKeys{HomingKey: homingKey, PublicKey: pk, MasterRotKeys: masterKeys}
	eval := kgplus.NewEvaluator(params)
	return params, eval, tk
}

// BenchmarkMicroRotToRot measures a single RotToRot call at each level.
func BenchmarkMicroRotToRot(b *testing.B) {
	b.Run("LLKN/level0", func(b *testing.B) {
		params, eval, pk, masterKeys := microLLKNSetup(b)
		shift0, err := hierkeys.PubToRot(params.Levels[0], params.Top(), pk)
		if err != nil {
			b.Fatal(err)
		}
		master1 := masterKeys[1]
		galEl := params.Levels[0].GaloisElement(1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := eval.RotToRot(0, shift0, master1, galEl); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus/level0", func(b *testing.B) {
		params, eval, tk := microKGPlusSetup(b)
		topLevel := params.NumLevels() - 1
		shift0, err := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
		master1 := tk.MasterRotKeys[1]
		galEl := params.RPrime[0].GaloisElement(1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := eval.RotToRot(0, shift0, master1, galEl); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus/level1", func(b *testing.B) {
		params, eval, tk := microKGPlusSetup(b)
		topLevel := params.NumLevels() - 1
		shift0, err := hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey)
		if err != nil {
			b.Fatal(err)
		}
		master1 := tk.MasterRotKeys[1]
		galEl := params.RPrime[1].GaloisElement(1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := eval.RotToRot(1, shift0, master1, galEl); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMicroPubToRot measures PubToRot at each level.
func BenchmarkMicroPubToRot(b *testing.B) {
	b.Run("LLKN/level0", func(b *testing.B) {
		params, _, pk, _ := microLLKNSetup(b)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hierkeys.PubToRot(params.Levels[0], params.Top(), pk); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus/level0", func(b *testing.B) {
		params, _, tk := microKGPlusSetup(b)
		topLevel := params.NumLevels() - 1
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus/level1", func(b *testing.B) {
		params, _, tk := microKGPlusSetup(b)
		topLevel := params.NumLevels() - 1
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMicroFinalizeKey measures per-key finalization.
func BenchmarkMicroFinalizeKey(b *testing.B) {
	b.Run("LLKN", func(b *testing.B) {
		params, eval, pk, masterKeys := microLLKNSetup(b)
		shift0, _ := hierkeys.PubToRot(params.Levels[0], params.Top(), pk)
		// Derive a key to finalize
		galEl := params.Levels[0].GaloisElement(1)
		derived, _ := eval.RotToRot(0, shift0, masterKeys[1], galEl)

		// Pre-generate keys to finalize (FinalizeKey consumes the MasterKey)
		keys := make([]*hierkeys.MasterKey, b.N)
		for i := range keys {
			keys[i], _ = eval.RotToRot(0, shift0, masterKeys[1], galEl)
		}
		_ = derived
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := eval.FinalizeKey(keys[i]); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus", func(b *testing.B) {
		params, eval, tk := microKGPlusSetup(b)
		topLevel := params.NumLevels() - 1
		shift0, _ := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey)
		galEl := params.RPrime[0].GaloisElement(1)

		// Pre-generate keys
		keys := make([]*hierkeys.MasterKey, b.N)
		for i := range keys {
			keys[i], _ = eval.RotToRot(0, shift0, tk.MasterRotKeys[1], galEl)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := eval.FinalizeKey(1, keys[i], tk.HomingKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMicroGaloisKeyToMasterKey measures convention conversion.
func BenchmarkMicroGaloisKeyToMasterKey(b *testing.B) {
	b.Run("LLKN", func(b *testing.B) {
		paramsEval, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: 14, LogQ: []int{50, 50, 50, 50, 50}, LogP: []int{50, 50},
			NTTFlag: true,
		})
		params, _ := llkn.NewParameters(paramsEval, [][]int{{56}})
		topParams := params.Top()
		kgen := rlwe.NewKeyGenerator(topParams)
		sk := kgen.GenSecretKeyNew()
		galEl := topParams.GaloisElement(1)

		// Pre-generate GaloisKeys
		gks := make([]*rlwe.GaloisKey, b.N)
		for i := range gks {
			gks[i] = kgen.GenGaloisKeyNew(galEl, sk)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hierkeys.GaloisKeyToMasterKey(topParams, gks[i]); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("KGPlus_RPrime", func(b *testing.B) {
		paramsEval, _ := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN: 14, LogQ: []int{50, 50, 50, 50, 50}, LogP: []int{50, 50},
			NTTFlag: true, LogNthRoot: 16,
		})
		params, _ := kgplus.NewParameters(paramsEval, []int{56}, []int{56})
		topParams := params.RPrime[params.NumLevels()-1]
		kgenHK := rlwe.NewKeyGenerator(params.HK)
		sk := kgenHK.GenSecretKeyNew()
		sk1 := kgenHK.GenSecretKeyNew()
		skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)
		kgenRP := rlwe.NewKeyGenerator(topParams)
		galEl := topParams.GaloisElement(1)

		gks := make([]*rlwe.GaloisKey, b.N)
		for i := range gks {
			gks[i] = kgenRP.GenGaloisKeyNew(galEl, skExt)
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := hierkeys.GaloisKeyToMasterKey(topParams, gks[i]); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkMicroDecomposeRotation measures decomposition chain lengths.
func BenchmarkMicroDecomposeRotation(b *testing.B) {
	masters2 := []int{1, 4}
	masters7 := []int{1, 4, 16, 64, 256, 1024, 4096}

	for _, target := range []int{1, 16, 100, 1000, 4096, 8191} {
		b.Run("target="+itoa(target), func(b *testing.B) {
			steps2 := hierkeys.DecomposeRotation(target, masters2)
			steps7 := hierkeys.DecomposeRotation(target, masters7)
			b.Logf("target=%d: from {1,4}: %d steps, from base-4: %d steps",
				target, len(steps2), len(steps7))
		})
	}
}

func itoa(n int) string {
	s := ""
	if n == 0 {
		return "0"
	}
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
