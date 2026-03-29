package hierkeys_test

import (
	"sync"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

const benchNTargets = 256 // fixed number of derived rotation keys across all scenarios

type benchScenario struct {
	Name   string
	LogN   int
	LogQ   []int // Q prime bit-sizes
	LogP   []int // P prime bit-sizes
	LogPHK []int // Homing key / master P prime bit-sizes (k=2)
	Base   int   // master rotation base

	// k=3 KG+ parameters: P_hk with enough primes for noise control,
	// P_extra large enough for dnum=1 at the top level.
	LogPHK3   []int // P^(1) for RPrime[1] (≈ Q_eval primes for noise)
	LogPExtra []int // P^(2) for RPrime[2] (≈ Q^(2) primes for dnum=1)
}

func buildLogQ(n, bitSize int) []int {
	q := make([]int, n)
	for i := range q {
		q[i] = bitSize
	}
	return q
}

// 128-bit secure parameter sets (HE Standard, h=N/2 ternary secret).
var benchScenarios = []benchScenario{
	{
		Name: "LogN14_Q5_P2",
		LogN: 14, LogQ: buildLogQ(5, 50), LogP: []int{50, 50}, LogPHK: []int{56},
		Base:      4,
		LogPHK3:   []int{56},
		LogPExtra: []int{56},
	},
	{
		Name: "LogN15_Q10_P3",
		LogN: 15, LogQ: append([]int{55}, buildLogQ(9, 40)...), LogP: []int{61, 61, 61},
		LogPHK:    []int{61, 61},
		Base:      4,
		LogPHK3:   buildLogQ(10, 61),
		LogPExtra: buildLogQ(5, 61),
	},
	{
		Name: "LogN16_Q24_P4",
		LogN: 16, LogQ: buildLogQ(24, 55), LogP: []int{55, 55, 55, 55},
		LogPHK:    []int{55, 55, 55, 55},
		Base:      4,
		LogPHK3:   buildLogQ(3, 57),
		LogPExtra: buildLogQ(31, 55),
	},
}

// genLLKNTransmissionKeys generates LLKN transmission keys using the new API.
func genLLKNTransmissionKeys(b *testing.B, params llkn.Parameters, masterRots []int) *llkn.TransmissionKeys {
	topParams := params.Top()
	kgen := rlwe.NewKeyGenerator(topParams)
	sk := kgen.GenSecretKeyNew()
	pk := kgen.GenPublicKeyNew(sk)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		gk := kgen.GenGaloisKeyNew(topParams.GaloisElement(rot), sk)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			b.Fatal(err)
		}
		masterKeys[rot] = mk
	}
	return &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}
}

// genKGPlusTransmissionKeys generates KG+ transmission keys using the new API.
func genKGPlusTransmissionKeys(b *testing.B, params kgplus.Parameters, masterRots []int) *kgplus.TransmissionKeys {
	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sk := kgenHK.GenSecretKeyNew()
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)

	kgenRP := rlwe.NewKeyGenerator(topParams)
	pk := kgenRP.GenPublicKeyNew(skExt)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))
	for _, rot := range masterRots {
		gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			b.Fatal(err)
		}
		masterKeys[rot] = mk
	}
	return &kgplus.TransmissionKeys{HomingKey: homingKey, PublicKey: pk, MasterRotKeys: masterKeys}
}

// BenchmarkKeySizes measures and reports transmission key sizes for LLKN k=2 and KG+ k=3.
func BenchmarkKeySizes(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:       sc.LogN,
				LogQ:       sc.LogQ,
				LogP:       sc.LogP,
				NTTFlag:    true,
				LogNthRoot: sc.LogN + 2,
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := make([]int, 0, benchNTargets)
			for i := 1; i <= benchNTargets && i < slots; i++ {
				targetRots = append(targetRots, i)
			}

			kgenRef := rlwe.NewKeyGenerator(paramsEval)
			skRef := kgenRef.GenSecretKeyNew()
			refGK := kgenRef.GenGaloisKeyNew(paramsEval.GaloisElement(1), skRef)
			stdKeySize := refGK.BinarySize()
			conventionalBytes := stdKeySize * len(targetRots)

			b.Logf("N=%d, QCount=%d, PCount=%d, dnum_eval=%d, masters=%d, targets=%d",
				paramsEval.N(), paramsEval.QCount(), paramsEval.PCount(),
				paramsEval.BaseRNSDecompositionVectorSize(paramsEval.MaxLevel(), paramsEval.MaxLevelP()),
				len(masterRots), len(targetRots))
			b.Logf("Conventional: %d keys × %d bytes = %.1f MB",
				len(targetRots), stdKeySize, float64(conventionalBytes)/(1024*1024))

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, [][]int{sc.LogPHK})
				if err != nil {
					b.Fatal(err)
				}

				topLevel := params.Top()
				dnumMaster := topLevel.BaseRNSDecompositionVectorSize(
					topLevel.MaxLevel(), topLevel.MaxLevelP())

				tk := genLLKNTransmissionKeys(b, params, masterRots)
				tkSize := tk.BinarySize()
				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("LLKN k=2: dnum_master=%d, TX=%.1f MB (%.0f%% of conventional)",
					dnumMaster, float64(tkSize)/(1024*1024), ratio)
				b.ReportMetric(float64(tkSize)/(1024*1024), "TX_MB")
				b.ReportMetric(ratio, "vs_conv_%")
				b.ReportMetric(float64(dnumMaster), "dnum_master")
			})

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}

				topRP := params.RPrime[params.NumLevels()-1]
				dnumMaster := topRP.BaseRNSDecompositionVectorSize(
					topRP.MaxLevel(), topRP.MaxLevelP())

				k3MasterRots := []int{1, sc.Base}
				tk := genKGPlusTransmissionKeys(b, params, k3MasterRots)
				tkSize := tk.BinarySize()
				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("KG+ k=3: dnum_master=%d, masters=%v, TX=%.1f MB (%.0f%% of conventional)",
					dnumMaster, k3MasterRots, float64(tkSize)/(1024*1024), ratio)
				b.ReportMetric(float64(tkSize)/(1024*1024), "TX_MB")
				b.ReportMetric(ratio, "vs_conv_%")
				b.ReportMetric(float64(dnumMaster), "dnum_master")
			})
		})
	}
}

// BenchmarkDeriveGaloisKeys measures server-side key derivation time.
func BenchmarkDeriveGaloisKeys(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:       sc.LogN,
				LogQ:       sc.LogQ,
				LogP:       sc.LogP,
				NTTFlag:    true,
				LogNthRoot: sc.LogN + 2,
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := make([]int, 0, benchNTargets)
			for i := 1; i <= benchNTargets && i < slots; i++ {
				targetRots = append(targetRots, i)
			}

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, [][]int{sc.LogPHK})
				if err != nil {
					b.Fatal(err)
				}
				tk := genLLKNTransmissionKeys(b, params, masterRots)
				eval := llkn.NewEvaluator(params)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := eval.DeriveGaloisKeys(tk, targetRots); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}
				k3MasterRots := []int{1, sc.Base}
				tk := genKGPlusTransmissionKeys(b, params, k3MasterRots)
				eval := kgplus.NewEvaluator(params)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := eval.DeriveGaloisKeys(tk, targetRots); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// BenchmarkDeriveGaloisKeysConcurrent measures concurrent server-side derivation.
// Uses LevelExpansion.Derive from goroutines + concurrent FinalizeKey.
func BenchmarkDeriveGaloisKeysConcurrent(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:       sc.LogN,
				LogQ:       sc.LogQ,
				LogP:       sc.LogP,
				NTTFlag:    true,
				LogNthRoot: sc.LogN + 2,
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := make([]int, 0, benchNTargets)
			for i := 1; i <= benchNTargets && i < slots; i++ {
				targetRots = append(targetRots, i)
			}

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, [][]int{sc.LogPHK})
				if err != nil {
					b.Fatal(err)
				}
				tk := genLLKNTransmissionKeys(b, params, masterRots)
				eval := llkn.NewEvaluator(params)
				topLevel := params.NumLevels() - 1

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Sequential cascade through intermediate levels
					currentMasters := tk.MasterRotKeys
					for level := params.NumLevels() - 2; level >= 1; level-- {
						shift0, err := hierkeys.PubToRot(params.Levels[level], params.Levels[topLevel], tk.PublicKey)
						if err != nil {
							b.Fatal(err)
						}
						intermediate, err := eval.ExpandLevel(level, shift0, currentMasters, masterRots)
						if err != nil {
							b.Fatal(err)
						}
						currentMasters = intermediate.Keys
					}

					// Concurrent level-0 expansion
					shift0, err := hierkeys.PubToRot(params.Levels[0], params.Levels[topLevel], tk.PublicKey)
					if err != nil {
						b.Fatal(err)
					}
					exp := eval.NewLevelExpansion(0, shift0, currentMasters)
					var wg sync.WaitGroup
					for _, rot := range targetRots {
						wg.Add(1)
						go func(r int) {
							defer wg.Done()
							if _, err := exp.Derive(r); err != nil {
								b.Error(err)
							}
						}(rot)
					}
					wg.Wait()

					// Concurrent finalization
					level0Keys := exp.IntermediateKeys(targetRots)
					galoisKeys := make([]*rlwe.GaloisKey, len(targetRots))
					for j, rot := range targetRots {
						wg.Add(1)
						go func(idx, r int) {
							defer wg.Done()
							gk, err := eval.FinalizeKey(level0Keys.Keys[r])
							if err != nil {
								b.Error(err)
							}
							galoisKeys[idx] = gk
						}(j, rot)
					}
					wg.Wait()
				}
			})

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}
				k3MasterRots := []int{1, sc.Base}
				tk := genKGPlusTransmissionKeys(b, params, k3MasterRots)
				eval := kgplus.NewEvaluator(params)
				topLevel := params.NumLevels() - 1

				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Sequential cascade through intermediate levels
					currentMasters := tk.MasterRotKeys
					for level := params.NumLevels() - 2; level >= 1; level-- {
						shift0, err := hierkeys.PubToRot(params.RPrime[level], params.RPrime[topLevel], tk.PublicKey)
						if err != nil {
							b.Fatal(err)
						}
						intermediate, err := eval.ExpandLevel(level, shift0, currentMasters, masterRots)
						if err != nil {
							b.Fatal(err)
						}
						currentMasters = intermediate.Keys
					}

					// Concurrent level-0 expansion
					shift0, err := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey)
					if err != nil {
						b.Fatal(err)
					}
					exp := eval.NewLevelExpansion(0, shift0, currentMasters)
					var wg sync.WaitGroup
					for _, rot := range targetRots {
						wg.Add(1)
						go func(r int) {
							defer wg.Done()
							if _, err := exp.Derive(r); err != nil {
								b.Error(err)
							}
						}(rot)
					}
					wg.Wait()

					// Concurrent finalization
					level0Keys := exp.IntermediateKeys(targetRots)
					galoisKeys := make([]*rlwe.GaloisKey, len(targetRots))
					for j, rot := range targetRots {
						wg.Add(1)
						go func(idx, r int) {
							defer wg.Done()
							gk, err := eval.FinalizeKey(r, level0Keys.Keys[r], tk.HomingKey)
							if err != nil {
								b.Error(err)
							}
							galoisKeys[idx] = gk
						}(j, rot)
					}
					wg.Wait()
				}
			})
		})
	}
}

// BenchmarkGenTransmissionKeys measures client-side key generation time.
func BenchmarkGenTransmissionKeys(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:       sc.LogN,
				LogQ:       sc.LogQ,
				LogP:       sc.LogP,
				NTTFlag:    true,
				LogNthRoot: sc.LogN + 2,
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, [][]int{sc.LogPHK})
				if err != nil {
					b.Fatal(err)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					genLLKNTransmissionKeys(b, params, masterRots)
				}
			})

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}
				k3MasterRots := []int{1, sc.Base}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					genKGPlusTransmissionKeys(b, params, k3MasterRots)
				}
			})
		})
	}
}
