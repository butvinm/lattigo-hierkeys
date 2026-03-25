package hierkeys_test

import (
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

type benchScenario struct {
	Name       string
	LogN       int
	LogQ       []int // Q prime bit-sizes
	LogP       []int // P prime bit-sizes
	LogPHK     []int // Homing key / master P prime bit-sizes
	Base       int   // master rotation base
	NTargets   int   // number of target rotations to derive
	SkipKGPlus bool  // skip KG+ if primes aren't NTT-friendly for 2N
}

// buildLogQ creates a slice of n copies of bitSize.
func buildLogQ(n, bitSize int) []int {
	q := make([]int, n)
	for i := range q {
		q[i] = bitSize
	}
	return q
}

var benchScenarios = []benchScenario{
	{
		Name: "Toy_LogN10",
		LogN: 10, LogQ: buildLogQ(5, 55), LogP: []int{56}, LogPHK: []int{56},
		Base: 4, NTargets: 15,
	},
	{
		Name: "Small_LogN12",
		LogN: 12, LogQ: buildLogQ(8, 55), LogP: []int{56, 56}, LogPHK: []int{56},
		Base: 4, NTargets: 20,
	},
	{
		// Approaching realistic: dnum_eval = ceil(14/3) = 5
		Name: "Medium_LogN14",
		LogN: 14, LogQ: buildLogQ(14, 55), LogP: []int{56, 56, 56}, LogPHK: []int{56},
		Base: 4, NTargets: 50,
	},
	{
		// Paper-like regime: many Q primes, large modulus chain
		// dnum_eval = ceil(22/5) ≈ 5, but KG+ in R' gets dnum_master ~ 1-2
		// because Q_R' = Q_eval ∪ P_eval = 27 primes, and P_hk can be large.
		// We use 5 large P_hk primes so dnum_RPrimeMaster = ceil(27/5) = 6
		// To truly get dnum=1 as in the paper, we'd need P_hk ≈ Q, which
		// requires many more P_hk primes.
		Name: "Large_LogN15",
		LogN: 15, LogQ: buildLogQ(22, 55), LogP: []int{56, 56, 56, 56, 56}, LogPHK: []int{56, 56, 56, 56, 56},
		Base: 4, NTargets: 100,
	},
}

// BenchmarkKeySizes measures and reports transmission key sizes.
// Run with: go test -bench BenchmarkKeySizes -benchtime 1x -run ^$ -timeout 30m ./...
func BenchmarkKeySizes(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			// Generate primes NTT-friendly for 2N (so KG+ also works)
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:       sc.LogN,
				LogQ:       sc.LogQ,
				LogP:       sc.LogP,
				NTTFlag:    true,
				LogNthRoot: sc.LogN + 2, // q ≡ 1 mod 4N → NTT-friendly for degree 2N
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := make([]int, 0, sc.NTargets)
			for i := 1; i <= sc.NTargets && i < slots; i++ {
				targetRots = append(targetRots, i)
			}

			// Reference: size of one standard GaloisKey
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

			b.Run("KGPlus", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ params failed:", err)
					return
				}

				dnumMaster := params.RPrimeMaster.BaseRNSDecompositionVectorSize(
					params.RPrimeMaster.MaxLevel(), params.RPrimeMaster.MaxLevelP())

				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}

				tkSize := tk.BinarySize()
				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("KG+ dnum_master=%d, TX=%.1f MB (%.0f%% of conventional)",
					dnumMaster, float64(tkSize)/(1024*1024), ratio)
				b.ReportMetric(float64(tkSize)/(1024*1024), "TX_MB")
				b.ReportMetric(ratio, "vs_conv_%")
				b.ReportMetric(float64(dnumMaster), "dnum_master")
			})

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Fatal(err)
				}

				dnumMaster := params.Master.BaseRNSDecompositionVectorSize(
					params.Master.MaxLevel(), params.Master.MaxLevelP())

				kgen := llkn.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}

				// Compute LLKN transmission size
				tkSize := 0
				if tk.Shift0Key != nil {
					tkSize += tk.Shift0Key.BinarySize()
				}
				tkSize += 8
				for _, gk := range tk.MasterRotKeys {
					tkSize += 8 + gk.BinarySize()
				}

				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("LLKN dnum_master=%d, TX=%.1f MB (%.0f%% of conventional)",
					dnumMaster, float64(tkSize)/(1024*1024), ratio)
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
		if sc.LogN > 14 {
			continue // skip very large for speed
		}

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
			targetRots := make([]int, 0, sc.NTargets)
			for i := 1; i <= sc.NTargets && i < slots; i++ {
				targetRots = append(targetRots, i)
			}

			b.Run("KGPlus", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ params failed:", err)
					return
				}
				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}
				eval := kgplus.NewEvaluator(params)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := eval.DeriveGaloisKeys(tk, targetRots); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Fatal(err)
				}
				kgen := llkn.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}
				eval := llkn.NewEvaluator(params)
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

// BenchmarkGenTransmissionKeys measures client-side key generation time.
func BenchmarkGenTransmissionKeys(b *testing.B) {
	for _, sc := range benchScenarios {
		if sc.LogN > 14 {
			continue
		}

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

			b.Run("KGPlus", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ params failed:", err)
					return
				}
				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := kgen.GenTransmissionKeys(sk, masterRots); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Fatal(err)
				}
				kgen := llkn.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := kgen.GenTransmissionKeys(sk, masterRots); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
