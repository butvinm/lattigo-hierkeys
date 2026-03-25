package hierkeys_test

import (
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
	LogPHK []int // Homing key / master P prime bit-sizes
	Base   int   // master rotation base
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
		Name: "LogN10_Q5_P1",
		LogN: 10, LogQ: buildLogQ(5, 55), LogP: []int{56}, LogPHK: []int{56},
		Base: 4,
	},
	{
		Name: "LogN12_Q8_P2",
		LogN: 12, LogQ: buildLogQ(8, 55), LogP: []int{56, 56}, LogPHK: []int{56},
		Base: 4,
	},
	{
		Name: "LogN14_Q14_P3",
		LogN: 14, LogQ: buildLogQ(14, 55), LogP: []int{56, 56, 56}, LogPHK: []int{56},
		Base: 4,
	},
	{
		Name: "LogN15_Q22_P5",
		LogN: 15, LogQ: buildLogQ(22, 55), LogP: []int{56, 56, 56, 56, 56}, LogPHK: []int{56, 56, 56, 56, 56},
		Base: 4,
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
			targetRots := make([]int, 0, benchNTargets)
			for i := 1; i <= benchNTargets && i < slots; i++ {
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
			targetRots := make([]int, 0, benchNTargets)
			for i := 1; i <= benchNTargets && i < slots; i++ {
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
