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
// Each scenario satisfies:
//   - Eval QP ≤ Q_max(N)
//   - LLKN k=2 top QP ≤ Q_max(N)
//   - KG+ k=3 top QP ≤ Q_max(2N) (R' extension ring)
var benchScenarios = []benchScenario{
	{
		// Q_max(14)=438. Eval QP=350, LLKN top=406, KG+ R' top=462≤881.
		Name: "LogN14_Q5_P2",
		LogN: 14, LogQ: buildLogQ(5, 50), LogP: []int{50, 50}, LogPHK: []int{56},
		Base:      4,
		LogPHK3:   []int{56},
		LogPExtra: []int{56},
	},
	{
		// Q_max(15)=881. Eval QP=598, LLKN top=720, KG+ R' top=1513≤1761.
		Name: "LogN15_Q10_P3",
		LogN: 15, LogQ: append([]int{55}, buildLogQ(9, 40)...), LogP: []int{61, 61, 61},
		LogPHK:    []int{61, 61},
		Base:      4,
		LogPHK3:   buildLogQ(10, 61),
		LogPExtra: buildLogQ(5, 61),
	},
	{
		// Q_max(16)=1761. Eval QP=1540, LLKN top=1760, KG+ R' top=3416≤3500.
		// Matches KG+ paper (Cheon-Kang-Park) C.ii parameter set.
		Name: "LogN16_Q24_P4",
		LogN: 16, LogQ: buildLogQ(24, 55), LogP: []int{55, 55, 55, 55},
		LogPHK:    []int{55, 55, 55, 55},
		Base:      4,
		LogPHK3:   buildLogQ(3, 57),
		LogPExtra: buildLogQ(31, 55),
	},
}

// BenchmarkKeySizes measures and reports transmission key sizes for LLKN, KG+ k=2, and KG+ k=3.
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

				kgen := llkn.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}

				tkSize := tk.BinarySize()
				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("LLKN k=2: dnum_master=%d, TX=%.1f MB (%.0f%% of conventional)",
					dnumMaster, float64(tkSize)/(1024*1024), ratio)
				b.ReportMetric(float64(tkSize)/(1024*1024), "TX_MB")
				b.ReportMetric(ratio, "vs_conv_%")
				b.ReportMetric(float64(dnumMaster), "dnum_master")
			})

			b.Run("KGPlus_k2", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ k=2 params failed:", err)
					return
				}

				topRP := params.RPrime[params.NumLevels()-1]
				dnumMaster := topRP.BaseRNSDecompositionVectorSize(
					topRP.MaxLevel(), topRP.MaxLevelP())

				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}

				tkSize := tk.BinarySize()
				ratio := float64(tkSize) / float64(conventionalBytes) * 100

				b.Logf("KG+ k=2: dnum_master=%d, TX=%.1f MB (%.0f%% of conventional)",
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

				// k=3 uses a reduced master set: {1, base}.
				// The full base-4 set is derived server-side at the intermediate level.
				k3MasterRots := []int{1, sc.Base}

				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, k3MasterRots)
				if err != nil {
					b.Fatal(err)
				}

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

			b.Run("KGPlus_k2", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ k=2 params failed:", err)
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

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}
				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				k3MasterRots := []int{1, sc.Base}
				tk, err := kgen.GenTransmissionKeys(sk, k3MasterRots)
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
				kgen := llkn.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := kgen.GenTransmissionKeys(sk, masterRots); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("KGPlus_k2", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK)
				if err != nil {
					b.Skip("KG+ k=2 params failed:", err)
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

			b.Run("KGPlus_k3", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, sc.LogPHK3, sc.LogPExtra)
				if err != nil {
					b.Skip("KG+ k=3 params failed:", err)
					return
				}
				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				k3MasterRots := []int{1, sc.Base}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if _, err := kgen.GenTransmissionKeys(sk, k3MasterRots); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}
