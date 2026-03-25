package hierkeys_test

import (
	"fmt"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// NTT-friendly 61-bit primes for N up to 2^17 (q ≡ 1 mod 2^18).
var benchQi = []uint64{
	0x1fffffffffe00001, 0x1fffffffffc80001, 0x1fffffffffb40001,
	0x1fffffffff500001, 0x1fffffffff380001, 0x1fffffffff000001,
	0x1ffffffffef00001, 0x1ffffffffee80001, 0x1ffffffffeb40001,
	0x1ffffffffe780001, 0x1ffffffffe600001, 0x1ffffffffe480001,
}

var benchPi = []uint64{
	0x1ffffffff6c80001,
	0x1ffffffff6140001,
}

type benchScenario struct {
	Name string
	LogN int
	NQ   int // number of Q primes
	NP   int // number of P primes
	Base int // master rotation base
}

var benchScenarios = []benchScenario{
	{"Small", 10, 5, 1, 4},
	{"Medium", 12, 7, 1, 4},
	{"Large", 14, 10, 1, 4},
}

// BenchmarkKeySizes prints key sizes for both schemes across scenarios.
// Run with: go test -bench BenchmarkKeySizes -benchtime 1x -v ./...
func BenchmarkKeySizes(b *testing.B) {
	for _, sc := range benchScenarios {
		b.Run(sc.Name, func(b *testing.B) {
			paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
				LogN:    sc.LogN,
				Q:       benchQi[:sc.NQ],
				P:       benchPi[:sc.NP],
				NTTFlag: true,
			})
			if err != nil {
				b.Fatal(err)
			}

			slots := paramsEval.N() / 2
			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			nTargets := len(masterRots) * (sc.Base - 1) // approximate number of derivable rotations

			b.Run("KGPlus", func(b *testing.B) {
				params, err := kgplus.NewParameters(paramsEval, []int{61})
				if err != nil {
					b.Fatal(err)
				}
				kgen := kgplus.NewKeyGenerator(params)
				sk := kgen.GenSecretKeyNew()
				tk, err := kgen.GenTransmissionKeys(sk, masterRots)
				if err != nil {
					b.Fatal(err)
				}

				tkSize := tk.BinarySize()
				b.ReportMetric(float64(tkSize)/(1024*1024), "TransmissionMB")
				b.ReportMetric(float64(len(masterRots)), "MasterKeys")
				b.ReportMetric(float64(nTargets), "DerivableRotations")

				// Also measure a single standard GaloisKey for comparison
				kgenEval := rlwe.NewKeyGenerator(paramsEval)
				skEval := kgen.ProjectToEvalKey(sk)
				refGK := kgenEval.GenGaloisKeyNew(paramsEval.GaloisElement(1), skEval)
				stdKeySize := refGK.BinarySize()
				conventionalTotal := float64(stdKeySize) * float64(nTargets) / (1024 * 1024)
				b.ReportMetric(conventionalTotal, "ConventionalMB")
				b.ReportMetric(float64(tkSize)/float64(stdKeySize*nTargets)*100, "Ratio%")
			})

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, []int{61})
				if err != nil {
					b.Fatal(err)
				}
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
				tkSize += 8 // count
				for _, gk := range tk.MasterRotKeys {
					tkSize += 8 + gk.BinarySize()
				}

				b.ReportMetric(float64(tkSize)/(1024*1024), "TransmissionMB")
				b.ReportMetric(float64(len(masterRots)), "MasterKeys")
				b.ReportMetric(float64(nTargets), "DerivableRotations")

				kgenEval := rlwe.NewKeyGenerator(paramsEval)
				skEval := kgen.ProjectToEvalKey(sk)
				refGK := kgenEval.GenGaloisKeyNew(paramsEval.GaloisElement(1), skEval)
				stdKeySize := refGK.BinarySize()
				conventionalTotal := float64(stdKeySize) * float64(nTargets) / (1024 * 1024)
				b.ReportMetric(conventionalTotal, "ConventionalMB")
				b.ReportMetric(float64(tkSize)/float64(stdKeySize*nTargets)*100, "Ratio%")
			})
		})
	}
}

// BenchmarkGenTransmissionKeys measures client-side key generation time.
func BenchmarkGenTransmissionKeys(b *testing.B) {
	for _, sc := range benchScenarios {
		if sc.LogN > 12 {
			continue // skip large for speed
		}
		paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:    sc.LogN,
			Q:       benchQi[:sc.NQ],
			P:       benchPi[:sc.NP],
			NTTFlag: true,
		})
		if err != nil {
			b.Fatal(err)
		}

		slots := paramsEval.N() / 2
		masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)

		b.Run(fmt.Sprintf("%s/KGPlus", sc.Name), func(b *testing.B) {
			params, err := kgplus.NewParameters(paramsEval, []int{61})
			if err != nil {
				b.Fatal(err)
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

		b.Run(fmt.Sprintf("%s/LLKN", sc.Name), func(b *testing.B) {
			params, err := llkn.NewParameters(paramsEval, []int{61})
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
	}
}

// BenchmarkDeriveGaloisKeys measures server-side key derivation time.
func BenchmarkDeriveGaloisKeys(b *testing.B) {
	for _, sc := range benchScenarios {
		if sc.LogN > 12 {
			continue
		}
		paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:    sc.LogN,
			Q:       benchQi[:sc.NQ],
			P:       benchPi[:sc.NP],
			NTTFlag: true,
		})
		if err != nil {
			b.Fatal(err)
		}

		slots := paramsEval.N() / 2
		masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
		// Derive a reasonable set of target rotations
		targetRots := make([]int, 0)
		for i := 1; i <= 20 && i < slots; i++ {
			targetRots = append(targetRots, i)
		}

		b.Run(fmt.Sprintf("%s/KGPlus", sc.Name), func(b *testing.B) {
			params, err := kgplus.NewParameters(paramsEval, []int{61})
			if err != nil {
				b.Fatal(err)
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

		b.Run(fmt.Sprintf("%s/LLKN", sc.Name), func(b *testing.B) {
			params, err := llkn.NewParameters(paramsEval, []int{61})
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
	}
}
