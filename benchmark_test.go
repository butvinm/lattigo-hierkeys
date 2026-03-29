package hierkeys_test

import (
	"runtime"
	"sync"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// Realistic sparse target rotation sets mimicking FHE workloads:
// small positives (BSGS), powers of 2 (bootstrapping), convolution strides,
// negative rotations (values near N/2). 256 targets spread across [1, N/2].
var sparseTargets14 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 54, 64, 90, 96, 128, 160, 180, 192, 205, 218, 224, 245, 256, 261, 263, 270, 288, 320, 356, 360, 376, 384, 448, 450, 459, 512, 540, 570, 576, 585, 630, 640, 646, 654, 713, 720, 760, 768, 793, 810, 828, 838, 840, 896, 900, 913, 990, 1023, 1024, 1080, 1144, 1152, 1170, 1260, 1274, 1280, 1308, 1333, 1339, 1350, 1402, 1440, 1530, 1536, 1576, 1620, 1629, 1710, 1717, 1764, 1792, 1800, 1806, 1829, 1867, 1877, 1906, 1908, 2006, 2007, 2048, 2167, 2188, 2194, 2212, 2254, 2277, 2278, 2279, 2304, 2371, 2402, 2560, 2585, 2657, 2758, 2788, 2818, 2911, 2941, 2963, 2989, 3033, 3072, 3101, 3109, 3113, 3114, 3287, 3437, 3457, 3463, 3584, 3680, 3715, 3764, 3787, 4096, 4140, 4376, 4393, 4465, 4468, 4523, 4563, 4598, 4608, 4730, 4828, 4838, 4932, 4946, 4991, 5067, 5120, 5150, 5202, 5208, 5239, 5243, 5309, 5324, 5418, 5491, 5544, 5600, 5609, 5638, 5720, 5746, 5750, 5772, 5866, 5974, 5978, 6034, 6068, 6075, 6144, 6217, 6255, 6295, 6333, 6357, 6595, 6602, 6612, 6631, 6733, 6795, 6834, 6905, 6943, 7007, 7060, 7099, 7122, 7168, 7254, 7309, 7556, 7581, 7674, 7842, 7972, 8071, 8107, 8143, 8144, 8145, 8146, 8147, 8148, 8149, 8150, 8151, 8152, 8153, 8154, 8155, 8156, 8157, 8158, 8159, 8160, 8161, 8162, 8163, 8164, 8165, 8166, 8167, 8168, 8169, 8170, 8171, 8172, 8173, 8174, 8175, 8176, 8177, 8178, 8179, 8180, 8181, 8182, 8183, 8184, 8185, 8186, 8187, 8188, 8189, 8190, 8191}

var sparseTargets15 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 64, 96, 107, 128, 160, 192, 224, 256, 288, 320, 384, 410, 435, 448, 489, 512, 521, 526, 576, 640, 712, 751, 768, 896, 917, 1024, 1085, 1140, 1152, 1170, 1280, 1292, 1308, 1408, 1425, 1520, 1536, 1585, 1655, 1664, 1675, 1680, 1792, 1825, 1920, 2046, 2048, 2176, 2287, 2304, 2432, 2548, 2560, 2616, 2665, 2678, 2804, 3072, 3151, 3258, 3433, 3457, 3484, 3528, 3583, 3584, 3599, 3612, 3658, 3734, 3753, 3812, 3815, 4011, 4013, 4096, 4334, 4375, 4387, 4423, 4507, 4553, 4555, 4558, 4608, 4742, 4804, 5120, 5156, 5169, 5314, 5515, 5575, 5636, 5821, 5882, 5926, 5978, 6066, 6144, 6202, 6217, 6225, 6228, 6573, 6874, 6913, 6925, 7168, 7360, 7429, 7528, 7574, 8180, 8192, 8280, 8752, 8786, 8929, 8936, 9045, 9126, 9196, 9216, 9293, 9460, 9655, 9675, 9864, 9892, 9981, 10134, 10300, 10404, 10416, 10477, 10486, 10618, 10648, 10739, 10835, 10981, 11088, 11200, 11217, 11275, 11439, 11491, 11499, 11544, 11732, 11763, 11947, 11956, 12067, 12136, 12150, 12433, 12510, 12589, 12666, 12714, 13190, 13203, 13224, 13262, 13465, 13589, 13667, 13810, 13886, 14014, 14119, 14197, 14243, 14359, 14508, 14618, 14961, 15111, 15162, 15347, 15449, 15683, 15944, 16142, 16213, 16335, 16336, 16337, 16338, 16339, 16340, 16341, 16342, 16343, 16344, 16345, 16346, 16347, 16348, 16349, 16350, 16351, 16352, 16353, 16354, 16355, 16356, 16357, 16358, 16359, 16360, 16361, 16362, 16363, 16364, 16365, 16366, 16367, 16368, 16369, 16370, 16371, 16372, 16373, 16374, 16375, 16376, 16377, 16378, 16379, 16380, 16381, 16382, 16383}

var sparseTargets16 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 64, 96, 128, 160, 181, 192, 213, 224, 256, 288, 320, 362, 384, 448, 512, 543, 576, 640, 724, 768, 820, 870, 896, 905, 977, 1024, 1042, 1086, 1152, 1267, 1280, 1424, 1448, 1502, 1536, 1629, 1792, 1810, 1833, 1991, 2048, 2172, 2280, 2304, 2340, 2353, 2534, 2560, 2583, 2615, 2715, 2849, 2896, 3040, 3071, 3072, 3077, 3170, 3258, 3310, 3350, 3359, 3439, 3584, 3649, 4091, 4096, 4573, 4608, 5095, 5120, 5232, 5330, 5355, 5608, 6144, 6301, 6516, 6866, 7056, 7165, 7168, 7197, 7224, 7315, 7468, 7506, 7624, 7629, 8022, 8025, 8192, 8668, 8749, 8846, 9013, 9106, 9109, 9116, 9216, 9483, 9607, 10627, 11030, 11150, 11271, 11642, 11764, 11851, 11955, 12131, 12404, 12434, 12450, 12456, 13747, 13826, 13849, 14720, 14858, 15055, 15148, 16384, 16560, 17503, 17572, 17857, 17871, 18090, 18251, 18391, 18919, 19310, 19350, 19727, 19783, 19961, 20268, 20600, 20807, 20831, 20953, 20972, 21235, 21296, 21669, 21961, 22175, 22399, 22434, 22550, 22877, 22982, 22998, 23088, 23463, 23893, 23912, 24133, 24271, 24300, 24865, 25019, 25177, 25332, 25428, 26406, 26448, 26524, 26929, 27178, 27333, 27619, 27771, 28028, 28237, 28393, 28486, 29015, 29235, 30222, 30324, 30693, 31366, 31888, 32284, 32425, 32719, 32720, 32721, 32722, 32723, 32724, 32725, 32726, 32727, 32728, 32729, 32730, 32731, 32732, 32733, 32734, 32735, 32736, 32737, 32738, 32739, 32740, 32741, 32742, 32743, 32744, 32745, 32746, 32747, 32748, 32749, 32750, 32751, 32752, 32753, 32754, 32755, 32756, 32757, 32758, 32759, 32760, 32761, 32762, 32763, 32764, 32765, 32766, 32767}

// benchTargetRots returns the sparse target set for the given LogN.
func benchTargetRots(logN int) []int {
	switch logN {
	case 14:
		return sparseTargets14
	case 15:
		return sparseTargets15
	case 16:
		return sparseTargets16
	default:
		return sparseTargets14
	}
}

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
			targetRots := benchTargetRots(sc.LogN)

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
			targetRots := benchTargetRots(sc.LogN)

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
			targetRots := benchTargetRots(sc.LogN)

			b.Run("LLKN", func(b *testing.B) {
				params, err := llkn.NewParameters(paramsEval, [][]int{sc.LogPHK})
				if err != nil {
					b.Fatal(err)
				}
				tk := genLLKNTransmissionKeys(b, params, masterRots)
				eval := llkn.NewEvaluator(params)
				topLevel := params.NumLevels() - 1

				runtime.GC()
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

				runtime.GC()
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
