package llkn

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"sort"
	"sync"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/internal/testutil"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// buildParams constructs LLKN 2-level parameters from a production scenario, using the given ring type.
// Scenarios use LogNthRoot = LogN+2 (= 4N),
// which satisfies both Standard (requires 2N) and ConjugateInvariant (requires 4N) NTT root-of-unity constraints.
func buildParams(t *testing.T, sc testutil.Scenario, ringType ring.Type) Parameters {
	t.Helper()
	paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:       sc.LogN,
		LogQ:       sc.LogQ,
		LogP:       sc.LogP,
		NTTFlag:    true,
		LogNthRoot: sc.LogN + 2,
		RingType:   ringType,
	})
	require.NoError(t, err)
	params, err := NewParameters(paramsEval, [][]int{sc.LogPHK})
	require.NoError(t, err)
	return params
}

func testString(params Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/%d-level",
		opname,
		params.Eval().LogN(),
		params.Eval().QCount(),
		params.Eval().PCount(),
		params.NumLevels())
}

type testContext struct {
	params     Parameters
	kgenTop    *rlwe.KeyGenerator
	sk         *rlwe.SecretKey // at top level
	skEval     *rlwe.SecretKey // projected to eval level
	tk         *TransmissionKeys
	eval       *Evaluator
	masterRots []int
}

func newTestContext(params Parameters, masterRots []int) (*testContext, error) {
	kgenTop := rlwe.NewKeyGenerator(params.Top())
	sk := kgenTop.GenSecretKeyNew()
	skEval, err := params.ProjectToEvalKey(sk)
	if err != nil {
		return nil, err
	}

	// Generate public key
	pk := kgenTop.GenPublicKeyNew(sk)
	// Generate master rotation keys
	masterKeys := make(map[int]*hierkeys.MasterKey)
	for _, rot := range masterRots {
		galEl := params.Top().GaloisElement(rot)
		gk := kgenTop.GenGaloisKeyNew(galEl, sk)
		mk, err := hierkeys.GaloisKeyToMasterKey(params.Top(), gk)
		if err != nil {
			return nil, err
		}
		masterKeys[rot] = mk
	}
	tk := &TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}

	eval := NewEvaluator(params)

	return &testContext{
		params:     params,
		kgenTop:    kgenTop,
		sk:         sk,
		skEval:     skEval,
		tk:         tk,
		eval:       eval,
		masterRots: masterRots,
	}, nil
}

// expandAll cascades NewLevelExpansion through all levels.
// Test-internal helper used by tests that need level-0 IntermediateKeys.
func expandAll(eval *Evaluator, tk *TransmissionKeys, targetRots []int) (*hierkeys.IntermediateKeys, error) {
	k := eval.params.NumLevels()
	masterRots := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRots = append(masterRots, rot)
	}
	sort.Ints(masterRots)

	topLevel := k - 1
	currentMasters := tk.MasterRotKeys
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.Levels()[level], eval.params.Levels()[topLevel], tk.PublicKey)
		if err != nil {
			return nil, err
		}
		exp := eval.NewLevelExpansion(level, shift0Key, currentMasters, masterRots)
		nextMasters := make(map[int]*hierkeys.MasterKey, len(masterRots))
		for _, r := range masterRots {
			mk, err := exp.Derive(r)
			if err != nil {
				return nil, err
			}
			nextMasters[r] = mk
		}
		currentMasters = nextMasters
	}
	shift0Key0, err := hierkeys.PubToRot(eval.params.Levels()[0], eval.params.Levels()[topLevel], tk.PublicKey)
	if err != nil {
		return nil, err
	}
	exp := eval.NewLevelExpansion(0, shift0Key0, currentMasters, targetRots)
	result := &hierkeys.IntermediateKeys{Keys: make(map[int]*hierkeys.MasterKey, len(targetRots))}
	for _, r := range targetRots {
		mk, err := exp.Derive(r)
		if err != nil {
			return nil, err
		}
		result.Keys[r] = mk
	}
	return result, nil
}

// TestLLKN runs the unit-style test suite against the LogN=14 production scenario in both supported ring types (Standard and ConjugateInvariant).
// Production-scale smoke coverage across all scenarios lives in TestDeriveGaloisKeys.
func TestLLKN(t *testing.T) {

	fixtures := []struct {
		name   string
		params Parameters
	}{
		{"Standard", buildParams(t, testutil.Scenarios[0], ring.Standard)},
		{"ConjugateInvariant", buildParams(t, testutil.Scenarios[0], ring.ConjugateInvariant)},
	}

	for _, fix := range fixtures {
		masterRots := []int{1, 4}

		tc, err := newTestContext(fix.params, masterRots)
		require.NoError(t, err)

		for _, testSet := range []func(*testContext, *testing.T){
			testKeyGenerator,
			testDeriveGaloisKeys,
			testDeriveGaloisKeysWithEvaluator,
			testExpandAndFinalize,
			testPubToRot,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}

	testMasterRotationsForBase(t)
}

// productionScenarios returns testutil.Scenarios,
// reduced to LogN=14 only in -short mode so PR-time CI stays fast while master pushes cover all sizes.
func productionScenarios() []testutil.Scenario {
	if testing.Short() {
		return testutil.Scenarios[:1]
	}
	return testutil.Scenarios
}

// TestDeriveGaloisKeys exercises the full client/server pipeline (MasterRotationsForBase → expandAll → FinalizeKey → rotation verification) sequentially against each production scenario.
// Mirrors BenchmarkDeriveGaloisKeys.
func TestDeriveGaloisKeys(t *testing.T) {
	for _, sc := range productionScenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			params := buildParams(t, sc, ring.Standard)
			paramsEval := params.Eval()
			slots := paramsEval.N() / 2

			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := testutil.ReducedTestTargets(slots)
			t.Logf("LogN=%d, masters=%d (%v), targets=%d",
				paramsEval.LogN(), len(masterRots), masterRots, len(targetRots))

			tc, err := newTestContext(params, masterRots)
			require.NoError(t, err)

			intermediate, err := expandAll(tc.eval, tc.tk, targetRots)
			require.NoError(t, err)

			galoisKeys := make([]*rlwe.GaloisKey, 0, len(targetRots))
			for _, r := range targetRots {
				mk := intermediate.Keys[r]
				intermediate.Keys[r] = nil
				gk, err := tc.eval.FinalizeKey(mk)
				require.NoError(t, err)
				galoisKeys = append(galoisKeys, gk)
			}
			evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)

			ct := prepareTestCiphertext(t, paramsEval, tc.skEval)
			stdEval := rlwe.NewEvaluator(paramsEval, evk)
			for _, rot := range targetRots {
				verifyDeriveRotation(t, paramsEval, tc.skEval, stdEval, ct, rot, float64(1<<30))
			}
			runtime.GC()
		})
	}
}

// TestDeriveGaloisKeysConcurrent exercises LevelExpansion.Derive's thread-safety
// (sync.Once dedup, pool buffers) by deriving + finalizing targets concurrently
// across GOMAXPROCS workers. Run with -race in CI to catch regressions in the
// concurrent path.
//
// Pinned to LogN=14: the race surface is purely code-level, so larger scenarios
// add cost without adding coverage. Correctness of derived keys is verified by
// the sequential TestDeriveGaloisKeys at all scenarios; this test only asserts
// that concurrent Derive/FinalizeKey complete without error or races.
func TestDeriveGaloisKeysConcurrent(t *testing.T) {
	workers := runtime.GOMAXPROCS(0)
	sc := testutil.Scenarios[0]
	t.Run(sc.Name, func(t *testing.T) {
		params := buildParams(t, sc, ring.Standard)
		slots := params.Eval().N() / 2

		masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
		targetRots := testutil.ReducedTestTargets(slots)

		tc, err := newTestContext(params, masterRots)
		require.NoError(t, err)

		k := params.NumLevels()
		topLevel := k - 1
		currentMasters := tc.tk.MasterRotKeys
		for level := k - 2; level >= 1; level-- {
			shift0Key, err := hierkeys.PubToRot(params.Levels()[level], params.Levels()[topLevel], tc.tk.PublicKey)
			require.NoError(t, err)
			exp := tc.eval.NewLevelExpansion(level, shift0Key, currentMasters, masterRots)
			nextMasters := make(map[int]*hierkeys.MasterKey, len(masterRots))
			for _, r := range masterRots {
				mk, err := exp.Derive(r)
				require.NoError(t, err)
				nextMasters[r] = mk
			}
			currentMasters = nextMasters
		}

		shift0Key, err := hierkeys.PubToRot(params.Levels()[0], params.Levels()[topLevel], tc.tk.PublicKey)
		require.NoError(t, err)
		exp := tc.eval.NewLevelExpansion(0, shift0Key, currentMasters, targetRots)

		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		errs := make([]error, len(targetRots))
		for i, r := range targetRots {
			wg.Add(1)
			sem <- struct{}{}
			go func(i, r int) {
				defer wg.Done()
				defer func() { <-sem }()
				mk, err := exp.Derive(r)
				if err != nil {
					errs[i] = err
					return
				}
				if _, err := tc.eval.FinalizeKey(mk); err != nil {
					errs[i] = err
				}
			}(i, r)
		}
		wg.Wait()
		for i, err := range errs {
			require.NoError(t, err, "target %d", targetRots[i])
		}
		runtime.GC()
	})
}

func testKeyGenerator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "KeyGeneration"), func(t *testing.T) {

		t.Run("GenSecretKeyNew", func(t *testing.T) {
			sk := tc.kgenTop.GenSecretKeyNew()
			require.NotNil(t, sk)
			require.Equal(t, params.Top().QCount(), sk.LevelQ()+1)
			require.Equal(t, params.Top().PCount(), sk.LevelP()+1)
		})

		t.Run("ProjectToEvalKey", func(t *testing.T) {
			skEval, err := params.ProjectToEvalKey(tc.sk)
			require.NoError(t, err)
			require.NotNil(t, skEval)
			require.Equal(t, params.Eval().QCount(), skEval.LevelQ()+1)
			require.Equal(t, params.Eval().PCount(), skEval.LevelP()+1)
		})

		t.Run("TransmissionKeys", func(t *testing.T) {
			tk := tc.tk
			require.NotNil(t, tk)
			require.NotNil(t, tk.PublicKey)
			require.Len(t, tk.MasterRotKeys, len(tc.masterRots))
			for _, rot := range tc.masterRots {
				_, ok := tk.MasterRotKeys[rot]
				require.True(t, ok, "missing master key for rotation %d", rot)
			}
		})
	})
}

func testDeriveGaloisKeys(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "DeriveGaloisKeys"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}
		eval := NewEvaluator(params)
		intermediate, err := expandAll(eval, tc.tk, targetRots)
		require.NoError(t, err)
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for _, mk := range intermediate.Keys {
			gk, err := eval.FinalizeKey(mk)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.NotNil(t, evk)

		ct := prepareTestCiphertext(t, params.Eval(), tc.skEval)
		stdEval := rlwe.NewEvaluator(params.Eval(), evk)

		// Allow more noise for 3-level (2 RotToRot stages)
		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, params.Eval(), tc.skEval, stdEval, ct, rot, threshold)
		}
	})
}

func testDeriveGaloisKeysWithEvaluator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "DeriveGaloisKeys/WithEvaluator"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}
		intermediate, err := expandAll(tc.eval, tc.tk, targetRots)
		require.NoError(t, err)
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for _, mk := range intermediate.Keys {
			gk, err := tc.eval.FinalizeKey(mk)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)

		ct := prepareTestCiphertext(t, params.Eval(), tc.skEval)
		stdEval := rlwe.NewEvaluator(params.Eval(), evk)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, params.Eval(), tc.skEval, stdEval, ct, rot, threshold)
		}
	})
}

func testExpandAndFinalize(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "ExpandAndFinalize"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		// Expand (expensive)
		intermediate, err := expandAll(tc.eval, tc.tk, targetRots)
		require.NoError(t, err)
		require.Len(t, intermediate.Keys, len(targetRots))

		// Serialize + deserialize intermediate
		var buf bytes.Buffer
		_, err = intermediate.WriteTo(&buf)
		require.NoError(t, err)
		t.Logf("intermediate keys: %d bytes (%.2f KB)", buf.Len(), float64(buf.Len())/1024)

		intermediate2 := new(hierkeys.IntermediateKeys)
		_, err = intermediate2.ReadFrom(&buf)
		require.NoError(t, err)
		require.Len(t, intermediate2.Keys, len(targetRots))

		// Finalize
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate2.Keys))
		for _, mk := range intermediate2.Keys {
			gk, err := tc.eval.FinalizeKey(mk)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)

		ct := prepareTestCiphertext(t, params.Eval(), tc.skEval)
		stdEval := rlwe.NewEvaluator(params.Eval(), evk)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, params.Eval(), tc.skEval, stdEval, ct, rot, threshold)
		}
	})
}

func testPubToRot(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "PubToRot"), func(t *testing.T) {

		// The PublicKey in TransmissionKeys is at the top level.
		// PubToRot is now integrated into the pipeline,
		// so we verify that the full derive flow works with PubToRot-derived shift-0 keys at each level.
		k := params.NumLevels()
		for level := 0; level < k-1; level++ {
			t.Run(fmt.Sprintf("level=%d", level), func(t *testing.T) {

				paramsLevel := params.Levels()[level]

				// Derive shift-0 key via PubToRot
				derivedShift0, err := hierkeys.PubToRot(paramsLevel, params.Top(), tc.tk.PublicKey)
				require.NoError(t, err)
				require.NotNil(t, derivedShift0)
				require.Equal(t, uint64(1), derivedShift0.GaloisElement())

				masterRots := make([]int, 0, len(tc.tk.MasterRotKeys))
				for rot := range tc.tk.MasterRotKeys {
					masterRots = append(masterRots, rot)
				}
				sort.Ints(masterRots)

				eval := tc.eval

				// Use PubToRot-derived shift-0 key to derive rotation keys
				targetRots := []int{1, 2, 3}
				var currentMasters map[int]*hierkeys.MasterKey

				if level == k-2 {
					// Level directly below top: use top master keys
					currentMasters = tc.tk.MasterRotKeys
				} else {
					// Need to expand down from top to this level+1 first
					currentMasters = tc.tk.MasterRotKeys
					for lvl := k - 2; lvl > level; lvl-- {
						shift0, err := hierkeys.PubToRot(params.Levels()[lvl], params.Top(), tc.tk.PublicKey)
						require.NoError(t, err)
						expDown := eval.NewLevelExpansion(lvl, shift0, currentMasters, masterRots)
						nextMasters := make(map[int]*hierkeys.MasterKey, len(masterRots))
						for _, r := range masterRots {
							mk, err := expDown.Derive(r)
							require.NoError(t, err)
							nextMasters[r] = mk
						}
						currentMasters = nextMasters
					}
				}

				// Now expand at this level using the PubToRot-derived shift-0 key
				expHere := eval.NewLevelExpansion(level, derivedShift0, currentMasters, targetRots)
				intermediate := &hierkeys.IntermediateKeys{Keys: make(map[int]*hierkeys.MasterKey, len(targetRots))}
				for _, r := range targetRots {
					mk, err := expHere.Derive(r)
					require.NoError(t, err)
					intermediate.Keys[r] = mk
				}

				if level == 0 {
					// At level 0, finalize and verify with actual rotation
					galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
					for _, mk := range intermediate.Keys {
						gk, err := eval.FinalizeKey(mk)
						require.NoError(t, err)
						galoisKeys = append(galoisKeys, gk)
					}
					evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)

					ct := prepareTestCiphertext(t, params.Eval(), tc.skEval)
					stdEval := rlwe.NewEvaluator(params.Eval(), evk)

					threshold := float64(1 << 25)
					if params.NumLevels() > 2 {
						threshold = float64(1 << 35)
					}

					for _, rot := range targetRots {
						verifyDeriveRotation(t, params.Eval(), tc.skEval, stdEval, ct, rot, threshold)
					}
				} else {
					// For intermediate levels, verify the keys are non-nil
					require.NotEmpty(t, intermediate.Keys)
					for _, rot := range targetRots {
						_, ok := intermediate.Keys[rot]
						require.True(t, ok, "missing key for rotation %d", rot)
					}
				}
			})
		}
	})
}

func testMasterRotationsForBase(t *testing.T) {

	t.Run("MasterRotationsForBase", func(t *testing.T) {
		rots := hierkeys.MasterRotationsForBase(4, 32768)
		require.Equal(t, []int{1, 4, 16, 64, 256, 1024, 4096, 16384}, rots)

		rots2 := hierkeys.MasterRotationsForBase(2, 16)
		require.Equal(t, []int{1, 2, 4, 8}, rots2)

		require.Nil(t, hierkeys.MasterRotationsForBase(1, 16))
		require.Nil(t, hierkeys.MasterRotationsForBase(4, 0))

		steps := hierkeys.DecomposeRotation(7, []int{1, 4})
		require.Equal(t, []int{4, 1, 1, 1}, steps)

		steps2 := hierkeys.DecomposeRotation(21, []int{1, 4, 16})
		require.Equal(t, []int{16, 4, 1}, steps2)

		require.Nil(t, hierkeys.DecomposeRotation(0, []int{1, 4}))
		require.Nil(t, hierkeys.DecomposeRotation(5, nil))
	})
}

// prepareTestCiphertext creates a test plaintext and encrypts it.
func prepareTestCiphertext(t *testing.T, paramsEval rlwe.Parameters, skEval *rlwe.SecretKey) *rlwe.Ciphertext {
	t.Helper()

	ringQ := paramsEval.RingQ()
	encR := rlwe.NewEncryptor(paramsEval, skEval)

	pt := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
	for m := range pt.Value.Coeffs {
		for k := range pt.Value.Coeffs[m] {
			pt.Value.Coeffs[m][k] = 0
		}
		pt.Value.Coeffs[m][0] = 42
		pt.Value.Coeffs[m][1] = 7
	}
	ringQ.NTT(pt.Value, pt.Value)
	pt.IsNTT = true

	ct := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
	require.NoError(t, encR.Encrypt(pt, ct))

	return ct
}

type automorphEvaluator interface {
	Automorphism(ctIn *rlwe.Ciphertext, galEl uint64, opOut *rlwe.Ciphertext) error
}

// verifyDeriveRotation compares automorphism output from the given evaluator against a reference automorphism computed using lattigo's own GenGaloisKeyNew.
func verifyDeriveRotation(
	t *testing.T,
	paramsEval rlwe.Parameters,
	skEval *rlwe.SecretKey,
	derivedEval automorphEvaluator,
	ct *rlwe.Ciphertext,
	rot int,
	noiseThreshold float64,
) {
	t.Helper()

	ringQ := paramsEval.RingQ()
	decR := rlwe.NewDecryptor(paramsEval, skEval)

	galEl := paramsEval.GaloisElement(rot)

	// Reference: use lattigo's own GaloisKey and Automorphism
	kgenEval := rlwe.NewKeyGenerator(paramsEval)
	refGK := kgenEval.GenGaloisKeyNew(galEl, skEval)
	evkRef := rlwe.NewMemEvaluationKeySet(nil, refGK)
	evalRef := rlwe.NewEvaluator(paramsEval, evkRef)

	ctRef := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
	require.NoError(t, evalRef.Automorphism(ct, galEl, ctRef))
	ptRef := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
	decR.Decrypt(ctRef, ptRef)
	ringQ.INTT(ptRef.Value, ptRef.Value)

	// Derived
	ctDerived := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
	require.NoError(t, derivedEval.Automorphism(ct, galEl, ctDerived))
	ptDerived := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
	decR.Decrypt(ctDerived, ptDerived)
	ringQ.INTT(ptDerived.Value, ptDerived.Value)

	q0 := paramsEval.Q()[0]
	maxDiff := 0.0
	for k := 0; k < 5; k++ {
		refS := int64(ptRef.Value.Coeffs[0][k])
		if ptRef.Value.Coeffs[0][k] > q0/2 {
			refS -= int64(q0)
		}
		derS := int64(ptDerived.Value.Coeffs[0][k])
		if ptDerived.Value.Coeffs[0][k] > q0/2 {
			derS -= int64(q0)
		}
		diff := math.Abs(float64(refS - derS))
		if diff > maxDiff {
			maxDiff = diff
		}
	}

	log2Noise := math.Log2(maxDiff + 1)
	t.Logf("rotation %d: maxDiff=%.0f (log2=%.1f)", rot, maxDiff, log2Noise)
	require.Less(t, maxDiff, noiseThreshold,
		"rotation %d: derived key noise too high (maxDiff=%.0f, threshold=%.0f)",
		rot, maxDiff, noiseThreshold)
}
