package kgplus

import (
	"bytes"
	"fmt"
	"math"
	"math/cmplx"
	"runtime"
	"sort"
	"sync"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/internal/testutil"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

// buildParams constructs KG+ 3-level parameters from a production scenario.
func buildParams(t *testing.T, sc testutil.Scenario) Parameters {
	t.Helper()
	paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
		LogN:       sc.LogN,
		LogQ:       sc.LogQ,
		LogP:       sc.LogP,
		NTTFlag:    true,
		LogNthRoot: sc.LogN + 2,
	})
	require.NoError(t, err)
	params, err := NewParameters(paramsEval, sc.LogPHK3, [][]int{sc.LogPExtra})
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
	sk         *rlwe.SecretKey // at HK level
	skEval     *rlwe.SecretKey // projected to eval level
	tk         *TransmissionKeys
	hkEval     *Evaluator
	masterRots []int
}

func newTestContext(params Parameters, masterRots []int) (*testContext, error) {
	kgenHK := rlwe.NewKeyGenerator(params.HomingKey())

	sk := kgenHK.GenSecretKeyNew()
	skEval, err := params.ProjectToEvalKey(sk)
	if err != nil {
		return nil, err
	}

	// Build transmission keys manually
	sk1 := kgenHK.GenSecretKeyNew()
	homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

	topParams := params.Top()
	skExt := ConstructExtendedSecretKey(params.HomingKey(), topParams, sk, sk1)

	pk := rlwe.NewKeyGenerator(topParams).GenPublicKeyNew(skExt)

	kgenRP := rlwe.NewKeyGenerator(topParams)
	masterKeys := make(map[int]*hierkeys.MasterKey)
	for _, rot := range masterRots {
		galEl := topParams.GaloisElement(rot)
		gk := kgenRP.GenGaloisKeyNew(galEl, skExt)
		mk, err := hierkeys.GaloisKeyToMasterKey(topParams, gk)
		if err != nil {
			return nil, err
		}
		masterKeys[rot] = mk
	}

	tk := &TransmissionKeys{
		HomingKey:     homingKey,
		PublicKey:     pk,
		MasterRotKeys: masterKeys,
	}

	hkEval := NewEvaluator(params)

	return &testContext{
		params:     params,
		sk:         sk,
		skEval:     skEval,
		tk:         tk,
		hkEval:     hkEval,
		masterRots: masterRots,
	}, nil
}

// expandAll cascades NewLevelExpansion through all levels. Test-internal
// helper used by tests that need level-0 IntermediateKeys.
func expandAll(eval *Evaluator, tk *TransmissionKeys, targetRots []int) (*hierkeys.IntermediateKeys, error) {
	k := eval.params.NumLevels()
	masterRots := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRots = append(masterRots, rot)
	}
	sort.Ints(masterRots)

	currentMasters := tk.MasterRotKeys
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.Levels()[level], eval.params.Top(), tk.PublicKey)
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
	shift0Key0, err := hierkeys.PubToRot(eval.params.Levels()[0], eval.params.Top(), tk.PublicKey)
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

// TestKGPlus runs the unit-style test suite against the LogN=14 production
// scenario. Production-scale smoke coverage across all scenarios lives in
// TestDeriveGaloisKeysProduction.
func TestKGPlus(t *testing.T) {

	params := buildParams(t, testutil.Scenarios[0])

	// Master rotations: {1, 4} — enough to derive targets {1,2,3,4,5}
	masterRots := []int{1, 4}

	tc, err := newTestContext(params, masterRots)
	require.NoError(t, err)

	for _, testSet := range []func(*testContext, *testing.T){
		testKeyGenerator,
		testRotToRot,
		testRotToRotMultiStep,
		testDeriveGaloisKeys,
		testDeriveGaloisKeysWithEvaluator,
		testExpandAndFinalize,
		testIntermediateKeyReuse,
		testSerialization,
		testCKKSRotation,
	} {
		testSet(tc, t)
		runtime.GC()
	}

	testMasterRotationsForBase(t)
}

// testKeyGenerator tests secret key generation, ProjectToEvalKey, and transmission key construction.
func testKeyGenerator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "KeyGenerator"), func(t *testing.T) {

		t.Run("GenSecretKeyNew", func(t *testing.T) {
			kgenHK := rlwe.NewKeyGenerator(params.HomingKey())
			sk := kgenHK.GenSecretKeyNew()
			require.NotNil(t, sk)
			// Key should have HK-level Q primes (Q_eval + P_eval)
			require.Equal(t, params.HomingKey().QCount()-1, sk.LevelQ())
			require.Equal(t, params.HomingKey().PCount()-1, sk.LevelP())
		})

		t.Run("ProjectToEvalKey", func(t *testing.T) {
			skEval, err := params.ProjectToEvalKey(tc.sk)
			require.NoError(t, err)
			require.NotNil(t, skEval)
			require.Equal(t, params.Eval().QCount()-1, skEval.LevelQ())
			require.Equal(t, params.Eval().PCount()-1, skEval.LevelP())
		})

		t.Run("TransmissionKeys", func(t *testing.T) {
			tk := tc.tk
			require.NotNil(t, tk.HomingKey)
			require.NotNil(t, tk.PublicKey)
			require.Equal(t, len(tc.masterRots), len(tk.MasterRotKeys))
			for _, rot := range tc.masterRots {
				_, ok := tk.MasterRotKeys[rot]
				require.True(t, ok, "missing master key for rotation %d", rot)
			}
		})
	})
}

// constructExtendedSKForParams builds s_tilde = s + Y*s1 in R' for a specific
// R' parameter set. This is a test helper that generalizes the KeyGenerator's
// constructExtendedSK to work with arbitrary R' params.
// constructExtendedSKForParams delegates to the exported ConstructExtendedSecretKey.
func constructExtendedSKForParams(
	paramsHK rlwe.Parameters,
	paramsRP rlwe.Parameters,
	skS, skS1 *rlwe.SecretKey,
) *rlwe.SecretKey {
	return ConstructExtendedSecretKey(paramsHK, paramsRP, skS, skS1)
}

// verifyRotationKey verifies a derived GaloisKey against a reference key
// generated directly from the secret key.
func verifyRotationKey(
	t *testing.T,
	paramsEval rlwe.Parameters,
	paramsHK rlwe.Parameters,
	skHK *rlwe.SecretKey,
	derivedGK *rlwe.GaloisKey,
	rot int,
	noiseThreshold float64,
) {
	t.Helper()

	skEval := rlwe.NewSecretKey(paramsEval)
	for m := 0; m <= paramsEval.MaxLevel(); m++ {
		copy(skEval.Value.Q.Coeffs[m], skHK.Value.Q.Coeffs[m])
	}
	for m := 0; m <= paramsEval.MaxLevelP(); m++ {
		copy(skEval.Value.P.Coeffs[m], skHK.Value.Q.Coeffs[paramsEval.QCount()+m])
	}

	galElR := paramsEval.GaloisElement(rot)

	// Reference key
	kgenEval := rlwe.NewKeyGenerator(paramsEval)
	refGK := kgenEval.GenGaloisKeyNew(galElR, skEval)

	ringQ := paramsEval.RingQ()
	encR := rlwe.NewEncryptor(paramsEval, skEval)
	decR := rlwe.NewDecryptor(paramsEval, skEval)

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

	// Reference automorphism
	evkRef := rlwe.NewMemEvaluationKeySet(nil, refGK)
	evalRef := rlwe.NewEvaluator(paramsEval, evkRef)
	ctRef := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
	require.NoError(t, evalRef.Automorphism(ct, galElR, ctRef))
	ptRef := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
	decR.Decrypt(ctRef, ptRef)
	ringQ.INTT(ptRef.Value, ptRef.Value)

	// Derived automorphism
	evkDerived := rlwe.NewMemEvaluationKeySet(nil, derivedGK)
	evalDerived := rlwe.NewEvaluator(paramsEval, evkDerived)
	ctDerived := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
	require.NoError(t, evalDerived.Automorphism(ct, galElR, ctDerived))
	ptDerived := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
	decR.Decrypt(ctDerived, ptDerived)
	ringQ.INTT(ptDerived.Value, ptDerived.Value)

	// Measure noise as max coefficient difference
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

	// Use log2 of the noise for reporting, consistent with lattigo style
	log2Noise := math.Log2(maxDiff + 1)
	t.Logf("rotation %d: maxDiff=%.0f (log2=%.1f)", rot, maxDiff, log2Noise)
	require.Less(t, maxDiff, noiseThreshold,
		"rotation %d: derived key noise too high (maxDiff=%.0f, threshold=%.0f)",
		rot, maxDiff, noiseThreshold)
}

// testRotToRot tests the RotToRot algorithm: combining a shift-0 level-0 key
// with a master rotation key to produce a level-0 rotation key, then ring-switching
// to R and verifying against a standard reference key.
func testRotToRot(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "RotToRot/SingleStep"), func(t *testing.T) {

		paramsEval := params.Eval()
		paramsRPLow := params.Levels()[0]
		paramsRPHigh := params.Levels()[1]
		paramsHK := params.HomingKey()

		kgenHK := rlwe.NewKeyGenerator(paramsHK)
		kgenRPLow := rlwe.NewKeyGenerator(paramsRPLow)
		kgenRPHigh := rlwe.NewKeyGenerator(paramsRPHigh)

		skS := kgenHK.GenSecretKeyNew()
		skS1 := kgenHK.GenSecretKeyNew()

		skTildeLow := constructExtendedSKForParams(paramsHK, paramsRPLow, skS, skS1)
		skTildeHigh := constructExtendedSKForParams(paramsHK, paramsRPHigh, skS, skS1)

		homingKey := kgenHK.GenEvaluationKeyNew(skS1, skS)

		// Shift-0 key at level-0 in R'
		shift0EK := kgenRPLow.GenEvaluationKeyNew(skTildeLow, skTildeLow)
		shift0Key := hierkeys.NewMasterKey(&rlwe.GaloisKey{
			EvaluationKey: *shift0EK,
			GaloisElement: 1,
			NthRoot:       paramsRPLow.RingQ().NthRoot(),
		})

		// Master key for rotation 1 at master level
		rot := 1
		galElRPHigh := paramsRPHigh.GaloisElement(rot)

		skTildeHighAut := rlwe.NewSecretKey(paramsRPHigh)
		autIdx, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galElRPHigh)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, autIdx, skTildeHighAut.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, autIdx, skTildeHighAut.Value.P)

		masterEK := kgenRPHigh.GenEvaluationKeyNew(skTildeHighAut, skTildeHigh)
		masterKey := hierkeys.NewMasterKey(&rlwe.GaloisKey{
			EvaluationKey: *masterEK,
			GaloisElement: galElRPHigh,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		})

		// RotToRot: shift0 + master -> rotation key at level-0
		galElRPLow := paramsRPLow.GaloisElement(rot)
		rotKey, err := tc.hkEval.RotToRot(0, shift0Key, masterKey, galElRPLow)
		require.NoError(t, err)

		// Ring-switch from R' to R
		galElR := paramsEval.GaloisElement(rot)
		rsGK, err := tc.hkEval.RingSwitchGaloisKey(rotKey, homingKey, galElR)
		require.NoError(t, err)

		rsGKConverted, err := hierkeys.MasterKeyToGaloisKey(paramsEval, hierkeys.NewMasterKey(rsGK))
		require.NoError(t, err)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGKConverted, rot, threshold)
	})
}

// testRotToRotMultiStep tests composing RotToRot twice:
// shift0 + master(1) -> rot-1, then rot-1 + master(4) -> rot-5.
func testRotToRotMultiStep(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "RotToRot/MultiStep"), func(t *testing.T) {

		paramsEval := params.Eval()
		paramsRPLow := params.Levels()[0]
		paramsRPHigh := params.Levels()[1]
		paramsHK := params.HomingKey()

		kgenHK := rlwe.NewKeyGenerator(paramsHK)
		kgenRPLow := rlwe.NewKeyGenerator(paramsRPLow)
		kgenRPHigh := rlwe.NewKeyGenerator(paramsRPHigh)

		skS := kgenHK.GenSecretKeyNew()
		skS1 := kgenHK.GenSecretKeyNew()

		skTildeLow := constructExtendedSKForParams(paramsHK, paramsRPLow, skS, skS1)
		skTildeHigh := constructExtendedSKForParams(paramsHK, paramsRPHigh, skS, skS1)

		homingKey := kgenHK.GenEvaluationKeyNew(skS1, skS)

		shift0EK := kgenRPLow.GenEvaluationKeyNew(skTildeLow, skTildeLow)
		shift0Key := hierkeys.NewMasterKey(&rlwe.GaloisKey{
			EvaluationKey: *shift0EK,
			GaloisElement: 1,
			NthRoot:       paramsRPLow.RingQ().NthRoot(),
		})

		// Master key for rotation 1
		rot1 := 1
		galEl1High := paramsRPHigh.GaloisElement(rot1)
		skAut1 := rlwe.NewSecretKey(paramsRPHigh)
		idx1, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galEl1High)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, idx1, skAut1.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, idx1, skAut1.Value.P)
		master1EK := kgenRPHigh.GenEvaluationKeyNew(skAut1, skTildeHigh)
		masterKey1 := hierkeys.NewMasterKey(&rlwe.GaloisKey{
			EvaluationKey: *master1EK,
			GaloisElement: galEl1High,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		})

		// Master key for rotation 4
		rot4 := 4
		galEl4High := paramsRPHigh.GaloisElement(rot4)
		skAut4 := rlwe.NewSecretKey(paramsRPHigh)
		idx4, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galEl4High)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, idx4, skAut4.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, idx4, skAut4.Value.P)
		master4EK := kgenRPHigh.GenEvaluationKeyNew(skAut4, skTildeHigh)
		masterKey4 := hierkeys.NewMasterKey(&rlwe.GaloisKey{
			EvaluationKey: *master4EK,
			GaloisElement: galEl4High,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		})

		// Step 1: shift0 + master(1) -> rot-1
		galEl1Low := paramsRPLow.GaloisElement(rot1)
		rot1Key, err := tc.hkEval.RotToRot(0, shift0Key, masterKey1, galEl1Low)
		require.NoError(t, err)

		// Step 2: rot-1 + master(4) -> rot-5
		rot5 := rot1 + rot4
		galEl5Low := paramsRPLow.GaloisElement(rot5)
		rot5Key, err := tc.hkEval.RotToRot(0, rot1Key, masterKey4, galEl5Low)
		require.NoError(t, err)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		// Ring-switch and verify rot-1
		galElR1 := paramsEval.GaloisElement(rot1)
		rsGK1, err := tc.hkEval.RingSwitchGaloisKey(rot1Key, homingKey, galElR1)
		require.NoError(t, err)
		rsGK1Converted, err := hierkeys.MasterKeyToGaloisKey(paramsEval, hierkeys.NewMasterKey(rsGK1))
		require.NoError(t, err)
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGK1Converted, rot1, threshold)

		// Ring-switch and verify rot-5
		galElR5 := paramsEval.GaloisElement(rot5)
		rsGK5, err := tc.hkEval.RingSwitchGaloisKey(rot5Key, homingKey, galElR5)
		require.NoError(t, err)
		rsGK5Converted, err := hierkeys.MasterKeyToGaloisKey(paramsEval, hierkeys.NewMasterKey(rsGK5))
		require.NoError(t, err)
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGK5Converted, rot5, threshold)
	})
}

// verifyDeriveRotation is a helper that compares a derived Galois key rotation
// against a reference key generated directly from the eval secret key.
func verifyDeriveRotation(
	t *testing.T,
	paramsEval rlwe.Parameters,
	skEval *rlwe.SecretKey,
	eval *rlwe.Evaluator,
	ct *rlwe.Ciphertext,
	rot int,
	noiseThreshold float64,
) {
	t.Helper()

	ringQ := paramsEval.RingQ()
	decR := rlwe.NewDecryptor(paramsEval, skEval)

	galEl := paramsEval.GaloisElement(rot)

	// Reference
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
	require.NoError(t, eval.Automorphism(ct, galEl, ctDerived))
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

// testDeriveGaloisKeys tests the full production API end-to-end:
// NewParameters -> KeyGenerator -> TransmissionKeys -> NewLevelExpansion -> Derive -> FinalizeKey -> standard Automorphism.
func testDeriveGaloisKeys(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "DeriveGaloisKeys"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
		require.NoError(t, err)
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for r, mk := range intermediate.Keys {
			intermediate.Keys[r] = nil
			gk, err := tc.hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		paramsEval := params.Eval()
		eval := rlwe.NewEvaluator(paramsEval, evk)
		ct := prepareTestCiphertext(t, paramsEval, tc.skEval)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, paramsEval, tc.skEval, eval, ct, rot, threshold)
		}
	})
}

// testDeriveGaloisKeysWithEvaluator tests the same end-to-end flow but uses
// a pre-allocated hierkeys.Evaluator instead of the convenience function.
func testDeriveGaloisKeysWithEvaluator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "DeriveGaloisKeys/WithEvaluator"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
		require.NoError(t, err)
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for r, mk := range intermediate.Keys {
			intermediate.Keys[r] = nil
			gk, err := tc.hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		paramsEval := params.Eval()
		eval := rlwe.NewEvaluator(paramsEval, evk)
		ct := prepareTestCiphertext(t, paramsEval, tc.skEval)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, paramsEval, tc.skEval, eval, ct, rot, threshold)
		}
	})
}

// testExpandAndFinalize verifies the two-phase approach (Expand +
// FinalizeKeys) produces correct rotation keys end-to-end.
func testExpandAndFinalize(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "ExpandAndFinalize"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		// Two-phase approach
		intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
		require.NoError(t, err)
		require.Equal(t, len(targetRots), len(intermediate.Keys))

		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for r, mk := range intermediate.Keys {
			intermediate.Keys[r] = nil
			gk, err := tc.hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		// Verify each rotation works correctly
		paramsEval := params.Eval()
		eval := rlwe.NewEvaluator(paramsEval, evk)
		ct := prepareTestCiphertext(t, paramsEval, tc.skEval)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			verifyDeriveRotation(t, paramsEval, tc.skEval, eval, ct, rot, threshold)
		}
	})
}

// testIntermediateKeyReuse verifies that caching in Expand works
// correctly: deriving {1,2,3,4,5} in one call should produce valid keys,
// and intermediate keys for shared prefixes should be computed once.
func testIntermediateKeyReuse(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "IntermediateKeyReuse"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		// Derive all at once (with caching)
		intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
		require.NoError(t, err)

		// Verify all requested keys are present
		for _, rot := range targetRots {
			_, ok := intermediate.Keys[rot]
			require.True(t, ok, "missing intermediate key for rotation %d", rot)
		}

		// Derive each individually and verify functional equivalence:
		// both should produce keys that decrypt correctly.
		paramsEval := params.Eval()
		ct := prepareTestCiphertext(t, paramsEval, tc.skEval)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			// Finalize the single key from the batch
			gk, err := tc.hkEval.FinalizeKey(rot, intermediate.Keys[rot], tc.tk.HomingKey)
			require.NoError(t, err)
			evk := rlwe.NewMemEvaluationKeySet(nil, gk)

			eval := rlwe.NewEvaluator(paramsEval, evk)
			verifyDeriveRotation(t, paramsEval, tc.skEval, eval, ct, rot, threshold)
		}
	})
}

// testSerialization tests TransmissionKeys WriteTo/ReadFrom roundtrip.
func testSerialization(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "Serialization"), func(t *testing.T) {

		// Serialize
		var buf bytes.Buffer
		n, err := tc.tk.WriteTo(&buf)
		require.NoError(t, err)
		t.Logf("serialized %d bytes (%.2f KB)", n, float64(n)/1024)

		// Deserialize
		tk2 := new(TransmissionKeys)
		_, err = tk2.ReadFrom(&buf)
		require.NoError(t, err)

		// Verify structure
		require.NotNil(t, tk2.HomingKey)
		require.NotNil(t, tk2.PublicKey)
		require.Equal(t, len(tc.tk.MasterRotKeys), len(tk2.MasterRotKeys))

		for rot := range tc.tk.MasterRotKeys {
			_, ok := tk2.MasterRotKeys[rot]
			require.True(t, ok, "master key for rotation %d missing after deserialization", rot)
		}

		// Functional test: derive keys from deserialized transmission keys
		hkEval := NewEvaluator(params)
		intermediate, err := expandAll(hkEval, tk2, []int{1, 2, 3, 4, 5})
		require.NoError(t, err)
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))
		for r, mk := range intermediate.Keys {
			intermediate.Keys[r] = nil
			gk, err := hkEval.FinalizeKey(r, mk, tk2.HomingKey)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.Equal(t, 5, len(evk.GetGaloisKeysList()))
	})

	t.Run(testString(params, "Serialization/IntermediateKeys"), func(t *testing.T) {

		// Expand to get intermediate keys
		hkEval := NewEvaluator(params)
		intermediate, err := expandAll(hkEval, tc.tk, []int{1, 2, 3, 4, 5})
		require.NoError(t, err)

		// Serialize
		var buf bytes.Buffer
		n, err := intermediate.WriteTo(&buf)
		require.NoError(t, err)
		t.Logf("intermediate keys: %d bytes (%.2f KB)", n, float64(n)/1024)

		// Deserialize
		intermediate2 := new(hierkeys.IntermediateKeys)
		_, err = intermediate2.ReadFrom(&buf)
		require.NoError(t, err)

		require.Equal(t, len(intermediate.Keys), len(intermediate2.Keys))
		for rot := range intermediate.Keys {
			_, ok := intermediate2.Keys[rot]
			require.True(t, ok, "intermediate key for rotation %d missing", rot)
		}

		// Functional test: finalize from deserialized intermediates
		galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate2.Keys))
		for r, mk := range intermediate2.Keys {
			intermediate2.Keys[r] = nil
			gk, err := hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
			require.NoError(t, err)
			galoisKeys = append(galoisKeys, gk)
		}
		evk := rlwe.NewMemEvaluationKeySet(nil, galoisKeys...)
		require.Equal(t, 5, len(evk.GetGaloisKeysList()))
	})
}

// testMasterRotationsForBase is a pure unit test for MasterRotationsForBase.
func testMasterRotationsForBase(t *testing.T) {

	t.Run("MasterRotationsForBase", func(t *testing.T) {
		rots := hierkeys.MasterRotationsForBase(4, 32768)
		require.Equal(t, []int{1, 4, 16, 64, 256, 1024, 4096, 16384}, rots)

		rots2 := hierkeys.MasterRotationsForBase(2, 16)
		require.Equal(t, []int{1, 2, 4, 8}, rots2)

		require.Nil(t, hierkeys.MasterRotationsForBase(1, 16))
		require.Nil(t, hierkeys.MasterRotationsForBase(4, 0))

		// decomposeRotation: p-ary decomposition
		steps := hierkeys.DecomposeRotation(7, []int{1, 4})
		require.Equal(t, []int{4, 1, 1, 1}, steps)

		steps2 := hierkeys.DecomposeRotation(21, []int{1, 4, 16})
		require.Equal(t, []int{16, 4, 1}, steps2)

		require.Nil(t, hierkeys.DecomposeRotation(0, []int{1, 4}))
		require.Nil(t, hierkeys.DecomposeRotation(5, nil))
	})
}

// testCKKSRotation verifies that derived rotation keys work end-to-end with
// CKKS slot encoding/decoding, not just raw RLWE polynomials.
func testCKKSRotation(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "CKKSRotation"), func(t *testing.T) {

		logDefaultScale := 45

		// Build CKKS parameters from the same Q/P/LogN as the eval-level RLWE params
		ckksParams, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
			LogN:            params.Eval().LogN(),
			Q:               params.Eval().Q(),
			P:               params.Eval().P(),
			LogDefaultScale: logDefaultScale,
		})
		require.NoError(t, err)

		slots := ckksParams.MaxSlots() // N/2

		// Derive rotation keys for rotation by 1
		rot := 1
		intermediate, err := expandAll(tc.hkEval, tc.tk, []int{rot})
		require.NoError(t, err)
		gk, err := tc.hkEval.FinalizeKey(rot, intermediate.Keys[rot], tc.tk.HomingKey)
		require.NoError(t, err)
		intermediate.Keys[rot] = nil
		evk := rlwe.NewMemEvaluationKeySet(nil, gk)

		// CKKS primitives
		encoder := ckks.NewEncoder(ckksParams)
		encryptor := ckks.NewEncryptor(ckksParams, tc.skEval)
		decryptor := ckks.NewDecryptor(ckksParams, tc.skEval)
		evaluator := ckks.NewEvaluator(ckksParams, evk)

		// Build test vector: [1, 2, 3, ..., slots]
		want := make([]complex128, slots)
		for i := range want {
			want[i] = complex(float64(i+1), 0)
		}

		// Encode and encrypt
		pt := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
		require.NoError(t, encoder.Encode(want, pt))

		ct := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel())
		require.NoError(t, encryptor.Encrypt(pt, ct))

		// Rotate by rot using the derived key
		ctRot := ckks.NewCiphertext(ckksParams, 1, ckksParams.MaxLevel())
		require.NoError(t, evaluator.Rotate(ct, rot, ctRot))

		// Decrypt and decode
		ptDec := ckks.NewPlaintext(ckksParams, ctRot.Level())
		ptDec.Scale = ctRot.Scale
		decryptor.Decrypt(ctRot, ptDec)

		got := make([]complex128, slots)
		require.NoError(t, encoder.Decode(ptDec, got))

		// Expected: cyclic left shift by rot
		expected := make([]complex128, slots)
		for i := range expected {
			expected[i] = want[(i+rot)%slots]
		}

		// Verify precision: max |expected[i] - got[i]| should be small
		maxErr := 0.0
		for i := range got {
			e := cmplx.Abs(expected[i] - got[i])
			if e > maxErr {
				maxErr = e
			}
		}

		// With LogDefaultScale=45, we expect roughly 45 bits of precision.
		// Allow generous threshold of 2^{-10} given the small parameters
		// and potential extra noise from hierarchical key derivation.
		threshold := math.Exp2(-10)
		t.Logf("CKKS rotation by %d: maxErr=%.2e (threshold=%.2e)", rot, maxErr, threshold)
		require.Less(t, maxErr, threshold,
			"CKKS rotation error too large: maxErr=%.2e, threshold=%.2e", maxErr, threshold)
	})
}

// productionScenarios returns testutil.Scenarios, reduced to LogN=14 only in
// -short mode so PR-time CI stays fast while master pushes cover all sizes.
func productionScenarios() []testutil.Scenario {
	if testing.Short() {
		return testutil.Scenarios[:1]
	}
	return testutil.Scenarios
}

// TestDeriveGaloisKeys exercises the full client/server pipeline
// (MasterRotationsForBase → expandAll → FinalizeKey → rotation verification)
// sequentially against each production scenario. Mirrors BenchmarkDeriveGaloisKeys.
func TestDeriveGaloisKeys(t *testing.T) {
	for _, sc := range productionScenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			params := buildParams(t, sc)
			paramsEval := params.Eval()
			slots := paramsEval.N() / 2

			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := testutil.ReducedTestTargets(slots)
			t.Logf("LogN=%d, masters=%d (%v), targets=%d",
				paramsEval.LogN(), len(masterRots), masterRots, len(targetRots))

			tc, err := newTestContext(params, masterRots)
			require.NoError(t, err)

			intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
			require.NoError(t, err)

			galoisKeys := make([]*rlwe.GaloisKey, 0, len(targetRots))
			for _, r := range targetRots {
				mk := intermediate.Keys[r]
				intermediate.Keys[r] = nil
				gk, err := tc.hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
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

// TestDeriveGaloisKeysConcurrent runs the same pipeline as TestDeriveGaloisKeys
// but derives + finalizes targets concurrently across GOMAXPROCS workers.
// Exercises LevelExpansion.Derive's thread-safety (sync.Once dedup, pool
// buffers). Run with -race in CI to catch regressions in the concurrent path.
// Mirrors BenchmarkDeriveGaloisKeysConcurrent.
func TestDeriveGaloisKeysConcurrent(t *testing.T) {
	workers := runtime.GOMAXPROCS(0)
	for _, sc := range productionScenarios() {
		t.Run(sc.Name, func(t *testing.T) {
			params := buildParams(t, sc)
			paramsEval := params.Eval()
			slots := paramsEval.N() / 2

			masterRots := hierkeys.MasterRotationsForBase(sc.Base, slots)
			targetRots := testutil.ReducedTestTargets(slots)

			tc, err := newTestContext(params, masterRots)
			require.NoError(t, err)

			// Cascade through intermediate levels sequentially (levels are
			// dependent), then derive + finalize level-0 targets concurrently.
			k := params.NumLevels()
			currentMasters := tc.tk.MasterRotKeys
			for level := k - 2; level >= 1; level-- {
				shift0Key, err := hierkeys.PubToRot(params.Levels()[level], params.Top(), tc.tk.PublicKey)
				require.NoError(t, err)
				exp := tc.hkEval.NewLevelExpansion(level, shift0Key, currentMasters, masterRots)
				nextMasters := make(map[int]*hierkeys.MasterKey, len(masterRots))
				for _, r := range masterRots {
					mk, err := exp.Derive(r)
					require.NoError(t, err)
					nextMasters[r] = mk
				}
				currentMasters = nextMasters
			}

			shift0Key, err := hierkeys.PubToRot(params.Levels()[0], params.Top(), tc.tk.PublicKey)
			require.NoError(t, err)
			exp := tc.hkEval.NewLevelExpansion(0, shift0Key, currentMasters, targetRots)

			sem := make(chan struct{}, workers)
			var wg sync.WaitGroup
			results := make([]*rlwe.GaloisKey, len(targetRots))
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
					gk, err := tc.hkEval.FinalizeKey(r, mk, tc.tk.HomingKey)
					if err != nil {
						errs[i] = err
						return
					}
					results[i] = gk
				}(i, r)
			}
			wg.Wait()
			for i, err := range errs {
				require.NoError(t, err, "target %d", targetRots[i])
			}

			evk := rlwe.NewMemEvaluationKeySet(nil, results...)
			ct := prepareTestCiphertext(t, paramsEval, tc.skEval)
			stdEval := rlwe.NewEvaluator(paramsEval, evk)
			for _, rot := range targetRots {
				verifyDeriveRotation(t, paramsEval, tc.skEval, stdEval, ct, rot, float64(1<<30))
			}
			runtime.GC()
		})
	}
}
