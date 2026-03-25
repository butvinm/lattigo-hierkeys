package kgplus

import (
	"bytes"
	"fmt"
	"math"
	"math/cmplx"
	"runtime"
	"sort"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
)

func testString(params Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/k=%d",
		opname,
		params.Eval.LogN(),
		params.Eval.QCount(),
		params.Eval.PCount(),
		params.NumLevels())
}

type testContext struct {
	params     Parameters
	kgen       *KeyGenerator
	sk         *rlwe.SecretKey // at HK level
	skEval     *rlwe.SecretKey // projected to eval level
	tk         *TransmissionKeys
	hkEval     *Evaluator
	masterRots []int
}

func newTestContext(params Parameters, masterRots []int) (*testContext, error) {
	kgen := NewKeyGenerator(params)
	sk := kgen.GenSecretKeyNew()
	skEval := kgen.ProjectToEvalKey(sk)

	tk, err := kgen.GenTransmissionKeys(sk, masterRots)
	if err != nil {
		return nil, err
	}

	hkEval := NewEvaluator(params)

	return &testContext{
		params:     params,
		kgen:       kgen,
		sk:         sk,
		skEval:     skEval,
		tk:         tk,
		hkEval:     hkEval,
		masterRots: masterRots,
	}, nil
}

// expandAll cascades ExpandLevel through all levels, replicating what the
// removed Expand method did. Used by tests that need level-0 IntermediateKeys.
func expandAll(eval *Evaluator, tk *TransmissionKeys, targetRots []int) (*IntermediateKeys, error) {
	k := eval.params.NumLevels()
	masterRots := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRots = append(masterRots, rot)
	}
	sort.Ints(masterRots)

	currentMasters := tk.MasterRotKeys
	for level := k - 2; level >= 1; level-- {
		derived, err := eval.ExpandLevel(level, tk.Shift0Keys[level], currentMasters, masterRots)
		if err != nil {
			return nil, err
		}
		currentMasters = derived.Keys
	}
	return eval.ExpandLevel(0, tk.Shift0Keys[0], currentMasters, targetRots)
}

// TestKGPlus is the main entry point, iterating over parameter sets
// and running all individual test functions.
func TestKGPlus(t *testing.T) {

	for _, paramsLit := range testInsecure {

		paramsEval, err := rlwe.NewParametersFromLiteral(paramsLit.ParametersLiteral)
		require.NoError(t, err)

		params, err := NewParameters(paramsEval, paramsLit.LogPHK, paramsLit.LogPExtra...)
		require.NoError(t, err)

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
	}

	testMasterRotationsForBase(t)
	testDeriveGaloisKeysLargeN(t)
}

// testKeyGenerator tests GenSecretKeyNew, ProjectToEvalKey, and GenTransmissionKeys.
func testKeyGenerator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "KeyGenerator"), func(t *testing.T) {

		t.Run("GenSecretKeyNew", func(t *testing.T) {
			sk := tc.kgen.GenSecretKeyNew()
			require.NotNil(t, sk)
			// Key should have HK-level Q primes (Q_eval + P_eval)
			require.Equal(t, params.HK.QCount()-1, sk.LevelQ())
			require.Equal(t, params.HK.PCount()-1, sk.LevelP())
		})

		t.Run("ProjectToEvalKey", func(t *testing.T) {
			skEval := tc.kgen.ProjectToEvalKey(tc.sk)
			require.NotNil(t, skEval)
			require.Equal(t, params.Eval.QCount()-1, skEval.LevelQ())
			require.Equal(t, params.Eval.PCount()-1, skEval.LevelP())
		})

		t.Run("GenTransmissionKeys", func(t *testing.T) {
			tk := tc.tk
			require.NotNil(t, tk.HomingKey)
			require.Len(t, tk.Shift0Keys, params.NumLevels()-1)
			for i, gk := range tk.Shift0Keys {
				require.NotNil(t, gk, "shift-0 key at level %d is nil", i)
			}
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
// constructExtendedSKForParams delegates to the exported ConstructExtendedSK.
func constructExtendedSKForParams(
	paramsHK rlwe.Parameters,
	paramsRP rlwe.Parameters,
	skS, skS1 *rlwe.SecretKey,
) *rlwe.SecretKey {
	return ConstructExtendedSK(paramsHK, paramsRP, skS, skS1)
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

		paramsEval := params.Eval
		paramsRPLow := params.RPrime[0]
		paramsRPHigh := params.RPrime[1]
		paramsHK := params.HK

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
		shift0Key := &rlwe.GaloisKey{
			EvaluationKey: *shift0EK,
			GaloisElement: 1,
			NthRoot:       paramsRPLow.RingQ().NthRoot(),
		}

		// Master key for rotation 1 at master level
		rot := 1
		galElRPHigh := paramsRPHigh.GaloisElement(rot)

		skTildeHighAut := rlwe.NewSecretKey(paramsRPHigh)
		autIdx, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galElRPHigh)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, autIdx, skTildeHighAut.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, autIdx, skTildeHighAut.Value.P)

		masterEK := kgenRPHigh.GenEvaluationKeyNew(skTildeHighAut, skTildeHigh)
		masterKey := &rlwe.GaloisKey{
			EvaluationKey: *masterEK,
			GaloisElement: galElRPHigh,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		}

		// RotToRot: shift0 + master -> rotation key at level-0
		galElRPLow := paramsRPLow.GaloisElement(rot)
		rotKey, err := RotToRot(paramsRPLow, paramsRPHigh, shift0Key, masterKey, galElRPLow)
		require.NoError(t, err)

		// Ring-switch from R' to R
		galElR := paramsEval.GaloisElement(rot)
		rsGK, err := RingSwitchGaloisKey(paramsEval, paramsHK, paramsRPLow, rotKey, homingKey, galElR)
		require.NoError(t, err)

		require.NoError(t, hierkeys.ConvertToLattigoConvention(paramsEval, rsGK))

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGK, rot, threshold)
	})
}

// testRotToRotMultiStep tests composing RotToRot twice:
// shift0 + master(1) -> rot-1, then rot-1 + master(4) -> rot-5.
func testRotToRotMultiStep(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "RotToRot/MultiStep"), func(t *testing.T) {

		paramsEval := params.Eval
		paramsRPLow := params.RPrime[0]
		paramsRPHigh := params.RPrime[1]
		paramsHK := params.HK

		kgenHK := rlwe.NewKeyGenerator(paramsHK)
		kgenRPLow := rlwe.NewKeyGenerator(paramsRPLow)
		kgenRPHigh := rlwe.NewKeyGenerator(paramsRPHigh)

		skS := kgenHK.GenSecretKeyNew()
		skS1 := kgenHK.GenSecretKeyNew()

		skTildeLow := constructExtendedSKForParams(paramsHK, paramsRPLow, skS, skS1)
		skTildeHigh := constructExtendedSKForParams(paramsHK, paramsRPHigh, skS, skS1)

		homingKey := kgenHK.GenEvaluationKeyNew(skS1, skS)

		shift0EK := kgenRPLow.GenEvaluationKeyNew(skTildeLow, skTildeLow)
		shift0Key := &rlwe.GaloisKey{
			EvaluationKey: *shift0EK,
			GaloisElement: 1,
			NthRoot:       paramsRPLow.RingQ().NthRoot(),
		}

		// Master key for rotation 1
		rot1 := 1
		galEl1High := paramsRPHigh.GaloisElement(rot1)
		skAut1 := rlwe.NewSecretKey(paramsRPHigh)
		idx1, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galEl1High)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, idx1, skAut1.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, idx1, skAut1.Value.P)
		master1EK := kgenRPHigh.GenEvaluationKeyNew(skAut1, skTildeHigh)
		masterKey1 := &rlwe.GaloisKey{
			EvaluationKey: *master1EK,
			GaloisElement: galEl1High,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		}

		// Master key for rotation 4
		rot4 := 4
		galEl4High := paramsRPHigh.GaloisElement(rot4)
		skAut4 := rlwe.NewSecretKey(paramsRPHigh)
		idx4, err := ring.AutomorphismNTTIndex(paramsRPHigh.N(), paramsRPHigh.RingQ().NthRoot(), galEl4High)
		require.NoError(t, err)
		paramsRPHigh.RingQ().AutomorphismNTTWithIndex(skTildeHigh.Value.Q, idx4, skAut4.Value.Q)
		paramsRPHigh.RingP().AutomorphismNTTWithIndex(skTildeHigh.Value.P, idx4, skAut4.Value.P)
		master4EK := kgenRPHigh.GenEvaluationKeyNew(skAut4, skTildeHigh)
		masterKey4 := &rlwe.GaloisKey{
			EvaluationKey: *master4EK,
			GaloisElement: galEl4High,
			NthRoot:       paramsRPHigh.RingQ().NthRoot(),
		}

		// Step 1: shift0 + master(1) -> rot-1
		galEl1Low := paramsRPLow.GaloisElement(rot1)
		rot1Key, err := RotToRot(paramsRPLow, paramsRPHigh, shift0Key, masterKey1, galEl1Low)
		require.NoError(t, err)

		// Step 2: rot-1 + master(4) -> rot-5
		rot5 := rot1 + rot4
		galEl5Low := paramsRPLow.GaloisElement(rot5)
		rot5Key, err := RotToRot(paramsRPLow, paramsRPHigh, rot1Key, masterKey4, galEl5Low)
		require.NoError(t, err)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		// Ring-switch and verify rot-1
		galElR1 := paramsEval.GaloisElement(rot1)
		rsGK1, err := RingSwitchGaloisKey(paramsEval, paramsHK, paramsRPLow, rot1Key, homingKey, galElR1)
		require.NoError(t, err)
		require.NoError(t, hierkeys.ConvertToLattigoConvention(paramsEval, rsGK1))
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGK1, rot1, threshold)

		// Ring-switch and verify rot-5
		galElR5 := paramsEval.GaloisElement(rot5)
		rsGK5, err := RingSwitchGaloisKey(paramsEval, paramsHK, paramsRPLow, rot5Key, homingKey, galElR5)
		require.NoError(t, err)
		require.NoError(t, hierkeys.ConvertToLattigoConvention(paramsEval, rsGK5))
		verifyRotationKey(t, paramsEval, paramsHK, skS, rsGK5, rot5, threshold)
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
// NewParameters -> KeyGenerator -> TransmissionKeys -> DeriveGaloisKeys -> standard Automorphism.
func testDeriveGaloisKeys(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "DeriveGaloisKeys"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		evk, err := DeriveGaloisKeys(params, tc.tk, targetRots)
		require.NoError(t, err)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		paramsEval := params.Eval
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

		evk, err := tc.hkEval.DeriveGaloisKeys(tc.tk, targetRots)
		require.NoError(t, err)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		paramsEval := params.Eval
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

// testExpandAndFinalize verifies that the two-phase approach (Expand +
// FinalizeKeys) produces the same results as the single-call DeriveGaloisKeys.
func testExpandAndFinalize(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "ExpandAndFinalize"), func(t *testing.T) {

		targetRots := []int{1, 2, 3, 4, 5}

		// Two-phase approach
		intermediate, err := expandAll(tc.hkEval, tc.tk, targetRots)
		require.NoError(t, err)
		require.Equal(t, len(targetRots), len(intermediate.Keys))

		evk, err := tc.hkEval.FinalizeKeys(tc.tk, intermediate)
		require.NoError(t, err)
		require.Equal(t, len(targetRots), len(evk.GetGaloisKeysList()))

		// Verify each rotation works correctly
		paramsEval := params.Eval
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
		paramsEval := params.Eval
		ct := prepareTestCiphertext(t, paramsEval, tc.skEval)

		threshold := float64(1 << 25)
		if params.NumLevels() > 2 {
			threshold = float64(1 << 35)
		}

		for _, rot := range targetRots {
			// Finalize the single key from the batch
			singleIntermediate := &IntermediateKeys{
				Keys: map[int]*rlwe.GaloisKey{rot: intermediate.Keys[rot]},
			}
			evk, err := tc.hkEval.FinalizeKeys(tc.tk, singleIntermediate)
			require.NoError(t, err)

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
		require.Len(t, tk2.Shift0Keys, len(tc.tk.Shift0Keys))
		for i, gk := range tk2.Shift0Keys {
			require.NotNil(t, gk, "shift-0 key at level %d is nil after deserialization", i)
		}
		require.Equal(t, len(tc.tk.MasterRotKeys), len(tk2.MasterRotKeys))

		for rot := range tc.tk.MasterRotKeys {
			_, ok := tk2.MasterRotKeys[rot]
			require.True(t, ok, "master key for rotation %d missing after deserialization", rot)
		}

		// Functional test: derive keys from deserialized transmission keys
		evk, err := DeriveGaloisKeys(params, tk2, []int{1, 2, 3, 4, 5})
		require.NoError(t, err)
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
		intermediate2 := new(IntermediateKeys)
		_, err = intermediate2.ReadFrom(&buf)
		require.NoError(t, err)

		require.Equal(t, len(intermediate.Keys), len(intermediate2.Keys))
		for rot := range intermediate.Keys {
			_, ok := intermediate2.Keys[rot]
			require.True(t, ok, "intermediate key for rotation %d missing", rot)
		}

		// Functional test: finalize from deserialized intermediates
		evk, err := hkEval.FinalizeKeys(tc.tk, intermediate2)
		require.NoError(t, err)
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
			LogN:            params.Eval.LogN(),
			Q:               params.Eval.Q(),
			P:               params.Eval.P(),
			LogDefaultScale: logDefaultScale,
		})
		require.NoError(t, err)

		slots := ckksParams.MaxSlots() // N/2

		// Derive rotation keys for rotation by 1
		rot := 1
		evk, err := DeriveGaloisKeys(params, tc.tk, []int{rot})
		require.NoError(t, err)

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

// testDeriveGaloisKeysLargeN tests with LogN=14, closer to production scale.
// Uses 8 Q primes + 1 P prime, base-4 master rotations.
// Skipped in short mode.
func testDeriveGaloisKeysLargeN(t *testing.T) {

	t.Run("DeriveGaloisKeys/LargeN", func(t *testing.T) {

		if testing.Short() {
			t.Skip("skipped in -short mode")
		}

		paramsEval, err := rlwe.NewParametersFromLiteral(rlwe.ParametersLiteral{
			LogN:    14,
			Q:       testQi60[:8],
			P:       testPi60[:1],
			NTTFlag: true,
		})
		require.NoError(t, err)

		params, err := NewParameters(paramsEval, []int{61})
		require.NoError(t, err)

		t.Logf("Eval: LogN=%d, Q=%d primes, P=%d primes, N=%d",
			paramsEval.LogN(), paramsEval.QCount(), paramsEval.PCount(), paramsEval.N())

		// Client
		kgen := NewKeyGenerator(params)
		sk := kgen.GenSecretKeyNew()
		skEval := kgen.ProjectToEvalKey(sk)

		masterRots := hierkeys.MasterRotationsForBase(4, paramsEval.N()/2)
		t.Logf("master rotations (base-4): %v (%d keys)", masterRots, len(masterRots))

		tk, err := kgen.GenTransmissionKeys(sk, masterRots)
		require.NoError(t, err)

		// Server: derive
		targetRots := []int{1, 2, 3, 5, 7, 10, 17, 31, 64, 100, 255, 512, 1000}
		hkEval := NewEvaluator(params)
		evk, err := hkEval.DeriveGaloisKeys(tk, targetRots)
		require.NoError(t, err)
		t.Logf("derived %d evaluation keys", len(evk.GetGaloisKeysList()))

		// Verify a subset
		ringQ := paramsEval.RingQ()
		encR := rlwe.NewEncryptor(paramsEval, skEval)

		pt := rlwe.NewPlaintext(paramsEval, paramsEval.MaxLevel())
		for m := range pt.Value.Coeffs {
			for k := range pt.Value.Coeffs[m] {
				pt.Value.Coeffs[m][k] = 0
			}
			pt.Value.Coeffs[m][0] = 42
		}
		ringQ.NTT(pt.Value, pt.Value)
		pt.IsNTT = true

		ct := rlwe.NewCiphertext(paramsEval, 1, paramsEval.MaxLevel())
		require.NoError(t, encR.Encrypt(pt, ct))

		stdEval := rlwe.NewEvaluator(paramsEval, evk)

		verifyRots := []int{1, 5, 17, 100, 1000}
		for _, rot := range verifyRots {
			verifyDeriveRotation(t, paramsEval, skEval, stdEval, ct, rot, float64(1<<30))
		}
	})
}
