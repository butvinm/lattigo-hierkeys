package llkn

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"sort"
	"testing"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

func testString(params Parameters, opname string) string {
	return fmt.Sprintf("%s/logN=%d/Qi=%d/Pi=%d/k=%d",
		opname,
		params.Eval().LogN(),
		params.Eval().QCount(),
		params.Eval().PCount(),
		params.NumLevels())
}

type testContext struct {
	params     Parameters
	kgen       *KeyGenerator
	sk         *rlwe.SecretKey // at top level
	skEval     *rlwe.SecretKey // projected to eval level
	tk         *TransmissionKeys
	eval       *Evaluator
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

	eval := NewEvaluator(params)

	return &testContext{
		params:     params,
		kgen:       kgen,
		sk:         sk,
		skEval:     skEval,
		tk:         tk,
		eval:       eval,
		masterRots: masterRots,
	}, nil
}

// expandAll cascades ExpandLevel through all levels. Used by tests that
// need level-0 IntermediateKeys.
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

func TestLLKN(t *testing.T) {

	for _, paramsLit := range testInsecure {

		paramsEval, err := rlwe.NewParametersFromLiteral(paramsLit.ParametersLiteral)
		require.NoError(t, err)

		params, err := NewParameters(paramsEval, paramsLit.LogPPerLevel)
		require.NoError(t, err)

		masterRots := []int{1, 4}

		tc, err := newTestContext(params, masterRots)
		require.NoError(t, err)

		for _, testSet := range []func(*testContext, *testing.T){
			testKeyGenerator,
			testDeriveGaloisKeys,
			testDeriveGaloisKeysWithEvaluator,
			testExpandAndFinalize,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}

	testMasterRotationsForBase(t)
}

func testKeyGenerator(tc *testContext, t *testing.T) {

	params := tc.params

	t.Run(testString(params, "KeyGenerator"), func(t *testing.T) {

		t.Run("GenSecretKeyNew", func(t *testing.T) {
			sk := tc.kgen.GenSecretKeyNew()
			require.NotNil(t, sk)
			require.Equal(t, params.Top().QCount(), sk.LevelQ()+1)
			require.Equal(t, params.Top().PCount(), sk.LevelP()+1)
		})

		t.Run("ProjectToEvalKey", func(t *testing.T) {
			skEval := tc.kgen.ProjectToEvalKey(tc.sk)
			require.NotNil(t, skEval)
			require.Equal(t, params.Eval().QCount(), skEval.LevelQ()+1)
			require.Equal(t, params.Eval().PCount(), skEval.LevelP()+1)
		})

		t.Run("GenTransmissionKeys", func(t *testing.T) {
			tk := tc.tk
			require.NotNil(t, tk)
			require.Len(t, tk.Shift0Keys, params.NumLevels()-1)
			for i, gk := range tk.Shift0Keys {
				require.NotNil(t, gk, "shift-0 key at level %d is nil", i)
			}
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
		evk, err := DeriveGaloisKeys(params, tc.tk, targetRots)
		require.NoError(t, err)
		require.NotNil(t, evk)

		ct := prepareTestCiphertext(t, params.Eval(), tc.skEval)
		stdEval := rlwe.NewEvaluator(params.Eval(), evk)

		// Allow more noise for k=3 (2 RotToRot stages)
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
		evk, err := tc.eval.DeriveGaloisKeys(tc.tk, targetRots)
		require.NoError(t, err)

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

		intermediate2 := new(IntermediateKeys)
		_, err = intermediate2.ReadFrom(&buf)
		require.NoError(t, err)
		require.Len(t, intermediate2.Keys, len(targetRots))

		// Finalize (cheap)
		evk, err := tc.eval.FinalizeKeys(intermediate2)
		require.NoError(t, err)

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

// verifyDeriveRotation compares automorphism output from the given evaluator
// against a reference automorphism computed using lattigo's own GenGaloisKeyNew.
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
