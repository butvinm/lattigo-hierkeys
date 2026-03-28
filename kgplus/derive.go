package kgplus

import (
	"fmt"
	"sort"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// IntermediateKeys holds R' GaloisKeys produced by RotToRot expansion at a
// single hierarchy level. These are in the paper's convention (not yet
// ring-switched or post-converted). They can be serialized, stored, and later
// used as input to expand the next level down or finalized via
// [Evaluator.FinalizeKeys] (level 0 only).
type IntermediateKeys struct {
	Keys map[int]*rlwe.GaloisKey // indexed by rotation index
}

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys in one shot. The returned keys work with lattigo's standard
// rlwe.Evaluator.Automorphism and ckks.Evaluator.Rotate.
//
// For per-level control (e.g., storing intermediates at each level for the
// inactive/active pattern), derive shift-0 keys via PubToRot and use
// [Evaluator.ExpandLevel] directly:
//
//	shift0L1, _ := hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.EncZero)
//	level1Keys, _ := eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots)
//	// store level1Keys to disk...
//	shift0L0, _ := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.EncZero)
//	level0Keys, _ := eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots)
//	// store level0Keys to disk...
//	evk, _ := eval.FinalizeKeys(tk, level0Keys)
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.EncZero == nil {
		return nil, fmt.Errorf("transmission keys and EncZero must not be nil")
	}

	k := eval.params.NumLevels()
	topLevel := k - 1

	masterRots := sortedKeys(tk.MasterRotKeys)
	currentMasters := tk.MasterRotKeys

	isDerived := false // tracks whether currentMasters is derived (safe to nil) vs original TX data
	for level := k - 2; level >= 1; level-- {
		shift0Key, err := hierkeys.PubToRot(eval.params.RPrime[level], eval.params.RPrime[topLevel], tk.EncZero)
		if err != nil {
			return nil, fmt.Errorf("PubToRot at level %d: %w", level, err)
		}
		derived, err := eval.ExpandLevel(level, shift0Key, currentMasters, masterRots)
		if err != nil {
			return nil, fmt.Errorf("expand R' level %d: %w", level, err)
		}

		// Release previous level's derived keys — no longer needed.
		// Skip if currentMasters is tk.MasterRotKeys (don't mutate caller's data).
		if isDerived {
			for rot := range currentMasters {
				currentMasters[rot] = nil // permit early GC
			}
		}

		currentMasters = derived.Keys
		isDerived = true
	}

	shift0Key0, err := hierkeys.PubToRot(eval.params.RPrime[0], eval.params.RPrime[topLevel], tk.EncZero)
	if err != nil {
		return nil, fmt.Errorf("PubToRot at level 0: %w", err)
	}
	level0Keys, err := eval.ExpandLevel(0, shift0Key0, currentMasters, targetRotations)
	if err != nil {
		return nil, fmt.Errorf("expand R' level 0: %w", err)
	}

	// Release intermediate masters — no longer needed after level-0 expansion.
	if isDerived {
		for rot := range currentMasters {
			currentMasters[rot] = nil // permit early GC
		}
	}

	return eval.FinalizeKeys(tk, level0Keys)
}

// ExpandLevel derives keys at the given R' hierarchy level using RotToRot with
// master keys from the level above.
//
// Parameters:
//   - level: the R' hierarchy level to derive keys at (0 = lowest R' level)
//   - shift0Key: the identity (shift-0) key at this level (derived via PubToRot from TransmissionKeys.EncZero)
//   - masterKeys: keys at level+1, indexed by rotation (either from TransmissionKeys.MasterRotKeys
//     or from a previous ExpandLevel call's IntermediateKeys.Keys)
//   - targetRotations: which rotations to derive at this level
//
// The returned IntermediateKeys can be serialized for storage, then later
// passed as masterKeys to the next ExpandLevel call (level-1), or finalized
// via [Evaluator.FinalizeKeys] if level == 0.
//
// Intermediate RotToRot results within a level are cached: if multiple targets
// share a decomposition prefix, the shared intermediate is computed once.
func (eval *Evaluator) ExpandLevel(
	level int,
	shift0Key *rlwe.GaloisKey,
	masterKeys map[int]*rlwe.GaloisKey,
	targetRotations []int,
) (*IntermediateKeys, error) {

	if shift0Key == nil {
		return nil, fmt.Errorf("shift-0 key must not be nil")
	}

	if len(masterKeys) == 0 {
		return nil, fmt.Errorf("master keys must not be empty")
	}

	paramsLow := eval.params.RPrime[level]
	nSlots := eval.params.Eval.N() / 2

	// Decomposition base: sorted rotation indices available as masters
	masterRots := sortedKeys(masterKeys)

	// Cache: normalized rotation index -> key at this level
	cache := make(map[int]*rlwe.GaloisKey)
	cache[0] = shift0Key

	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}

		if _, ok := cache[normalized]; ok {
			continue
		}

		steps := hierkeys.DecomposeRotation(normalized, masterRots)
		if steps == nil {
			return nil, fmt.Errorf("cannot decompose rotation %d (normalized from %d) from available masters",
				normalized, target)
		}

		currentRot := 0
		for _, step := range steps {
			nextRot := currentRot + step

			if _, ok := cache[nextRot]; !ok {
				masterKey, ok := masterKeys[step]
				if !ok {
					return nil, fmt.Errorf("missing master key for rotation %d at level %d", step, level+1)
				}
				combinedGalEl := paramsLow.GaloisElement(nextRot)
				key, err := eval.RotToRot(level, cache[currentRot], masterKey, combinedGalEl)
				if err != nil {
					return nil, fmt.Errorf("RotToRot step (current=%d + master=%d -> %d): %w",
						currentRot, step, nextRot, err)
				}
				cache[nextRot] = key
			}

			currentRot = nextRot
		}
	}

	// Build result indexed by requested rotations
	result := &IntermediateKeys{Keys: make(map[int]*rlwe.GaloisKey, len(targetRotations))}
	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}
		if key, ok := cache[normalized]; ok {
			result.Keys[target] = key
		}
	}
	return result, nil
}

// sortedKeys extracts and sorts the integer keys from a map.
func sortedKeys(m map[int]*rlwe.GaloisKey) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// FinalizeKeys ring-switches R' intermediate keys to R and post-converts
// to lattigo's standard convention. This is the cheaper phase (~20% of cost).
//
// The result is a standard MemEvaluationKeySet usable with [rlwe.Evaluator].
func (eval *Evaluator) FinalizeKeys(tk *TransmissionKeys, intermediate *IntermediateKeys) (*rlwe.MemEvaluationKeySet, error) {

	if tk == nil || tk.HomingKey == nil {
		return nil, fmt.Errorf("transmission keys and homing key must not be nil")
	}

	if intermediate == nil || len(intermediate.Keys) == 0 {
		return nil, fmt.Errorf("intermediate keys must not be nil or empty")
	}

	params := eval.params
	galoisKeys := make([]*rlwe.GaloisKey, 0, len(intermediate.Keys))

	for rot, rPrimeKey := range intermediate.Keys {
		// Ring-switch from R' to R
		galElR := params.Eval.GaloisElement(rot)
		rsGK, err := eval.RingSwitchGaloisKey(rPrimeKey, tk.HomingKey, galElR)
		if err != nil {
			return nil, fmt.Errorf("ring switch for rotation %d: %w", rot, err)
		}

		// Release R' key — no longer needed after ring switching
		intermediate.Keys[rot] = nil

		// Post-convert from paper convention to lattigo convention
		if err := eval.convertToLattigoConvention(rsGK); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}

		galoisKeys = append(galoisKeys, rsGK)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}

// RingSwitchGaloisKey ring-switches a GaloisKey from R' (degree 2N) to a
// standard GaloisKey in R (degree N) using a homing key.
func (eval *Evaluator) RingSwitchGaloisKey(
	masterKeyRPrime *rlwe.GaloisKey,
	homingKey *rlwe.EvaluationKey,
	galoisElement uint64,
) (*rlwe.GaloisKey, error) {

	paramsEval := eval.params.Eval
	paramsHK := eval.params.HK
	paramsRPrime := eval.params.RPrime[0]

	// Input validation
	if paramsRPrime.N() != 2*paramsEval.N() {
		return nil, fmt.Errorf("paramsRPrime.N()=%d must be 2*paramsEval.N()=%d", paramsRPrime.N(), 2*paramsEval.N())
	}
	if paramsHK.N() != paramsEval.N() {
		return nil, fmt.Errorf("paramsHK.N()=%d must equal paramsEval.N()=%d", paramsHK.N(), paramsEval.N())
	}
	if paramsHK.QCount() != paramsEval.QCount()+paramsEval.PCount() {
		return nil, fmt.Errorf("paramsHK.QCount()=%d must equal paramsEval.QCount()+PCount()=%d",
			paramsHK.QCount(), paramsEval.QCount()+paramsEval.PCount())
	}
	if masterKeyRPrime == nil || homingKey == nil {
		return nil, fmt.Errorf("masterKeyRPrime and homingKey must not be nil")
	}

	N := paramsEval.N()
	ringQHK := paramsHK.RingQ()

	levelQHK := paramsHK.MaxLevel()
	levelQEval := paramsEval.MaxLevel()
	levelPEval := paramsEval.MaxLevelP()

	gc := &masterKeyRPrime.GadgetCiphertext
	nRNS := len(gc.Value)

	nEvalRNS := paramsEval.BaseRNSDecompositionVectorSize(levelQEval, levelPEval)
	if nRNS < nEvalRNS {
		return nil, fmt.Errorf("master key has %d RNS components, need at least %d", nRNS, nEvalRNS)
	}

	targetGK := &rlwe.GaloisKey{
		EvaluationKey: rlwe.EvaluationKey{
			GadgetCiphertext: *rlwe.NewGadgetCiphertext(
				paramsEval, 1, levelQEval, levelPEval, 0),
		},
		GaloisElement: galoisElement,
		NthRoot:       paramsEval.RingQ().NthRoot(),
	}

	ringQRPrimeQ := paramsRPrime.RingQ()
	ringPRPrime := paramsRPrime.RingP()
	ringQEval := paramsEval.RingQ()
	ringPEval := paramsEval.RingP()

	bQRPrime := eval.bQRPrime
	aQRPrime := eval.aQRPrime
	bQCoeff := eval.bQCoeff
	aQCoeff := eval.aQCoeff
	bPRPrime := eval.bPRPrime
	aPRPrime := eval.aPRPrime
	bPCoeff := eval.bPCoeff
	aPCoeff := eval.aPCoeff
	b0 := eval.b0RS
	a0 := eval.a0RS
	a1 := eval.a1RS
	Xa1 := eval.Xa1RS
	rsB := eval.rsBRS
	rsA := eval.rsARS
	ctKS := eval.ctKSRS

	pIdx := levelQEval + 1 // start index of P_eval primes in Q_hk

	for i := 0; i < nEvalRNS; i++ {
		component := gc.Value[i][0]

		// --- Extract even/odd from Q and P parts of R' component ---
		bQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[0].Q)
		aQRPrime.CopyLvl(paramsRPrime.MaxLevel(), component[1].Q)
		ringQRPrimeQ.IMForm(bQRPrime, bQRPrime)
		ringQRPrimeQ.IMForm(aQRPrime, aQRPrime)
		ringQRPrimeQ.INTT(bQRPrime, bQCoeff)
		ringQRPrimeQ.INTT(aQRPrime, aQCoeff)

		// P parts
		bPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[0].P)
		aPRPrime.CopyLvl(paramsRPrime.MaxLevelP(), component[1].P)
		ringPRPrime.IMForm(bPRPrime, bPRPrime)
		ringPRPrime.IMForm(aPRPrime, aPRPrime)
		ringPRPrime.INTT(bPRPrime, bPCoeff)
		ringPRPrime.INTT(aPRPrime, aPCoeff)

		// Even/odd extraction into Q_hk-level polynomials
		for m := 0; m <= paramsRPrime.MaxLevel(); m++ {
			for j := 0; j < N; j++ {
				b0.Coeffs[m][j] = bQCoeff.Coeffs[m][2*j]
				a0.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j]
				a1.Coeffs[m][j] = aQCoeff.Coeffs[m][2*j+1]
			}
		}
		for m := 0; m <= paramsRPrime.MaxLevelP(); m++ {
			for j := 0; j < N; j++ {
				b0.Coeffs[pIdx+m][j] = bPCoeff.Coeffs[m][2*j]
				a0.Coeffs[pIdx+m][j] = aPCoeff.Coeffs[m][2*j]
				a1.Coeffs[pIdx+m][j] = aPCoeff.Coeffs[m][2*j+1]
			}
		}

		// Multiply a1 by X: X*f(X) mod (X^N+1)
		for m := range a1.Coeffs {
			qi := ringQHK.SubRings[m].Modulus
			Xa1.Coeffs[m][0] = qi - a1.Coeffs[m][N-1]
			for k := 1; k < N; k++ {
				Xa1.Coeffs[m][k] = a1.Coeffs[m][k-1]
			}
		}

		ringQHK.NTT(b0, b0)
		ringQHK.NTT(a0, a0)
		ringQHK.NTT(Xa1, Xa1)

		// --- Key-switch X*a1 with homing key ---
		eval.evalHK.GadgetProduct(levelQHK, Xa1, &homingKey.GadgetCiphertext, ctKS)

		// Ring-switched ciphertext at Q_hk level
		ringQHK.Add(b0, ctKS.Value[0], rsB)
		ringQHK.Add(a0, ctKS.Value[1], rsA)

		// --- Split Q_hk into Q_eval and P_eval parts ---
		for m := 0; m <= levelQEval; m++ {
			s := ringQEval.SubRings[m]
			s.MForm(rsB.Coeffs[m], targetGK.Value[i][0][0].Q.Coeffs[m])
			s.MForm(rsA.Coeffs[m], targetGK.Value[i][0][1].Q.Coeffs[m])
		}
		for m := 0; m <= levelPEval; m++ {
			s := ringPEval.SubRings[m]
			srcIdx := pIdx + m
			s.MForm(rsB.Coeffs[srcIdx], targetGK.Value[i][0][0].P.Coeffs[m])
			s.MForm(rsA.Coeffs[srcIdx], targetGK.Value[i][0][1].P.Coeffs[m])
		}
	}

	return targetGK, nil
}

// convertToLattigoConvention applies pi^{-1} to each GadgetCiphertext component,
// converting from paper convention to lattigo convention in-place.
// Uses pre-allocated buffers for efficiency.
func (eval *Evaluator) convertToLattigoConvention(gk *rlwe.GaloisKey) error {

	paramsEval := eval.params.Eval

	galEl := gk.GaloisElement
	galElInv := paramsEval.ModInvGaloisElement(galEl)

	ringQ := paramsEval.RingQ()
	ringP := paramsEval.RingP()

	indexQ, err := ring.AutomorphismNTTIndex(ringQ.N(), ringQ.NthRoot(), galElInv)
	if err != nil {
		return fmt.Errorf("Q automorphism index: %w", err)
	}

	var indexP []uint64
	if ringP != nil {
		indexP, err = ring.AutomorphismNTTIndex(ringP.N(), ringP.NthRoot(), galElInv)
		if err != nil {
			return fmt.Errorf("P automorphism index: %w", err)
		}
	}

	for i := range gk.Value {
		for j := range gk.Value[i] {
			component := gk.Value[i][j]

			eval.automorphInPlaceQ(ringQ, indexQ, component[0].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[0].P)
			}

			eval.automorphInPlaceQ(ringQ, indexQ, component[1].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[1].P)
			}
		}
	}

	return nil
}

func (eval *Evaluator) automorphInPlaceQ(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpQ)
	p.CopyLvl(p.Level(), eval.autTmpQ)
}

func (eval *Evaluator) automorphInPlaceP(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpP)
	p.CopyLvl(p.Level(), eval.autTmpP)
}
