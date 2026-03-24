package hierkeys

import (
	"fmt"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

// IntermediateKeys holds level-0 R' GaloisKeys produced by RotToRot expansion.
// These are in the paper's convention (not yet ring-switched or post-converted).
// They can be stored by the server for the "inactive" use case and later
// finalized to evaluation keys on demand via [Evaluator.FinalizeKeys].
type IntermediateKeys struct {
	Keys map[int]*rlwe.GaloisKey // indexed by rotation index, at RPrime level
}

// DeriveGaloisKeys is a convenience wrapper that creates a temporary
// Evaluator internally. For repeated calls or when performance matters,
// use [Evaluator.DeriveGaloisKeys].
func DeriveGaloisKeys(params Parameters, tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {
	eval := NewEvaluator(params)
	return eval.DeriveGaloisKeys(tk, targetRotations)
}

// DeriveGaloisKeys derives standard evaluation-level GaloisKeys from
// transmission keys. The returned keys work with lattigo's standard
// rlwe.Evaluator.Automorphism and ckks.Evaluator.Rotate.
//
// This is a convenience wrapper that calls [Evaluator.ExpandInRPrime]
// followed by [Evaluator.FinalizeKeys]. For finer control (e.g., storing
// intermediate keys for later finalization), call those methods directly.
//
// The returned MemEvaluationKeySet can be passed directly to
// rlwe.NewEvaluator or ckks.NewEvaluator.
func (eval *Evaluator) DeriveGaloisKeys(tk *TransmissionKeys, targetRotations []int) (*rlwe.MemEvaluationKeySet, error) {

	intermediate, err := eval.ExpandInRPrime(tk, targetRotations)
	if err != nil {
		return nil, err
	}

	return eval.FinalizeKeys(tk, intermediate)
}

// ExpandInRPrime expands master keys via RotToRot to produce level-0 R' keys
// for all target rotations. This is the expensive phase (~80% of total cost).
//
// Intermediate RotToRot results are cached: if multiple targets share a
// prefix in their decomposition (e.g., rot1 used by both rot2 and rot5),
// the shared intermediate is computed only once.
//
// The results can be stored for later finalization via [Evaluator.FinalizeKeys].
func (eval *Evaluator) ExpandInRPrime(tk *TransmissionKeys, targetRotations []int) (*IntermediateKeys, error) {

	if tk == nil || tk.Shift0Key == nil {
		return nil, fmt.Errorf("transmission keys and shift-0 key must not be nil")
	}

	// Extract available master rotation indices (sorted ascending for greedy decomposition)
	masterRots := make([]int, 0, len(tk.MasterRotKeys))
	for rot := range tk.MasterRotKeys {
		masterRots = append(masterRots, rot)
	}
	sort.Ints(masterRots)

	// Cache: rotation index -> R' level-0 key
	cache := make(map[int]*rlwe.GaloisKey)
	cache[0] = tk.Shift0Key // seed

	// Normalize negative rotations: CKKS rotation by -k = rotation by nSlots-k.
	nSlots := eval.params.Eval.N() / 2

	for _, target := range targetRotations {
		// Normalize to positive
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue // identity rotation, skip
		}

		if _, ok := cache[normalized]; ok {
			continue // already computed
		}

		steps := decomposeRotation(normalized, masterRots)
		if steps == nil {
			return nil, fmt.Errorf("cannot decompose rotation %d (normalized from %d) from available masters",
				normalized, target)
		}

		currentRot := 0
		for _, step := range steps {
			nextRot := currentRot + step

			if _, ok := cache[nextRot]; !ok {
				// Not cached — compute via RotToRot
				combinedGalEl := eval.params.RPrime.GaloisElement(nextRot)
				key, err := eval.RotToRot(cache[currentRot], tk.MasterRotKeys[step], combinedGalEl)
				if err != nil {
					return nil, fmt.Errorf("RotToRot step (current=%d + master=%d -> %d): %w",
						currentRot, step, nextRot, err)
				}
				cache[nextRot] = key
			}

			currentRot = nextRot
		}
	}

	// Extract requested targets (use original rotation index as key,
	// normalized index for cache lookup)
	result := &IntermediateKeys{Keys: make(map[int]*rlwe.GaloisKey, len(targetRotations))}
	for _, target := range targetRotations {
		normalized := ((target % nSlots) + nSlots) % nSlots
		if normalized == 0 {
			continue
		}
		result.Keys[target] = cache[normalized]
	}
	return result, nil
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

		// Post-convert from paper convention to lattigo convention
		if err := eval.convertToLattigoConvention(rsGK); err != nil {
			return nil, fmt.Errorf("convention conversion for rotation %d: %w", rot, err)
		}

		galoisKeys = append(galoisKeys, rsGK)
	}

	return rlwe.NewMemEvaluationKeySet(nil, galoisKeys...), nil
}

// convertToLattigoConvention applies pi^{-1} to each GadgetCiphertext component,
// converting from paper convention to lattigo convention in-place.
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

	// Apply pi^{-1} to each component using pre-allocated buffers
	for i := range gk.Value {
		for j := range gk.Value[i] {
			component := gk.Value[i][j]

			// b component
			eval.automorphInPlaceQ(ringQ, indexQ, component[0].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[0].P)
			}

			// a component
			eval.automorphInPlaceQ(ringQ, indexQ, component[1].Q)
			if ringP != nil {
				eval.automorphInPlaceP(ringP, indexP, component[1].P)
			}
		}
	}

	return nil
}

// automorphInPlaceQ applies an automorphism to a polynomial at Q level
// using the pre-allocated Q temporary buffer.
func (eval *Evaluator) automorphInPlaceQ(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpQ)
	p.CopyLvl(p.Level(), eval.autTmpQ)
}

// automorphInPlaceP applies an automorphism to a polynomial at P level
// using the pre-allocated P temporary buffer.
func (eval *Evaluator) automorphInPlaceP(r *ring.Ring, index []uint64, p ring.Poly) {
	r.AutomorphismNTTWithIndex(p, index, eval.autTmpP)
	p.CopyLvl(p.Level(), eval.autTmpP)
}

// automorphInPlace applies an automorphism to a polynomial using a pre-computed
// index. Allocates a temporary buffer internally — kept for backward compatibility
// with tests that call convertToLattigoConvention as a package-level function.
func automorphInPlace(r *ring.Ring, index []uint64, p ring.Poly) {
	tmp := r.NewPoly()
	r.AutomorphismNTTWithIndex(p, index, tmp)
	p.CopyLvl(p.Level(), tmp)
}

// convertToLattigoConvention is the package-level backward-compatible wrapper.
// It allocates temporary buffers per call. For repeated use, prefer
// [Evaluator.convertToLattigoConvention].
func convertToLattigoConvention(paramsEval rlwe.Parameters, gk *rlwe.GaloisKey) error {

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

			automorphInPlace(ringQ, indexQ, component[0].Q)
			if ringP != nil {
				automorphInPlace(ringP, indexP, component[0].P)
			}

			automorphInPlace(ringQ, indexQ, component[1].Q)
			if ringP != nil {
				automorphInPlace(ringP, indexP, component[1].P)
			}
		}
	}

	return nil
}
