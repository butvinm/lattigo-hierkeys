// KG+ hierarchical rotation keys — N-out-of-N multiparty key generation.
//
// KG+ multiparty requires each party to generate two independent secrets
// (s_i, s̃₁_i) and construct an extended secret s̃_i = s_i + Y·s̃₁_i in R'.
// Three collective protocols run in parallel:
//   - EvaluationKeyGenProtocol for the homing key (s̃₁ → s at HK level)
//   - PublicKeyGenProtocol for the collective public key (in R')
//   - GaloisKeyGenProtocol for master rotation keys (in R')
//
// The server-side derivation is identical to single-party — it cannot
// distinguish multiparty keys from single-party ones.
package main

import (
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/kgplus"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const nParties = 3

func main() {
	var err error

	// --- CKKS + KG+ parameters (same as simple example) ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
		LogNthRoot:      16,
	}); err != nil {
		panic(err)
	}

	var params kgplus.Parameters
	if params, err = kgplus.NewParameters(ckksParams.Parameters,
		[]int{56},
		[]int{56},
	); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topLevel := params.NumLevels() - 1
	topParams := params.RPrime[topLevel]
	fmt.Printf("KG+ CKKS multiparty (N=%d, k=%d): LogN=%d, %d slots\n",
		nParties, params.NumLevels(), ckksParams.LogN(), slots)

	crs, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}

	// =========================================================================
	// PARTIES: each generates two secrets and constructs extended secret in R'
	// =========================================================================
	// s_i:   main secret at HK level (degree N)
	// s̃₁_i: auxiliary secret at HK level (degree N), independent from s_i
	// s̃_i:  extended secret s_i + Y·s̃₁_i in R' (degree 2N)
	//
	// The homing key enables ring-switching from s̃₁ back to s.
	// The public key and master keys are generated under s̃ in R'.

	kgenHK := rlwe.NewKeyGenerator(params.HK)
	sks := make([]*rlwe.SecretKey, nParties)
	skS1s := make([]*rlwe.SecretKey, nParties)
	skExts := make([]*rlwe.SecretKey, nParties)

	for i := range sks {
		sks[i] = kgenHK.GenSecretKeyNew()
		skS1s[i] = kgenHK.GenSecretKeyNew()
		skExts[i] = kgplus.ConstructExtendedSK(params.HK, topParams, sks[i], skS1s[i])
	}

	// Ideal HK-level secret for verification only.
	skIdealHK := rlwe.NewSecretKey(params.HK)
	for _, sk := range sks {
		params.HK.RingQP().Add(skIdealHK.Value, sk.Value, skIdealHK.Value)
	}

	// =========================================================================
	// PHASE 1: Collective homing key — EvalKey(s̃₁ → s) at HK level
	// =========================================================================
	// The homing key is NOT a GaloisKey — it's an EvaluationKey that switches
	// from the auxiliary secret s̃₁ to the main secret s. We use
	// EvaluationKeyGenProtocol directly, not GaloisKeyGenProtocol.
	// Each party contributes GenShare(skIn=s̃₁_i, skOut=s_i).

	hkProto := multiparty.NewEvaluationKeyGenProtocol(params.HK)
	hkCRP := hkProto.SampleCRP(crs)
	hkAcc := hkProto.AllocateShare()

	for i := range sks {
		share := hkProto.AllocateShare()
		if err = hkProto.GenShare(skS1s[i], sks[i], hkCRP, &share); err != nil {
			panic(err)
		}
		if err = hkProto.AggregateShares(hkAcc, share, &hkAcc); err != nil {
			panic(err)
		}
	}

	homingKey := rlwe.NewEvaluationKey(params.HK)
	if err = hkProto.GenEvaluationKey(hkAcc, hkCRP, homingKey); err != nil {
		panic(err)
	}
	fmt.Println("Collective homing key generated")

	// =========================================================================
	// PHASE 2: Collective public key in R' at top level
	// =========================================================================
	// Generated under the extended secret s̃ = sum(s̃_i).
	// Serves the same purpose as single-party: PubToRot + encryption.

	cpkProto := multiparty.NewPublicKeyGenProtocol(topParams)
	cpkCRP := cpkProto.SampleCRP(crs)
	cpkAgg := cpkProto.AllocateShare()

	for _, ske := range skExts {
		share := cpkProto.AllocateShare()
		cpkProto.GenShare(ske, cpkCRP, &share)
		cpkProto.AggregateShares(cpkAgg, share, &cpkAgg)
	}

	collectivePK := rlwe.NewPublicKey(topParams)
	cpkProto.GenPublicKey(cpkAgg, cpkCRP, collectivePK)
	fmt.Println("Collective public key generated")

	// =========================================================================
	// PHASE 3: Collective master rotation keys in R'
	// =========================================================================
	// Standard GaloisKeyGenProtocol, using the extended secrets s̃_i.
	// GaloisKeyToMasterKey converts to the format needed by RotToRot.

	k3Masters := []int{1, 4}
	gkg := multiparty.NewGaloisKeyGenProtocol(topParams)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(k3Masters))

	for _, rot := range k3Masters {
		galEl := topParams.GaloisElement(rot)

		crp := gkg.SampleCRP(crs)
		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl // must set before first AggregateShares

		for _, ske := range skExts {
			share := gkg.AllocateShare()
			if err = gkg.GenShare(ske, galEl, crp, &share); err != nil {
				panic(err)
			}
			if err = gkg.AggregateShares(acc, share, &acc); err != nil {
				panic(err)
			}
		}

		gk := rlwe.NewGaloisKey(topParams)
		if err = gkg.GenGaloisKey(acc, crp, gk); err != nil {
			panic(err)
		}
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}
	fmt.Printf("Collective master keys generated: %d keys for rotations %v\n", len(k3Masters), k3Masters)

	// =========================================================================
	// SERVER: per-level expansion (identical to single-party leveled example)
	// =========================================================================

	tk := &kgplus.TransmissionKeys{
		HomingKey:     homingKey,
		PublicKey:     collectivePK,
		MasterRotKeys: masterKeys,
	}
	fmt.Printf("TX size = %.1f MB\n", float64(tk.BinarySize())/(1024*1024))

	eval := kgplus.NewEvaluator(params)
	masterRots := hierkeys.MasterRotationsForBase(4, slots)

	var shift0L1 *hierkeys.MasterKey
	if shift0L1, err = hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level1Keys *hierkeys.IntermediateKeys
	if level1Keys, err = eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots); err != nil {
		panic(err)
	}
	fmt.Printf("\nServer (inactive): derived %d intermediate keys in R'\n", len(level1Keys.Keys))

	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}
	var shift0L0 *hierkeys.MasterKey
	if shift0L0, err = hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey); err != nil {
		panic(err)
	}
	var level0Keys *hierkeys.IntermediateKeys
	if level0Keys, err = eval.ExpandLevel(0, shift0L0, level1Keys.Keys, targetRots); err != nil {
		panic(err)
	}
	fmt.Printf("Server (active): derived %d level-0 keys in R'\n", len(level0Keys.Keys))

	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(tk, level0Keys); err != nil {
		panic(err)
	}
	fmt.Printf("Server: finalized %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// =========================================================================
	// VERIFY
	// =========================================================================

	var skEval *rlwe.SecretKey
	if skEval, err = params.ProjectToEvalKey(skIdealHK); err != nil {
		panic(err)
	}
	ecd := ckks.NewEncoder(ckksParams)
	enc := rlwe.NewEncryptor(ckksParams, skEval)
	dec := rlwe.NewDecryptor(ckksParams, skEval)
	ckksEval := ckks.NewEvaluator(ckksParams, evk)

	values := make([]complex128, slots)
	for i := range values {
		values[i] = complex(float64(i+1), 0)
	}

	pt := ckks.NewPlaintext(ckksParams, ckksParams.MaxLevel())
	if err = ecd.Encode(values, pt); err != nil {
		panic(err)
	}

	var ct *rlwe.Ciphertext
	if ct, err = enc.EncryptNew(pt); err != nil {
		panic(err)
	}

	fmt.Println()
	for _, rot := range targetRots {
		ctRot := ckks.NewCiphertext(ckksParams, 1, ct.Level())
		if err = ckksEval.Rotate(ct, rot, ctRot); err != nil {
			panic(err)
		}

		want := make([]complex128, slots)
		for i := range want {
			want[i] = values[(i+rot)%slots]
		}

		printPrecision(ckksParams, ctRot, want, rot, ecd, dec)
	}
}

func printPrecision(params ckks.Parameters, ct *rlwe.Ciphertext, want []complex128, rot int, ecd *ckks.Encoder, dec *rlwe.Decryptor) {
	pt := dec.DecryptNew(ct)
	have := make([]complex128, ct.Slots())
	if err := ecd.Decode(pt, have); err != nil {
		panic(err)
	}

	var maxErr float64
	for i := range have {
		if e := cmplx.Abs(have[i] - want[i]); e > maxErr {
			maxErr = e
		}
	}

	fmt.Printf("Rot %3d: [%.0f, %.0f, %.0f, ...] -> [%.1f, %.1f, %.1f, ...]  maxErr: %.2e\n",
		rot,
		real(want[0]), real(want[1]), real(want[2]),
		real(have[0]), real(have[1]), real(have[2]),
		maxErr)
}
