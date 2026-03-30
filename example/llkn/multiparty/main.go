// LLKN hierarchical rotation keys — N-out-of-N multiparty key generation.
//
// N parties collectively generate transmission keys without any single party
// knowing the full secret key. The server derives evaluation keys exactly as
// in the single-party case — it cannot distinguish multiparty keys from
// single-party ones.
//
// Uses lattigo's standard multiparty protocols:
//   - PublicKeyGenProtocol for the collective public key
//   - GaloisKeyGenProtocol for master rotation keys
//
// The ideal secret key s = sum(s_i) is computed only for verification.
// In a real deployment, parties use a collective decryption protocol instead.
package main

import (
	"fmt"
	"math/cmplx"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
	"github.com/butvinm/lattigo-hierkeys/llkn"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
)

const nParties = 3

func main() {
	var err error

	// --- CKKS + LLKN parameters (same as simple example) ---
	var ckksParams ckks.Parameters
	if ckksParams, err = ckks.NewParametersFromLiteral(ckks.ParametersLiteral{
		LogN:            14,
		LogQ:            []int{50, 50, 50, 50, 50},
		LogP:            []int{50, 50},
		LogDefaultScale: 50,
	}); err != nil {
		panic(err)
	}

	var params llkn.Parameters
	if params, err = llkn.NewParameters(ckksParams.Parameters, [][]int{
		{56},
	}); err != nil {
		panic(err)
	}

	slots := ckksParams.MaxSlots()
	topParams := params.Top()
	fmt.Printf("LLKN CKKS multiparty (N=%d, k=%d): LogN=%d, %d slots\n",
		nParties, params.NumLevels(), ckksParams.LogN(), slots)

	// =========================================================================
	// PARTIES: each generates a secret key independently
	// =========================================================================
	// All parties use the same parameters. Each sk_i is generated at the top
	// (master) level, same as single-party GenSecretKeyNew.

	kgen := rlwe.NewKeyGenerator(topParams)
	sks := make([]*rlwe.SecretKey, nParties)
	for i := range sks {
		sks[i] = kgen.GenSecretKeyNew()
	}

	// Common Reference String (CRS) — shared by all parties for deterministic
	// "a"-part generation in the multiparty protocols.
	crs, err := sampling.NewPRNG()
	if err != nil {
		panic(err)
	}

	// Ideal secret key s = sum(s_i) — for verification only.
	// In a real deployment, no single entity holds this.
	skIdeal := rlwe.NewSecretKey(topParams)
	for _, sk := range sks {
		topParams.RingQP().Add(skIdeal.Value, sk.Value, skIdeal.Value)
	}

	// =========================================================================
	// PHASE 1: Collective public key
	// =========================================================================
	// Each party generates a share from their sk_i. The aggregated shares
	// produce a public key for the ideal secret s = sum(s_i).
	// This public key serves two purposes:
	//   1. The server uses it in PubToRot to derive shift-0 keys
	//   2. Clients can use it for encryption (same pk works for both)

	cpkProto := multiparty.NewPublicKeyGenProtocol(topParams)
	cpkCRP := cpkProto.SampleCRP(crs)
	cpkAgg := cpkProto.AllocateShare()

	for _, sk := range sks {
		share := cpkProto.AllocateShare()
		cpkProto.GenShare(sk, cpkCRP, &share)
		cpkProto.AggregateShares(cpkAgg, share, &cpkAgg)
	}

	collectivePK := rlwe.NewPublicKey(topParams)
	cpkProto.GenPublicKey(cpkAgg, cpkCRP, collectivePK)
	fmt.Println("Collective public key generated")

	// =========================================================================
	// PHASE 2: Collective master rotation keys
	// =========================================================================
	// Each party generates a GaloisKey share for each master rotation.
	// GaloisKeyGenProtocol produces standard lattigo-convention GaloisKeys.
	// GaloisKeyToMasterKey converts them for use with RotToRot — same as
	// single-party, no multiparty-specific knowledge needed.
	//
	// Note: the accumulator's GaloisElement must be set before aggregation,
	// otherwise AggregateShares returns a mismatch error.

	masterRots := hierkeys.MasterRotationsForBase(4, slots)
	gkg := multiparty.NewGaloisKeyGenProtocol(topParams)
	masterKeys := make(map[int]*hierkeys.MasterKey, len(masterRots))

	for _, rot := range masterRots {
		galEl := topParams.GaloisElement(rot)

		crp := gkg.SampleCRP(crs)
		acc := gkg.AllocateShare()
		acc.GaloisElement = galEl // must set before first AggregateShares

		for _, sk := range sks {
			share := gkg.AllocateShare()
			if err = gkg.GenShare(sk, galEl, crp, &share); err != nil {
				panic(err)
			}
			if err = gkg.AggregateShares(acc, share, &acc); err != nil {
				panic(err)
			}
		}

		// Finalize the collective GaloisKey, then convert to MasterKey.
		gk := rlwe.NewGaloisKey(topParams)
		if err = gkg.GenGaloisKey(acc, crp, gk); err != nil {
			panic(err)
		}
		if masterKeys[rot], err = hierkeys.GaloisKeyToMasterKey(topParams, gk); err != nil {
			panic(err)
		}
	}
	fmt.Printf("Collective master keys generated: %d keys for rotations %v\n", len(masterRots), masterRots)

	// =========================================================================
	// SERVER: derive evaluation keys (identical to single-party)
	// =========================================================================

	tk := &llkn.TransmissionKeys{PublicKey: collectivePK, MasterRotKeys: masterKeys}
	fmt.Printf("TX size = %.1f MB\n", float64(tk.BinarySize())/(1024*1024))

	eval := llkn.NewEvaluator(params)
	targetRots := []int{1, 2, 3, 5, 7, 10, 50, 100}

	var shift0 *hierkeys.MasterKey
	if shift0, err = hierkeys.PubToRot(params.Levels[0], params.Top(), tk.PublicKey); err != nil {
		panic(err)
	}
	var level0 *hierkeys.IntermediateKeys
	if level0, err = eval.ExpandLevel(0, shift0, tk.MasterRotKeys, targetRots); err != nil {
		panic(err)
	}
	var evk *rlwe.MemEvaluationKeySet
	if evk, err = eval.FinalizeKeys(level0); err != nil {
		panic(err)
	}
	fmt.Printf("Server: derived %d evaluation keys\n", len(evk.GetGaloisKeysList()))

	// =========================================================================
	// VERIFY
	// =========================================================================

	var skEval *rlwe.SecretKey
	if skEval, err = params.ProjectToEvalKey(skIdeal); err != nil {
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
