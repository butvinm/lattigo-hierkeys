# Hierarchical Rotation Keys

The `hierkeys` package implements hierarchical rotation key generation via ring switching, reducing
the client-to-server key transmission cost for RLWE-based homomorphic encryption schemes.

Instead of transmitting one rotation key per needed cyclic shift, the client generates a small set of
master rotation keys in an extension ring R' (degree 2N) and sends them to the server. The server
expands these into all required evaluation keys via the RotToRot algorithm and ring switching. The
derived keys are standard `rlwe.GaloisKey` objects, compatible with `rlwe.Evaluator.Automorphism` and
`ckks.Evaluator.Rotate` without any special wrappers.

## References

1. Towards Lightweight CKKS: On Client Cost Efficiency (<https://eprint.iacr.org/2025/720>)
2. Rotation Key Reduction for Client-Server Systems of Deep Neural Network on Fully Homomorphic Encryption (<https://eprint.iacr.org/2022/532>)

## Quick Start

```go
// CKKS evaluation parameters. All Q and P primes must be NTT-friendly for
// degree 2N (q ≡ 1 mod 4N), not just N. Use explicit primes or generate
// with LogN+1 to ensure compatibility.
paramsEval, _ := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{...})

// Derive hierarchical key parameters (adds one auxiliary prime for ring switching)
hkParams, _ := hierkeys.NewParameters(paramsEval.Parameters, []int{61})

// CLIENT: generate and send master keys
kgen := hierkeys.NewKeyGenerator(hkParams)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, []int{1, 4, 16, 64, 256})
// Send tk to server. Keep sk for decryption.

// SERVER: derive evaluation keys via RotToRot expansion
evk, _ := hierkeys.DeriveGaloisKeys(hkParams, tk, targetRotations)

// Standard CKKS evaluator — nothing special
eval := ckks.NewEvaluator(paramsEval, evk)
eval.Rotate(ct, 3, ctRot) // just works
```

## Architecture

The package uses four parameter sets derived from the evaluation parameters plus auxiliary primes:

| Parameter Set  | Ring Degree | Q               | P      | Purpose                        |
| -------------- | ----------- | --------------- | ------ | ------------------------------ |
| `Eval`         | N           | Q_eval          | P_eval | Ciphertext evaluation          |
| `HK`           | N           | Q_eval ∪ P_eval | P_hk   | Homing key operations          |
| `RPrime`       | 2N          | Q_eval          | P_eval | Level-0 keys in extension ring |
| `RPrimeMaster` | 2N          | Q_eval ∪ P_eval | P_hk   | Master keys in extension ring  |

All primes must be NTT-friendly for degree 2N (i.e., q ≡ 1 mod 4N).

## Key Derivation Pipeline

**Client** generates transmission keys and sends them to the server:

1. `GenTransmissionKeys(sk, masterRotations)` produces:
   - Homing key (switches s̃₁ → s)
   - Shift-0 seed key (identity rotation in R')
   - Master rotation keys (one per master index, in R')

**Server** derives evaluation keys in two phases:

2. `ExpandInRPrime(tk, targetRotations)` — expensive, cacheable:
   - RotToRot: shift-0 + master(r) → intermediate key for rotation r
   - RotToRot: rot(r) + master(r') → intermediate key for rotation r+r'
   - Shared intermediates are computed once and reused

3. `FinalizeKeys(tk, intermediate)` — cheap, on-demand:
   - Ring switch each intermediate key from R' (degree 2N) to R (degree N)
   - Post-convert from paper convention to lattigo convention (π⁻¹ automorphism)

**Evaluation** uses standard lattigo — no special wrappers:

4. `ckks.NewEvaluator(params, evk)` then `eval.Rotate(ct, k, out)`

## Key Management Use Cases

Following the Lee-Lee-Kim-No paper (Section 2.2):

**Active:** Server pre-derives all evaluation keys and stores them for fast repeated use.

```go
evk, _ := eval.DeriveGaloisKeys(tk, allRotations)
```

**Inactive:** Server pre-expands R' intermediate keys (stores ~1/3 the size of full eval keys), and
finalizes to evaluation keys on demand when a service is requested.

```go
intermediate, _ := eval.ExpandInRPrime(tk, possibleRotations)
// ... later, when service is requested ...
evk, _ := eval.FinalizeKeys(tk, intermediate)
```

**Single use:** Server derives keys on demand and discards them after use.

```go
evk, _ := eval.DeriveGaloisKeys(tk, neededRotations)
// ... evaluate, then discard evk ...
```

## Package Structure

| File               | Contents                                                                 |
| ------------------ | ------------------------------------------------------------------------ |
| `params.go`        | `Parameters`, `NewParameters`                                            |
| `keygen.go`        | `KeyGenerator`, `TransmissionKeys`, `GenTransmissionKeys`                |
| `evaluator.go`     | `Evaluator` with pre-allocated buffers, `ShallowCopy`                    |
| `eval.go`          | `RingSwitchGaloisKey` (core ring switching)                              |
| `rottorot.go`      | `RotToRot` (hierarchical expansion in R')                                |
| `derive.go`        | `DeriveGaloisKeys`, `ExpandInRPrime`, `FinalizeKeys`, `IntermediateKeys` |
| `utils.go`         | `MasterRotationsForBase`, `decomposeRotation`                            |
| `serialization.go` | `TransmissionKeys` `WriteTo`/`ReadFrom`                                  |
