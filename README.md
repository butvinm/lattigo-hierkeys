# Hierarchical Rotation Keys

Implements hierarchical rotation key generation for RLWE-based homomorphic encryption (lattigo v6),
reducing client-to-server key transmission cost.

Instead of transmitting one rotation key per needed cyclic shift, the client generates a small set of
master rotation keys and sends them to the server. The server expands these into all required evaluation
keys via the RotToRot algorithm.

Two schemes are provided:

| Scheme                    | Package   | Ring Switching     | CI Ring Support | Key Size |
| ------------------------- | --------- | ------------------ | --------------- | -------- |
| **KG+** (Cheon-Kang-Park) | `kgplus/` | Yes (R' degree 2N) | No              | Smaller  |
| **LLKN** (Lee-Lee-Kim-No) | `llkn/`   | No (same ring)     | Yes             | Larger   |

## References

1. Towards Lightweight CKKS: On Client Cost Efficiency (<https://eprint.iacr.org/2025/720>)
2. Rotation Key Reduction for Client-Server Systems (<https://eprint.iacr.org/2022/532>)

## Quick Start — KG+

KG+ uses ring switching to reduce key sizes. Only supports Standard ring type.
All primes must be NTT-friendly for degree 2N (q ≡ 1 mod 4N).

```go
import (
    hierkeys "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/kgplus"
)

// Derive hierarchical parameters (adds one auxiliary prime for ring switching)
hkParams, _ := kgplus.NewParameters(paramsEval.Parameters, []int{61})

// CLIENT: generate and send master keys
kgen := kgplus.NewKeyGenerator(hkParams)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, hierkeys.MasterRotationsForBase(4, slots))

// SERVER: derive evaluation keys
evk, _ := kgplus.DeriveGaloisKeys(hkParams, tk, targetRotations)

// Standard CKKS evaluator — keys are in lattigo convention
eval := ckks.NewEvaluator(paramsEval, evk)
eval.Rotate(ct, 3, ctRot) // just works
```

## Quick Start — LLKN

LLKN operates in the evaluation ring (no extension ring). Supports any ring type
including ConjugateInvariant.

```go
import (
    hierkeys "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/llkn"
)

// Derive hierarchical parameters (adds one auxiliary prime for master level)
llknParams, _ := llkn.NewParameters(paramsEval.Parameters, []int{61})

// CLIENT: generate and send master keys
kgen := llkn.NewKeyGenerator(llknParams)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, hierkeys.MasterRotationsForBase(4, slots))

// SERVER: derive evaluation keys
evk, _ := llkn.DeriveGaloisKeys(llknParams, tk, targetRotations)

// Use PaperConventionEvaluator (keys are in paper convention)
paperEval := llkn.NewPaperConventionEvaluator(paramsEval.Parameters, evk)
paperEval.Automorphism(ct, galEl, ctRot)
```

## Architecture

### Parent package (`hierkeys`)

Shared utilities used by both schemes:

| Symbol                         | Purpose                                 |
| ------------------------------ | --------------------------------------- |
| `MasterRotationsForBase`       | Generate p-ary master rotation set      |
| `DecomposeRotation`            | Greedy p-ary decomposition              |
| `RotToRot` / `RotToRotBuffers` | Core RotToRot algorithm (parameterized) |
| `ConvertToLattigoConvention`   | Paper → lattigo convention (KG+ only)   |

### KG+ (`kgplus/`)

Four parameter tiers: Eval, HK, RPrime, RPrimeMaster.

Key pipeline: `GenTransmissionKeys` (client) → `ExpandInRPrime` + `FinalizeKeys` (server) → standard `rlwe.GaloisKey`.

Supports the inactive/active pattern: pre-expand intermediates, finalize on demand.

### LLKN (`llkn/`)

Two parameter tiers: Eval, Master (same degree N).

Key pipeline: `GenTransmissionKeys` (client) → `DeriveGaloisKeys` (server) → paper convention `rlwe.GaloisKey`.

Output keys use paper convention (automorph-then-keyswitch). Use `PaperConventionEvaluator` for automorphisms.

## Build & Test

```bash
go build ./...
gofmt -w hierkeys.go rottorot.go kgplus/*.go llkn/*.go
go test -v -count=1 -short ./kgplus/...   # KG+ tests
go test -v -count=1 -short ./llkn/...     # LLKN tests
go test -v -count=1 ./...                  # full suite
```

## Examples

```bash
cd example
go run ./kgplus/   # KG+ with inactive key management
go run ./llkn/     # LLKN single-phase derivation
```
