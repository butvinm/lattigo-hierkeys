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

## Benchmarks

Transmission key sizes for 256 derived rotation keys (base-4 master set, Intel i7-1260P):

| LogN | Q   | P   | Conventional | KG+ TX       | LLKN TX      |
| ---- | --- | --- | ------------ | ------------ | ------------ |
| 10   | 5   | 1   | 120 MB       | 8 MB (7%)    | 4 MB (3%)    |
| 12   | 8   | 2   | 640 MB       | 94 MB (15%)  | 44 MB (7%)   |
| 14   | 14  | 3   | 5.4 GB       | 1.2 GB (22%) | 557 MB (10%) |
| 15   | 22  | 5   | 17.3 GB      | 1.6 GB (9%)  | 740 MB (4%)  |

Percentages are vs conventional (one standard GaloisKey per rotation).

KG+ master keys live in R' (degree 2N), so each polynomial is 2x larger than LLKN's. This makes KG+ larger at small-to-medium parameters with few P_hk primes (high gadget rank). KG+ becomes smaller when P_hk is large enough to reduce the gadget rank (`dnum`) to 1 — this requires the extension ring's doubled modulus budget (`Q_max,2N ≈ 2·Q_max,N`), which only has room at production scale. The [Cheon-Kang-Park paper](https://eprint.iacr.org/2025/720) benchmarks this regime (N = 2^16, Q ≈ 1300 bits, P_hk ≈ 1700 bits, 265 rotations) and reports 0.3-0.6 GB for KG+ vs 3.5 GB for LLKN.

**When to use which:**

- **LLKN**: prototyping, small/medium N, ConjugateInvariant ring, or when simplicity matters. Requires `PaperConventionEvaluator` for automorphisms.
- **KG+**: production PPML (N ≥ 2^16, hundreds of rotations) where the modulus budget allows dnum=1 master keys. Produces standard lattigo-convention keys.

Run benchmarks:

```bash
go test -bench BenchmarkKeySizes -benchtime 1x -run ^$ -timeout 30m ./...
go test -bench BenchmarkDeriveGaloisKeys -benchtime 3x -run ^$ ./...
```

## Examples

```bash
cd example
go run ./kgplus/   # KG+ with inactive key management
go run ./llkn/     # LLKN single-phase derivation
```
