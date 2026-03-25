# Hierarchical Rotation Keys

[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

Hierarchical rotation key generation for [lattigo](https://github.com/tuneinsight/lattigo) v6 FHE library, reducing client-to-server key transmission cost.

Instead of transmitting one rotation key per needed cyclic shift, the client generates a small set of master rotation keys and sends them to the server. The server expands these into all required evaluation keys via the RotToRot algorithm. Derived keys are standard `rlwe.GaloisKey` objects, compatible with `rlwe.Evaluator`, `ckks.Evaluator.Rotate`, and hoisted rotations.

Based on:

1. [Towards Lightweight CKKS: On Client Cost Efficiency](https://eprint.iacr.org/2025/720) (Cheon, Kang, Park)
2. [Rotation Key Reduction for Client-Server Systems](https://eprint.iacr.org/2022/532) (Lee, Lee, Kim, No)

## Installation

```bash
go get github.com/butvinm/lattigo-hierkeys
```

## Two Schemes

|                         | **KG+** (`kgplus/`)                                      | **LLKN** (`llkn/`)                                      |
| ----------------------- | -------------------------------------------------------- | ------------------------------------------------------- |
| Based on                | [Cheon-Kang-Park 2025](https://eprint.iacr.org/2025/720) | [Lee-Lee-Kim-No 2022](https://eprint.iacr.org/2022/532) |
| Ring switching          | Yes (extension ring R', degree 2N)                       | No (same ring)                                          |
| ConjugateInvariant      | No                                                       | Yes                                                     |
| NTT prime constraint    | q ≡ 1 mod 4N                                             | Standard (q ≡ 1 mod 2N)                                 |
| Inactive/active pattern | Yes (Expand + FinalizeKeys)                              | Yes (Expand + FinalizeKeys)                             |

Both produce standard lattigo-convention keys. Both use k=2 hierarchy (master → eval).

## Quick Start

```go
import (
    hierkeys "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/kgplus" // or "github.com/butvinm/lattigo-hierkeys/llkn"
)

// Choose scheme: kgplus.NewParameters or llkn.NewParameters
params, _ := kgplus.NewParameters(paramsEval.Parameters, []int{61})

// CLIENT
kgen := kgplus.NewKeyGenerator(params)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, hierkeys.MasterRotationsForBase(4, slots))
// send tk to server

// SERVER
evk, _ := kgplus.DeriveGaloisKeys(params, tk, targetRotations)

// Standard CKKS evaluator
eval := ckks.NewEvaluator(paramsEval, evk)
eval.Rotate(ct, 3, ctRot)
```

Replace `kgplus` with `llkn` for the LLKN scheme — the API is the same.

## Architecture

### Parent package (`hierkeys`)

Shared utilities:

| Symbol                         | Purpose                                 |
| ------------------------------ | --------------------------------------- |
| `MasterRotationsForBase`       | Generate p-ary master rotation set      |
| `DecomposeRotation`            | Greedy p-ary decomposition              |
| `RotToRot` / `RotToRotBuffers` | Core RotToRot algorithm (parameterized) |
| `ConvertToLattigoConvention`   | Paper → lattigo convention conversion   |

### KG+ (`kgplus/`)

Four parameter tiers: Eval, HK, RPrime, RPrimeMaster.

Pipeline: `GenTransmissionKeys` → `Expand` + `FinalizeKeys` → `rlwe.GaloisKey`.

Supports the inactive/active key management pattern: pre-expand R' intermediates (expensive, cacheable), finalize to eval keys on demand (cheap).

### LLKN (`llkn/`)

Two parameter tiers: Eval, Master (same degree N).

Pipeline: `GenTransmissionKeys` → `DeriveGaloisKeys` → `rlwe.GaloisKey`.

Single-phase derivation, no intermediate step.

## Benchmarks

Transmission key sizes for 256 derived rotation keys (base-4 master set, k=2 hierarchy):

| LogN | Q   | P   | Conventional | KG+          | LLKN         |
| ---- | --- | --- | ------------ | ------------ | ------------ |
| 10   | 5   | 1   | 120 MB       | 8 MB (7%)    | 4 MB (3%)    |
| 12   | 8   | 2   | 640 MB       | 94 MB (15%)  | 44 MB (7%)   |
| 14   | 14  | 3   | 5.4 GB       | 1.2 GB (22%) | 557 MB (10%) |
| 15   | 22  | 5   | 17.3 GB      | 1.6 GB (9%)  | 740 MB (4%)  |

Percentages are vs conventional (one `rlwe.GaloisKey` per rotation).

At k=2 with small P_hk, LLKN produces smaller transmission keys because KG+ master keys live in R' (degree 2N). The [Cheon-Kang-Park paper](https://eprint.iacr.org/2025/720) reports 0.3-0.6 GB for KG+ at N=2^16 using a k=3 hierarchy with dnum=1 master keys — a regime not yet implemented here.

```bash
go test -bench BenchmarkKeySizes -benchtime 1x -run ^$ -timeout 30m ./...
go test -bench BenchmarkDeriveGaloisKeys -benchtime 3x -run ^$ ./...
```

## Build & Test

```bash
go build ./...
go test -v -count=1 -short ./kgplus/...
go test -v -count=1 -short ./llkn/...
```

## Examples

```bash
cd example
go run ./kgplus/   # KG+ with inactive key management pattern
go run ./llkn/     # LLKN single-phase derivation
```

## License

Apache 2.0
