# Hierarchical Rotation Keys

[![Go](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

Hierarchical rotation key generation for [lattigo](https://github.com/tuneinsight/lattigo) v6 FHE library, reducing client-to-server key transmission cost.

Instead of transmitting one rotation key per needed cyclic shift, the client generates a small set of master rotation keys and sends them to the server. The server expands these into all required evaluation keys via the RotToRot algorithm. Derived keys are standard `rlwe.GaloisKey` objects, compatible with `rlwe.Evaluator`, `ckks.Evaluator.Rotate`, and hoisted rotations.

## Installation

```bash
go get github.com/butvinm/lattigo-hierkeys
```

## Two Schemes

|                      | **LLKN** (`llkn/`)                                      | **KG+** (`kgplus/`)                                      |
| -------------------- | ------------------------------------------------------- | -------------------------------------------------------- |
| Based on             | [Lee-Lee-Kim-No 2022](https://eprint.iacr.org/2022/532) | [Cheon-Kang-Park 2025](https://eprint.iacr.org/2025/720) |
| Ring switching       | No                                                      | Yes (extension ring R', degree 2N)                       |
| ConjugateInvariant   | Yes                                                     | No                                                       |
| NTT prime constraint | Standard (q ≡ 1 mod 2N)                                 | q ≡ 1 mod 4N                                             |

Both produce standard lattigo Galois keys.

## Quick Start

### k=2 (two-level hierarchy)

```go
import (
    hierkeys "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/llkn"
)

// LLKN k=2: one level of P primes
params, _ := llkn.NewParameters(paramsEval, [][]int{{61}})

// CLIENT
kgen := llkn.NewKeyGenerator(params)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, hierkeys.MasterRotationsForBase(4, slots))

// SERVER: one-shot derivation
evk, _ := llkn.DeriveGaloisKeys(params, tk, targetRotations)
eval := ckks.NewEvaluator(paramsEval, evk)
```

### k=3 with gradual expansion

```go
// LLKN k=3: two levels of P primes (P ≈ Q at each level for noise control)
params, _ := llkn.NewParameters(paramsEval, [][]int{
    {61, 61, 61, 61, 61, 61}, // P for level 1
    {61, 61, 61, 61, 61, 61}, // P for level 2
})

kgen := llkn.NewKeyGenerator(params)
sk := kgen.GenSecretKeyNew()
tk, _ := kgen.GenTransmissionKeys(sk, masterRots)

eval := llkn.NewEvaluator(params)

// Phase 1 (rare): top masters → level-1 keys
level1, _ := eval.ExpandLevel(1, tk.Shift0Keys[1], tk.MasterRotKeys, masterRots)
// store level1 to disk...

// Phase 2 (occasional): level-1 → level-0 keys
level0, _ := eval.ExpandLevel(0, tk.Shift0Keys[0], level1.Keys, targetRots)
// store level0 to disk...

// Phase 3 (on-demand): finalize to eval keys
evk, _ := eval.FinalizeKeys(level0)
```

Replace `llkn` with `kgplus` for the KG+ scheme — the API pattern is the same (KG+ adds a homing key for ring switching).

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

Parameters: `{Eval, HK, RPrime []rlwe.Parameters}` — RPrime[0] is level-0, RPrime[k-1] is top master (all degree 2N).

Pipeline: `GenTransmissionKeys` → `ExpandLevel` (per-level) + `FinalizeKeys` → `rlwe.GaloisKey`.

### LLKN (`llkn/`)

Parameters: `{Levels []rlwe.Parameters}` — Levels[0] is eval, Levels[k-1] is top master.

Pipeline: `GenTransmissionKeys` → `ExpandLevel` (per-level) + `FinalizeKeys` → `rlwe.GaloisKey`.

## Benchmarks

256 target rotation keys, base-4, single-threaded CPU. Parameters are **insecure** (small N for fast testing) — see the papers for production parameter selection under security constraints.

**Scheme configurations** (each uses the same eval-level Q and P):

| Scheme                         | Masters | m   | dnum      | Modulus bit length    | Max modulus |
| ------------------------------ | ------- | --- | --------- | --------------------- | ----------- |
| **LogN=10, Q=5×55b, P=1×56b**  |         |     |           |                       |             |
| Conventional                   | —       | 256 | (5)       | (275, 56)             | 331         |
| LLKN k=2                       | base-4  | 5   | (5, 6)    | (275, 56, 56)         | 387         |
| KG+ k=3                        | {1, 4}  | 2   | (5, 2, 1) | (275, 56, 280, 616)   | 1227 / R'   |
| **LogN=12, Q=8×55b, P=2×56b**  |         |     |           |                       |             |
| Conventional                   | —       | 256 | (4)       | (440, 112)            | 552         |
| LLKN k=2                       | base-4  | 6   | (4, 10)   | (440, 112, 56)        | 608         |
| KG+ k=3                        | {1, 4}  | 2   | (4, 2, 1) | (440, 112, 448, 1008) | 2008 / R'   |
| **LogN=14, Q=14×55b, P=3×56b** |         |     |           |                       |             |
| Conventional                   | —       | 256 | (5)       | (770, 168)            | 938         |
| LLKN k=2                       | base-4  | 7   | (5, 17)   | (770, 168, 56)        | 994         |
| KG+ k=3                        | {1, 4}  | 2   | (5, 2, 1) | (770, 168, 784, 1736) | 3458 / R'   |

**Results:**

| LogN | Conventional | LLKN k=2    | KG+ k=3     |
| ---- | ------------ | ----------- | ----------- |
| 10   | 120 MB       | 4 MB / 1s   | 3 MB / 4s   |
| 12   | 640 MB       | 44 MB / 11s | 21 MB / 27s |
| 14   | 5.4 GB       | 557 MB / 3m | 151 MB / 5m |

Format: transmission key size / server derivation time.

```bash
go test -bench BenchmarkKeySizes -benchtime 1x -run ^NONE ./...
go test -bench BenchmarkDeriveGaloisKeys -benchtime 1x -run ^NONE -timeout 60m ./...
```

## Build & Test

```bash
go build ./...
go test -v -count=1 -short ./kgplus/...
go test -v -count=1 -short ./llkn/...
```

## Examples

Both examples demonstrate k=3 hierarchy with the gradual (per-level) inactive/active expansion pattern:

```bash
cd example
go run ./kgplus/   # KG+ k=3 with ring switching
go run ./llkn/     # LLKN k=3, same ring
```

## License

Apache 2.0
