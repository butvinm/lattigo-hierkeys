# Hierarchical Rotation Keys

[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://go.dev)
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
    "github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// LLKN k=2: one level of P primes
params, _ := llkn.NewParameters(paramsEval, [][]int{{61}})

// CLIENT: generate keys with standard lattigo, convert to MasterKeys
kgen := rlwe.NewKeyGenerator(params.Top())
sk := kgen.GenSecretKeyNew()
pk := kgen.GenPublicKeyNew(sk)

masterRots := hierkeys.MasterRotationsForBase(4, slots)
masterKeys := make(map[int]*hierkeys.MasterKey)
for _, rot := range masterRots {
    gk := kgen.GenGaloisKeyNew(params.Top().GaloisElement(rot), sk)
    masterKeys[rot], _ = hierkeys.GaloisKeyToMasterKey(params.Top(), gk)
}
tk := &llkn.TransmissionKeys{PublicKey: pk, MasterRotKeys: masterKeys}

// SERVER: one-shot derivation
eval := llkn.NewEvaluator(params)
evk, _ := eval.DeriveGaloisKeys(tk, targetRotations)

skEval, _ := params.ProjectToEvalKey(sk)
ckksEval := ckks.NewEvaluator(paramsEval, evk)
```

### KG+ k=3 with gradual expansion

```go
import (
    hierkeys "github.com/butvinm/lattigo-hierkeys"
    "github.com/butvinm/lattigo-hierkeys/kgplus"
    "github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// KG+ k=3: two levels of P primes in R' (degree 2N)
params, _ := kgplus.NewParameters(paramsEval, logPHK, logPExtra)
topLevel := params.NumLevels() - 1
topParams := params.RPrime[topLevel]

// CLIENT: generate keys with standard lattigo
kgenHK := rlwe.NewKeyGenerator(params.HK)
sk := kgenHK.GenSecretKeyNew()
sk1 := kgenHK.GenSecretKeyNew()
homingKey := kgenHK.GenEvaluationKeyNew(sk1, sk)

skExt := kgplus.ConstructExtendedSK(params.HK, topParams, sk, sk1)
kgenRP := rlwe.NewKeyGenerator(topParams)
pk := kgenRP.GenPublicKeyNew(skExt)

masterKeys := make(map[int]*hierkeys.MasterKey)
for _, rot := range []int{1, 4} { // {1, base}
    gk := kgenRP.GenGaloisKeyNew(topParams.GaloisElement(rot), skExt)
    masterKeys[rot], _ = hierkeys.GaloisKeyToMasterKey(topParams, gk)
}
tk := &kgplus.TransmissionKeys{HomingKey: homingKey, PublicKey: pk, MasterRotKeys: masterKeys}

// SERVER: per-level expansion with PubToRot
eval := kgplus.NewEvaluator(params)

// Phase 1 (inactive): derive full master set at intermediate level
shift0L1, _ := hierkeys.PubToRot(params.RPrime[1], params.RPrime[topLevel], tk.PublicKey)
level1, _ := eval.ExpandLevel(1, shift0L1, tk.MasterRotKeys, masterRots)

// Phase 2 (active): derive target keys at level 0
shift0L0, _ := hierkeys.PubToRot(params.RPrime[0], params.RPrime[topLevel], tk.PublicKey)
level0, _ := eval.ExpandLevel(0, shift0L0, level1.Keys, targetRots)

// Phase 3: ring-switch and finalize
evk, _ := eval.FinalizeKeys(tk, level0)
skEval, _ := params.ProjectToEvalKey(sk)
ckksEval := ckks.NewEvaluator(paramsEval, evk)
```

## Architecture

### Parent package (`hierkeys`)

Shared utilities:

| Symbol                         | Purpose                                     |
| ------------------------------ | ------------------------------------------- |
| `MasterKey`                    | Paper-convention key type for RotToRot      |
| `GaloisKeyToMasterKey`         | Lattigo GaloisKey → MasterKey (applies σ_r) |
| `MasterKeyToGaloisKey`         | MasterKey → lattigo GaloisKey (applies σ⁻¹) |
| `MasterRotationsForBase`       | Generate p-ary master rotation set          |
| `DecomposeRotation`            | Greedy p-ary decomposition                  |
| `RotToRot` / `RotToRotBuffers` | Core RotToRot algorithm with pre-alloc      |
| `PubToRot`                     | Derive shift-0 key from public key          |
| `GenerateUniquePrimes`         | Collision-free NTT-friendly prime gen       |

### KG+ (`kgplus/`)

Parameters: `{Eval, HK, RPrime []rlwe.Parameters}` — RPrime[0] is level-0, RPrime[k-1] is top master (all degree 2N).

Pipeline: `GaloisKeyToMasterKey` → `ExpandLevel` (per-level) + `FinalizeKeys` → `rlwe.GaloisKey`.

### LLKN (`llkn/`)

Parameters: `{Levels []rlwe.Parameters}` — Levels[0] is eval, Levels[k-1] is top master.

Pipeline: `GaloisKeyToMasterKey` → `ExpandLevel` (per-level) + `FinalizeKeys` → `rlwe.GaloisKey`.

## Benchmarks

256 target rotation keys, base-4, Intel Xeon GraniteRapids 16 vCPUs. All parameter sets are **128-bit secure** (HE Standard, ternary secret with h=N/2).

**Scheme configurations** (each uses the same eval-level Q and P):

| Scheme                            | Masters | m   | dnum       | Modulus bit length     | Max modulus |
| --------------------------------- | ------- | --- | ---------- | ---------------------- | ----------- |
| **LogN=14, Q=5×50b, P=2×50b**     |         |     |            |                        |             |
| Conventional                      | —       | 256 | (3)        | (253, 101)             | 354         |
| LLKN k=2                          | base-4  | 7   | (3, 7)     | (253, 101, 56)         | 411         |
| KG+ k=3                           | {1, 4}  | 2   | (3, 7, 8)  | (253, 101, 56, 56)     | 467 / R'    |
| **LogN=15, Q=55b+9×40b, P=3×61b** |         |     |            |                        |             |
| Conventional                      | —       | 256 | (4)        | (419, 183)             | 602         |
| LLKN k=2                          | base-4  | 7   | (4, 7)     | (419, 183, 122)        | 725         |
| KG+ k=3                           | {1, 4}  | 2   | (4, 2, 5)  | (419, 183, 610, 305)   | 1527 / R'   |
| **LogN=16, Q=24×55b, P=4×55b**    |         |     |            |                        |             |
| Conventional                      | —       | 256 | (6)        | (1332, 222)            | 1554        |
| LLKN k=2                          | base-4  | 8   | (6, 7)     | (1332, 222, 220)       | 1775        |
| KG+ k=3                           | {1, 4}  | 2   | (6, 10, 1) | (1332, 222, 171, 1705) | 3450 / R'   |

**Transmission key sizes:**

| LogN | Conventional | LLKN k=2        | KG+ k=3       |
| ---- | ------------ | --------------- | ------------- |
| 14   | 1,344 MB     | 100 MB (7.4%)   | 90 MB (6.7%)  |
| 15   | 6,656 MB     | 374 MB (5.6%)   | 326 MB (4.9%) |
| 16   | 43,009 MB    | 1,820 MB (4.2%) | 620 MB (1.4%) |

**Client TX generation time:**

| LogN | LLKN k=2 | KG+ k=3 |
| ---- | -------- | ------- |
| 14   | 0.4s     | 0.3s    |
| 15   | 1.3s     | 1.3s    |
| 16   | 7.0s     | 3.2s    |

**Server derivation time (sequential, single core):**

| LogN | LLKN k=2 | KG+ k=3 |
| ---- | -------- | ------- |
| 14   | 14s      | 48s     |
| 15   | 76s      | 217s    |
| 16   | 528s     | 2,179s  |

```bash
go test -bench BenchmarkKeySizes -benchtime 1x -run ^NONE ./...
go test -bench BenchmarkDeriveGaloisKeys -benchtime 1x -run ^NONE -timeout 60m ./...
go test -bench BenchmarkGenTransmissionKeys -benchtime 1x -run ^NONE ./...
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
go run ./llkn/simple/       # LLKN k=2: single-party
go run ./llkn/multiparty/   # LLKN k=2: N-out-of-N multiparty
go run ./kgplus/simple/     # KG+ k=3: single-party with ring switching
go run ./kgplus/multiparty/ # KG+ k=3: N-out-of-N multiparty
```

## License

Apache 2.0
