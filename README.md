# Hierarchical Rotation Keys

[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

Hierarchical rotation key generation for [lattigo](https://github.com/tuneinsight/lattigo) v6 FHE library, reducing client-to-server key transmission cost.

Instead of transmitting one rotation key per needed cyclic shift, the client generates a small set of master rotation keys and sends them to the server. The server expands these into all required evaluation keys using the LLKN or KG+ algorithms. Derived keys are standard `rlwe.GaloisKey` objects, compatible with `rlwe.Evaluator`, `ckks.Evaluator.Rotate`, and hoisted rotations.

Both single-party and N-out-of-N multiparty key generation are supported (see [examples](#examples)).

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

### LLKN k=2 (two-level hierarchy)

```go
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
// send tk to server

// SERVER: one-shot derivation → standard lattigo evaluation keys
eval := llkn.NewEvaluator(params)
evk, _ := eval.DeriveGaloisKeys(tk, targetRotations)
```

### KG+ k=3 with gradual expansion

KG+ uses an extension ring R' (degree 2N) and ring switching. The client generates two independent secrets, constructs an extended secret in R', and sends a homing key for ring switching.

See `example/kgplus/simple` for the complete flow.

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
go run ./llkn/simple/       # one-shot DeriveGaloisKeys
go run ./llkn/leveled/      # per-level ExpandLevel (inactive/active pattern)
go run ./llkn/multiparty/   # N-out-of-N multiparty
go run ./kgplus/simple/     # one-shot DeriveGaloisKeys with ring switching
go run ./kgplus/leveled/    # per-level ExpandLevel with ring switching
go run ./kgplus/multiparty/ # N-out-of-N multiparty with ring switching
```

## License

Apache 2.0
