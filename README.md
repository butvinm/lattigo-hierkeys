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

// SERVER: derive standard lattigo evaluation keys
eval := llkn.NewEvaluator(params)
shift0, _ := hierkeys.PubToRot(params.Levels[0], params.Top(), tk.PublicKey)
level0, _ := eval.ExpandLevel(0, shift0, tk.MasterRotKeys, targetRotations)
evk, _ := eval.FinalizeKeys(level0)
```

### KG+ k=3 with gradual expansion

KG+ uses an extension ring R' (degree 2N) and ring switching. The client generates two independent secrets, constructs an extended secret in R', and sends a homing key for ring switching.

See `example/kgplus/simple` for the complete flow.

## Benchmarks

256 target rotation keys, base-4, Intel Xeon GraniteRapids 16 vCPUs. All parameter sets are **128-bit secure** (HE Standard, ternary secret).

**Scheme configurations:**

```
LogN=14 (Q_max(N)=438, Q_max(2N)=881):

  LLKN k=2: 7 master keys {1,4,16,64,256,1024,4096}, dnum=3
    Target level: Q=5×50b  P=2×50b  dnum=3  QP=350b
    Master level: Q=7×50b  P=3×20b  dnum=3  QP=416b ≤ 438

  KG+ k=3: 2 master keys {1,64}, dnum=1 (in R', degree 2N)
    Target level:       Q=5×50b   P=2×50b   dnum=3  QP=350b
    Intermediate level: Q=7×50b   P=4×30b   dnum=2  QP=470b
    Master level:       Q=11×~38b P=12×30b  dnum=1  QP=840b ≤ 881

LogN=15 (Q_max(N)=881, Q_max(2N)=1761):

  LLKN k=2: 7 master keys {1,4,...,4096}, dnum=2
    Target level: Q=10×~42b  P=3×61b  dnum=4   QP=602b
    Master level: Q=13×~46b  P=7×25b  dnum=2   QP=782b ≤ 881

  KG+ k=3: 2 master keys {1,64}, dnum=1 (in R', degree 2N)
    Target level:       Q=10×~42b  P=3×61b   dnum=4  QP=602b
    Intermediate level: Q=13×~46b  P=5×30b   dnum=3  QP=752b
    Master level:       Q=18×~40b  P=18×30b  dnum=1  QP=1305b ≤ 1761

LogN=16 (Q_max(N)=1761, Q_max(2N)=3500):

  LLKN k=2: 8 master keys {1,4,...,16384}, dnum=5
    Target level: Q=24×55b  P=4×55b  dnum=6  QP=1540b
    Master level: Q=28×55b  P=6×30b  dnum=5  QP=1737b ≤ 1761

  KG+ k=3: 2 master keys {1,256}, dnum=1 (in R', degree 2N)
    Target level:       Q=24×55b  P=4×55b   dnum=6  QP=1540b
    Intermediate level: Q=28×55b  P=10×30b  dnum=3   QP=1840b
    Master level:       Q=38×~40b P=38×30b  dnum=1   QP=3023b ≤ 3500
```

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
go run ./llkn/simple/       # minimal k=2 derivation
go run ./llkn/leveled/      # per-level ExpandLevel (inactive/active pattern)
go run ./llkn/multiparty/   # N-out-of-N multiparty
go run ./kgplus/simple/     # k=3 derivation with ring switching
go run ./kgplus/leveled/    # per-level ExpandLevel with ring switching
go run ./kgplus/multiparty/ # N-out-of-N multiparty with ring switching
```

## License

Apache 2.0
