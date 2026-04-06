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

### LLKN 2-level (two-level hierarchy)

```go
// LLKN 2-level: one level of P primes
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

### KG+ 3-level with gradual expansion

KG+ uses an extension ring R' (degree 2N) and ring switching. The client generates two independent secrets, constructs an extended secret in R', and sends a homing key for ring switching.

See `example/kgplus/simple` for the complete flow.

## Benchmarks

256 target rotation keys, base-4. All parameter sets are **128-bit secure** (h=N/2 sparse ternary, σ=3.2, Q_max from Mono et al., AFRICACRYPT 2023, matching LLKN/KG+ papers).

Convention: q₀=55b, qᵢ=40b (Δ=2⁴⁰), Pᵢ=55b (eval), hierarchy P primes also 55b.

**Critical**: hierarchy P prime size must be ≥ max eval prime size. Lattigo's gadget
decomposition is count-based (`dnum = ceil(QCount/PCount)`) with each digit holding
exactly PCount consecutive Q primes. Smaller hierarchy P primes cause noise to blow
up by `2^(max_digit_bits − P_bits)` per RotToRot. See CLAUDE.md "Noise from
GadgetProduct". Verified empirically via `scripts/measure_noise.go`.

**Scheme configurations:**

```
LogN=14 (Q_max(N)=429, Q_max(2N)=857):

  Eval: Q=[55]+[40]×4=215b  P=[55]×2=110b  QP=325/429  depth=4  dnum=3

  LLKN 2-level (7 masters {1,4,16,64,256,1024,4096}):
    L1 (master): Q=325b  P=[55]×1=55b  QP=380/429  dnum=7

  KG+ 3-level (2 masters {1,64}):
    Homing:  Q=325b  P=[55]×1=55b   QP=380/429  dnum=7
    L1 (R'): Q=380b  P=[55]×1=55b   QP=435/857  dnum=7
    L2 (R'): Q=435b  P=[55]×7=385b  QP=820/857  dnum=2

LogN=15 (Q_max(N)=857, Q_max(2N)=1714):

  Eval: Q=[55]+[40]×9=415b  P=[55]×3=165b  QP=580/857  depth=9  dnum=3

  LLKN 2-level (7 masters {1,4,...,4096}):
    L1 (master): Q=580b  P=[55]×5=275b  QP=855/857  dnum=3

  KG+ 3-level (2 masters {1,64}):
    Homing:  Q=580b  P=[55]×5=275b   QP=855/857   dnum=3
    L1 (R'): Q=855b  P=[55]×5=275b   QP=1130/1714 dnum=3
    L2 (R'): Q=1130b P=[55]×10=550b  QP=1680/1714 dnum=2

LogN=16 (Q_max(N)=1714, Q_max(2N)=3428):

  Eval: Q=[55]+[40]×27=1135b  P=[55]×4=220b  QP=1355/1714  depth=27  dnum=6

  LLKN 2-level (8 masters {1,4,...,16384}):
    L1 (master): Q=1355b  P=[55]×6=330b  QP=1685/1714  dnum=6

  KG+ 3-level (2 masters {1,256}):
    Homing:  Q=1355b  P=[55]×6=330b    QP=1685/1714  dnum=6
    L1 (R'): Q=1685b  P=[55]×6=330b    QP=2015/3428  dnum=6
    L2 (R'): Q=2015b  P=[55]×25=1375b  QP=3390/3428  dnum=2
```

**Transmission key sizes:**

| LogN | Conventional | LLKN 2-level | KG+ 3-level |
| ---- | ------------ | -------- | ------- |
| 14   | TBD          | TBD      | TBD     |
| 15   | TBD          | TBD      | TBD     |
| 16   | TBD          | TBD      | TBD     |

**Client TX generation time:**

| LogN | LLKN 2-level | KG+ 3-level |
| ---- | -------- | ------- |
| 14   | TBD      | TBD     |
| 15   | TBD      | TBD     |
| 16   | TBD      | TBD     |

**Server derivation time:**

| LogN | LLKN 2-level | KG+ 3-level |
| ---- | -------- | ------- |
| 14   | TBD      | TBD     |
| 15   | TBD      | TBD     |
| 16   | TBD      | TBD     |

```bash
go test -bench BenchmarkKeySizes -benchtime 1x -run ^$ ./...
go test -bench BenchmarkDeriveGaloisKeys -benchtime 1x -run ^$ -timeout 60m ./...
go test -bench BenchmarkGenTransmissionKeys -benchtime 1x -run ^$ ./...
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
go run ./llkn/simple/       # minimal 2-level derivation
go run ./llkn/leveled/      # per-level ExpandLevel (inactive/active pattern)
go run ./llkn/multiparty/   # N-out-of-N multiparty
go run ./kgplus/simple/     # 3-level derivation with ring switching
go run ./kgplus/leveled/    # per-level ExpandLevel with ring switching
go run ./kgplus/multiparty/ # N-out-of-N multiparty with ring switching
```

## License

Apache 2.0
