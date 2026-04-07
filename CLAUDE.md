# CLAUDE.md

## Project

Standalone Go library implementing hierarchical rotation key generation for lattigo v6 FHE library.

Two schemes: KG+ (`kgplus/`) with ring switching, LLKN (`llkn/`) without.

Both support arbitrary k-level hierarchies (k≥2). For k>2, intermediate levels enable cascaded RotToRot derivation at the cost of additional P primes and server computation.

Based on:

- "Towards Lightweight CKKS" (Cheon, Kang, Park) — https://eprint.iacr.org/2025/720
- "Rotation Key Reduction" (Lee, Lee, Kim, No) — https://eprint.iacr.org/2022/532

## Papers

Reference papers are in `./papers/` (gitignored). Read them for algorithm details.

## Build & Test

**Always run tests, examples, and benchmarks sequentially — never simultaneously.
Parallel runs exceed available memory and cause OOM kills.**

```bash
go build ./...
go test -v -count=1 -short ./kgplus/...   # KG+ tests
go test -v -count=1 -short ./llkn/...     # LLKN tests
go test -v -count=1 ./...                  # full suite including LogN=14
go test -run "TestKGPlus/CKKSRotation" ./kgplus/...  # specific subtest
```

Go files are auto-formatted by gofmt via a PostToolUse hook (`.claude/hooks/gofmt.sh`).

## Architecture

### Parent package (`hierkeys`)

Shared primitives:

- `MasterKey` — rotation key type for hierarchical derivation. Wraps `*rlwe.GaloisKey`.
- `GaloisKeyToMasterKey` / `MasterKeyToGaloisKey` — convention conversion (mutate in-place, consume input).
- `RotToRotEvaluator` — thread-safe RotToRot with pool-based scratch buffers. Core key combination: shift-r + shift-r' → shift-(r+r').
- `PubToRot` — derives shift-0 MasterKey from `*rlwe.PublicKey`.
- `LevelExpansion` — thread-safe derivation session at one hierarchy level. Uses `sync.Once` per rotation for dedup. Created via `NewLevelExpansion`. Call `Derive` per target rotation, then `IntermediateKeys` to collect.
- `IntermediateKeys` — output of `LevelExpansion.IntermediateKeys`, input to next level or per-key `FinalizeKey`.
- `MasterRotationsForBase`, `DecomposeRotation` — rotation set utilities.
- `GenerateUniquePrimes` — collision-free NTT-friendly prime generation.

### KG+ (`kgplus/`)

Parameters: `{Eval, HK, RPrime []rlwe.Parameters}` — RPrime[0] is level-0, RPrime[k-1] is top master (all degree 2N). Only supports Standard ring type (not ConjugateInvariant).

TransmissionKeys: `{HomingKey *rlwe.EvaluationKey, PublicKey *rlwe.PublicKey, MasterRotKeys map[int]*MasterKey}`.

No KeyGenerator — users generate keys with standard `rlwe.KeyGenerator` and convert via `GaloisKeyToMasterKey`. Works with both single-party and multiparty (lattigo `GaloisKeyGenProtocol`).

`ConstructExtendedSK` builds s̃ = s + Y·s̃₁ in R' from two HK-level secrets. `ProjectToEvalKey` on Parameters projects top-level SK to eval level (with validation).

Server-side derivation: `PubToRot` → `NewLevelExpansion` (per level, call `Derive` per target) → `FinalizeKey` (per level-0 key, ring-switch + convention convert). Callers control concurrency by spawning goroutines around `Derive`/`FinalizeKey` and control peak heap by nilling `level0.Keys[r]` after handing the key off to `FinalizeKey`.

### LLKN (`llkn/`)

Parameters: `{Levels []rlwe.Parameters}` — Levels[0] is eval, Levels[k-1] is top master. Supports both Standard and ConjugateInvariant ring types.

TransmissionKeys: `{PublicKey *rlwe.PublicKey, MasterRotKeys map[int]*MasterKey}`.

Same key generation and server-side paths as KG+ (without ring switching).

### Examples

Each scheme has four examples in `example/<scheme>/`:

- `simple/` — minimal leveled derivation (PubToRot + NewLevelExpansion + FinalizeKey)
- `leveled/` — per-level `NewLevelExpansion` with inactive/active pattern
- `concurrent/` — `NewLevelExpansion` + goroutines for concurrent derivation
- `multiparty/` — N-out-of-N collective key generation via lattigo `GaloisKeyGenProtocol`

## Known Gotchas

- **CopyLvl direction**: `pol.CopyLvl(level, p1)` copies FROM p1 TO pol. Double-check every call.
- **IMForm before INTT**: R' GadgetCiphertext is NTT+Montgomery. Must IMForm before INTT+extraction, or values mix with non-Montgomery GadgetProduct output.
- **NTT prime constraint (KG+ only)**: All primes must satisfy q ≡ 1 mod 4N (NTT-friendly for degree 2N). LogQ-generated primes for degree N may fail.
- **Prime collision in multi-level**: When building parameter chains (Q\_{i+1} = Q_i ∪ P_i), P primes at each level MUST be distinct from all Q primes at that level. Lattigo's `GenModuli` does not enforce this. Both packages use `GenerateUniquePrimes` with an exclusion set.
- **Noise in multi-level (k>2)**: Each RotToRot adds noise proportional to √(dnum) × Q/P. Use many small P primes (e.g., 30b) to maximize total P within the budget — this lowers both dnum and Q/P. The paper uses large primes with high dnum (10-30); our optimized params use small primes with low dnum (2-3) and comparable or better noise.
- **ConstructExtendedSK for k>2 (KG+)**: When RPrime Q includes primes beyond HK Q (i.e., HK P primes), the interleaving must also cover the HK P-prime slots. Otherwise, those coefficient slots are zero and the extended SK is incorrect.
- **GaloisKeyGenProtocol accumulator**: When aggregating shares, the accumulator's `GaloisElement` must be set before the first `AggregateShares` call (it defaults to 0, causing a mismatch error).
- **LLKN shares Q_max with eval**: LLKN hierarchy P primes consume the same Q_max(N) budget as eval Q and P primes. Heavy eval parameters leave little room for hierarchy. KG+ avoids this via R' with Q_max(2N) ≈ 2×Q_max(N).

## Parameter Theory

### Modulus structure

Each RLWE parameter set has Q primes (ciphertext modulus) and P primes (key-switching auxiliary modulus):

- **Q primes**: each prime = one multiplication level. Count = circuit depth. Size = precision per level.
- **P primes**: used temporarily during key-switching, then divided out. More P = less noise, bigger keys.
- **Q_max(N)**: maximum total log2(Q×P) for ring degree N at 128-bit security. We use h=N/2 sparse ternary (σ=3.2) with values from the lattice estimator [32], matching the LLKN and KG+ papers:

  | Degree N | Q_max (bits) |
  | -------- | ------------ |
  | 2^14     | 429          |
  | 2^15     | 857          |
  | 2^16     | 1714         |
  | 2^17     | 3428         |

  Note: other sources give slightly different values for similar settings: Bossuat et al. 2024 (uniform ternary) gives 430/868/1747; HE Standard v1.1 gives 438/881/1782 for h=N/2. We use the paper-consistent values for direct comparison.

### dnum (gadget decomposition number)

`dnum = ceil(QCount / PCount)` — number of GadgetCiphertext components per key.

Each component = 2 polynomials of (QCount + PCount) × N coefficients. Affects:

- **Key size**: proportional to dnum. dnum=1 → smallest key.
- **GadgetProduct cost**: proportional to dnum. dnum=1 → fastest RotToRot.
- **GadgetProduct noise**: proportional to √(dnum) × Q/P. See noise section.

To reduce dnum: add more P primes. Each P prime costs ~20-55 bits of Q_max budget.

### Noise from GadgetProduct (lattigo's actual behavior)

**CRITICAL**: lattigo uses a count-based, fixed-window decomposition. Empirically verified at LogN=14:

```go
// core/rlwe/params.go
func (p Parameters) BaseRNSDecompositionVectorSize(levelQ, levelP int) int {
    return (levelQ + levelP + 1) / (levelP + 1)  // = ceil(QCount / PCount)
}
```

Digit `i` contains Q primes at indices `[i*PCount, (i+1)*PCount)` — exactly `PCount` consecutive primes per digit, **regardless of their bit sizes**. Digits are NOT bit-balanced.

The noise added by one GadgetProduct is bounded by the largest digit's bit-product divided by total P:

    noise_blowup ≈ 2^max(0, max_digit_bits − P_bits)

Where `max_digit_bits = sum of bit-sizes of the PCount Q primes in the largest digit`.

**The CORRECT rule**: avg(P prime bit-size) ≥ max(Q prime bit-size). For uniform Q this simplifies to **P prime size ≥ Q prime size**.

**Why "many small P primes" is WRONG (for lattigo specifically)**: the optimization is mathematically valid for the _bit-balanced_ gadget decomposition described in the LLKN/KG+ papers, where digits are formed by greedily packing Q primes until their product approaches P. Under that algorithm, more small P primes really do give lower dnum and lower noise.

Lattigo implements a _count-balanced_ simplification: each digit gets exactly `PCount` consecutive Q primes regardless of bit sizes. The two algorithms agree only when **all primes are the same size**. With mixed sizes, lattigo's static digit window can hold more bits than total P, breaking the noise bound. There is no API to override `dnum` or supply a custom decomposition — the only knob is the number of P primes, which controls dnum via `ceil(QCount/PCount)`.

So:

- The math in the papers is correct.
- The "many small primes" optimization is correct for that math.
- Lattigo's implementation requires uniform-size primes to realize that math.
- For hierarchy primes specifically (which mix with eval primes of a fixed size), this means hierarchy primes must match eval prime size.

**Empirical evidence (LogN=14, eval = 5×50b Q + 2×50b P, measured rotation error after Δ=2^40):**

| PHK config   | avg PHK | max Q | max digit | predicted  | rotation error |
| ------------ | ------- | ----- | --------- | ---------- | -------------- |
| 4×30b = 120b | 30      | 50    | 4×50=200  | BROKEN     | 2^62 ✗         |
| 3×40b = 120b | 40      | 50    | 3×50=150  | DEGRADED   | 2^12 ✗         |
| 2×60b = 120b | 60      | 50    | 2×50=100  | WORKS      | 2^-20 ✓        |
| 1×60b = 60b  | 60      | 50    | 1×50=50   | WORKS      | 2^-19 ✓        |
| 1×50b = 50b  | 50      | 50    | 1×50=50   | borderline | 2^-16 ✓        |

The 4×30b case gives FEWER digits (dnum=2 vs dnum=4) which looks "better" theoretically, but lattigo packs 4 large Q primes into each digit and the noise explodes.

### Hierarchy prime sizing (correct rule)

For hierarchical key derivation (LLKN, KG+):

1. **PHK prime size ≥ max(eval Q prime, eval P prime)** — typically use 50-60b primes matching the eval primes
2. **PExtra prime size ≥ max(level-1 Q prime)** — same rule applied at the master level
3. **dnum is determined by PHK count**: dnum = ceil(QCount / PCount). Choose PCount based on the noise/size tradeoff.

This is the OPPOSITE of what works for general dnum optimization theory — but it's what lattigo's implementation actually requires.

### What params affect what

**Eval-level Q primes** (fixed by application):

- Count = multiplication depth
- Size = precision per level
- Cannot be changed without affecting the circuit

**Eval-level P primes** (fixed by application):

- Determine eval key-switching noise during CKKS computation
- dnum_eval = ceil(QCount_eval / PCount_eval)

**Hierarchy P primes** (our optimization target):

- LLKN: P_master primes share Q_max(N) with eval. Budget = Q_max - Q_eval - P_eval.
- KG+: hierarchy is in R' with Q_max(2N). Separate budget, does not affect eval.

**For KG+ 3-level, `NewParameters(eval, logPHK, logPExtra)`**:

- `logPHK` serves DOUBLE DUTY: P primes for both HK level (degree N) and RPrime[1] (degree 2N)
  - Affects homing key size: dnum_hk = ceil(QCount_HK / len(logPHK))
  - Affects intermediate RotToRot cost: dnum_mid = ceil(QCount_RPrime1 / len(logPHK))
- `logPExtra`: P primes for top master level RPrime[k-1]
  - Affects master key size: dnum_top = ceil(QCount_top / len(logPExtra))

### Current optimized params

See README.md "Scheme configurations" for concrete parameter values per LogN. All use many small P primes (20-30b) for minimum dnum within Q_max.

### Why KG+ over LLKN

LLKN hierarchy shares Q_max(N) with the eval circuit. Heavy eval params (deep circuits) leave little room for hierarchy P primes → high dnum → large master keys.

KG+ moves the hierarchy to R' (degree 2N) with Q_max(2N) ≈ 2×Q_max(N). The eval budget is untouched. This matters for production params (LogN=16) where Q_eval + P_eval = 1355 of 1714 available — only 359 bits left for LLKN hierarchy, but 2073 bits available in R'.

### Why 3-level over 2-level

With 2-level, client sends m master keys (7-8 for base-4). With 3-level, client sends 2 master keys; server expands at the intermediate level.

3-level benefits:

- Fewer transmitted keys (2 vs 7-8)
- dnum=1 at top possible (smallest per-key size)
- Offline/online pattern: expand at intermediate level once, derive targets quickly

3-level costs:

- Extra level of RotToRot (server computation)
- More P primes consumed (larger QP at top)
- Level-1 chains from {1, bigMaster} can be long — use {1, p^(m/2)} to balance chain lengths

2-level is simpler and faster when the budget allows enough master keys with acceptable dnum.

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single entry point (`TestKGPlus`, `TestLLKN`)
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z/k=K"`
- Pool-based buffers in evaluators (sync.Pool via lattigo's `ring.BufferPool`), thread-safe by default
- Error returns on public API, panics only for internal sanity checks
