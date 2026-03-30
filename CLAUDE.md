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
- `LevelExpansion` — thread-safe derivation session at one hierarchy level. Uses `sync.Once` per rotation for dedup. Created via `NewLevelExpansion`.
- `ExpandLevel` — convenience wrapper: sequential derivation using `LevelExpansion`.
- `IntermediateKeys` — output of `ExpandLevel` / `LevelExpansion`, input to next level or `FinalizeKeys`.
- `MasterRotationsForBase`, `DecomposeRotation` — rotation set utilities.
- `GenerateUniquePrimes` — collision-free NTT-friendly prime generation.

### KG+ (`kgplus/`)

Parameters: `{Eval, HK, RPrime []rlwe.Parameters}` — RPrime[0] is level-0, RPrime[k-1] is top master (all degree 2N). Only supports Standard ring type (not ConjugateInvariant).

TransmissionKeys: `{HomingKey *rlwe.EvaluationKey, PublicKey *rlwe.PublicKey, MasterRotKeys map[int]*MasterKey}`.

No KeyGenerator — users generate keys with standard `rlwe.KeyGenerator` and convert via `GaloisKeyToMasterKey`. Works with both single-party and multiparty (lattigo `GaloisKeyGenProtocol`).

`ConstructExtendedSK` builds s̃ = s + Y·s̃₁ in R' from two HK-level secrets. `ProjectToEvalKey` on Parameters projects top-level SK to eval level (with validation).

Server-side derivation: `PubToRot` → `ExpandLevel` → `FinalizeKeys` (ring-switch + convention convert). Use `NewLevelExpansion` for concurrent derivation.

### LLKN (`llkn/`)

Parameters: `{Levels []rlwe.Parameters}` — Levels[0] is eval, Levels[k-1] is top master. Supports both Standard and ConjugateInvariant ring types.

TransmissionKeys: `{PublicKey *rlwe.PublicKey, MasterRotKeys map[int]*MasterKey}`.

Same key generation and server-side paths as KG+ (without ring switching).

### Examples

Each scheme has four examples in `example/<scheme>/`:

- `simple/` — minimal leveled derivation (PubToRot + ExpandLevel + FinalizeKeys)
- `leveled/` — per-level `ExpandLevel` with inactive/active pattern
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
- **Q_max(N)**: maximum total log2(Q×P) for ring degree N at 128-bit security. From HE Standard:

  | Degree N | Q_max (ternary secret) |
  | -------- | ---------------------- |
  | 2^14     | 438 bits               |
  | 2^15     | 881 bits               |
  | 2^16     | ~1761 bits             |
  | 2^17     | ~3500 bits             |

### dnum (gadget decomposition number)

`dnum = ceil(QCount / PCount)` — number of GadgetCiphertext components per key.

Each component = 2 polynomials of (QCount + PCount) × N coefficients. Affects:

- **Key size**: proportional to dnum. dnum=1 → smallest key.
- **GadgetProduct cost**: proportional to dnum. dnum=1 → fastest RotToRot.
- **GadgetProduct noise**: proportional to √(dnum) × Q/P. See noise section.

To reduce dnum: add more P primes. Each P prime costs ~20-55 bits of Q_max budget.

### Noise from GadgetProduct

Each RotToRot call does a GadgetProduct. The added noise is approximately:

    noise ∝ √(dnum) × (Q / P)

Where Q and P are the PRODUCTS of all Q and P primes at that level (2^total_bits).

Two factors:

1. **dnum** — fewer components = less noise accumulation. Lower is better.
2. **Q/P ratio** — larger total P product = smaller Q/P = less rounding error. Higher total P bits is better.

**Key insight**: many small P primes (e.g., 7×30b = 210 total bits) beat fewer large primes (2×55b = 110 total bits) on BOTH factors: lower dnum AND larger total P. This is because dnum depends on prime COUNT while Q/P depends on total BITS.

### Small primes optimization

Use many small NTT-friendly P primes (20-30 bits) instead of fewer large ones (55-60 bits):

    3 primes × 57b = 171 total bits, dnum = ceil(28/3) = 10
    10 primes × 30b = 300 total bits, dnum = ceil(28/10) = 3

Same Q_max budget consumed, but 10×30b gives:

- 3.3x lower dnum (3 vs 10) → faster RotToRot, smaller keys
- 1.75x larger total P (300b vs 171b) → less noise
- Strictly better on all axes

Constraint: primes must be NTT-friendly (q ≡ 1 mod NthRoot) and distinct from all other primes. With 30-bit primes and NthRoot=65536, there are ~millions of valid primes.

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

**For KG+ k=3, `NewParameters(eval, logPHK, logPExtra)`**:

- `logPHK` serves DOUBLE DUTY: P primes for both HK level (degree N) and RPrime[1] (degree 2N)
  - Affects homing key size: dnum_hk = ceil(QCount_HK / len(logPHK))
  - Affects intermediate RotToRot cost: dnum_mid = ceil(QCount_RPrime1 / len(logPHK))
- `logPExtra`: P primes for top master level RPrime[k-1]
  - Affects master key size: dnum_top = ceil(QCount_top / len(logPExtra))

### Current optimized params

All use many small primes for minimum dnum within Q_max:

```
LogN=14 (Q_max(N)=438, Q_max(2N)=881):
  LLKN:  P_master = 3×20b → dnum=3, QP=416 ≤ 438
  KG+:   P_hk = 4×30b → dnum_hk=2, dnum_mid=2
         P_top = 12×30b → dnum_top=1, QP=840 ≤ 881

LogN=15 (Q_max(N)=881, Q_max(2N)=1761):
  LLKN:  P_master = 7×25b → dnum=2, QP=782 ≤ 881
  KG+:   P_hk = 5×30b → dnum_hk=3, dnum_mid=3
         P_top = 18×30b → dnum_top=1, QP=1305 ≤ 1761

LogN=16 (Q_max(N)=1761, Q_max(2N)=3500):
  LLKN:  P_master = 6×30b → dnum=5, QP=1737 ≤ 1761
  KG+:   P_hk = 10×30b → dnum_hk=3, dnum_mid=3
         P_top = 38×30b → dnum_top=1, QP=3023 ≤ 3500
```

### Why KG+ over LLKN

LLKN hierarchy shares Q_max(N) with the eval circuit. Heavy eval params (deep circuits) leave little room for hierarchy P primes → high dnum → large master keys.

KG+ moves the hierarchy to R' (degree 2N) with Q_max(2N) ≈ 2×Q_max(N). The eval budget is untouched. This matters for production params (LogN=16) where Q_eval + P_eval = 1540 of 1761 available — only 221 bits left for LLKN hierarchy, but 1960 bits available in R'.

### Why k=3 over k=2

With k=2, client sends m master keys (7-8 for base-4). With k=3, client sends 2 master keys; server expands at the intermediate level.

k=3 benefits:

- Fewer transmitted keys (2 vs 7-8)
- dnum=1 at top possible (smallest per-key size)
- Offline/online pattern: expand at intermediate level once, derive targets quickly

k=3 costs:

- Extra level of RotToRot (server computation)
- More P primes consumed (larger QP at top)
- Level-1 chains from {1, bigMaster} can be long — use {1, p^(m/2)} to balance chain lengths

k=2 is simpler and faster when the budget allows enough master keys with acceptable dnum.

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single entry point (`TestKGPlus`, `TestLLKN`)
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z/k=K"`
- Pool-based buffers in evaluators (sync.Pool via lattigo's `ring.BufferPool`), thread-safe by default
- Error returns on public API, panics only for internal sanity checks
