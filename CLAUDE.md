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

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single entry point (`TestKGPlus`, `TestLLKN`)
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z/k=K"`
- Pool-based buffers in evaluators (sync.Pool via lattigo's `ring.BufferPool`), thread-safe by default
- Error returns on public API, panics only for internal sanity checks
