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

Shared utilities: `MasterRotationsForBase`, `DecomposeRotation`, `RotToRot` (parameterized), `ConvertToLattigoConvention`.

### KG+ (`kgplus/`)

Parameters: `{Eval, HK, RPrime []rlwe.Parameters}` — RPrime[0] is level-0, RPrime[k-1] is top master (all degree 2N).

Key pipeline: GenTransmissionKeys (client) → Expand + FinalizeKeys (server) → standard rlwe.GaloisKey.

Ring-switched keys are post-converted from paper convention to lattigo convention via π⁻¹ automorphism. Only supports Standard ring type (not ConjugateInvariant).

### LLKN (`llkn/`)

Parameters: `{Levels []rlwe.Parameters}` — Levels[0] is eval, Levels[k-1] is top master.

Key pipeline: GenTransmissionKeys (client) → Expand + FinalizeKeys (server) → standard rlwe.GaloisKey.

Both Expand and FinalizeKeys support inactive/active key management pattern. Convention conversion is applied in FinalizeKeys. Output keys work with standard lattigo evaluators.

Supports both Standard and ConjugateInvariant ring types.

### Multi-level Expand (k>2)

Top-down cascade: at each intermediate level, derive the full master rotation set via RotToRot from the level above. At level 0, derive target rotations. Intermediate results are cached per-level.

## Known Gotchas

- **CopyLvl direction**: `pol.CopyLvl(level, p1)` copies FROM p1 TO pol. Double-check every call.
- **IMForm before INTT**: R' GadgetCiphertext is NTT+Montgomery. Must IMForm before INTT+extraction, or values mix with non-Montgomery GadgetProduct output.
- **NTT prime constraint (KG+ only)**: All primes must satisfy q ≡ 1 mod 4N (NTT-friendly for degree 2N). LogQ-generated primes for degree N may fail.
- **Convention mismatch (KG+)**: Ring switching produces paper-convention keys. Must post-convert (π⁻¹ automorphism) for standard lattigo evaluator compatibility.
- **Convention conversion**: Both KG+ and LLKN use ConvertToLattigoConvention (π⁻¹ automorphism) to convert RotToRot output from paper convention to lattigo convention.
- **Prime collision in multi-level**: When building parameter chains (Q\_{i+1} = Q_i ∪ P_i), P primes at each level MUST be distinct from all Q primes at that level. Lattigo's `GenModuli` does not enforce this. Both packages use `generateUniquePrimes` with an exclusion set.
- **Noise in multi-level (k>2)**: Derived keys used as masters amplify noise by Q/P in GadgetProduct. Intermediate levels need P ≈ Q primes (dnum ≈ 1) to keep noise manageable.
- **ConstructExtendedSK for k>2 (KG+)**: When RPrime Q includes primes beyond HK Q (i.e., HK P primes), the interleaving must also cover the HK P-prime slots. Otherwise, those coefficient slots are zero and the extended SK is incorrect.

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single entry point (`TestKGPlus`, `TestLLKN`)
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z/k=K"`
- Pre-allocated buffers in Evaluator struct, ConcurrentCopy for concurrency
- Error returns on public API, panics only for internal sanity checks
