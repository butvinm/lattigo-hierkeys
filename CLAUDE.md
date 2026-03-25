# CLAUDE.md

## Project

Standalone Go library implementing hierarchical rotation key generation for lattigo v6 FHE library.

Two schemes: KG+ (`kgplus/`) with ring switching, LLKN (`llkn/`) without.

Based on:

- "Towards Lightweight CKKS" (Cheon, Kang, Park) — https://eprint.iacr.org/2025/720
- "Rotation Key Reduction" (Lee, Lee, Kim, No) — https://eprint.iacr.org/2022/532

## Papers

Reference papers are in `./papers/` (gitignored). Read them for algorithm details.

## Build & Test

```bash
go build ./...
gofmt -w hierkeys.go rottorot.go kgplus/*.go llkn/*.go  # always format before commit
go test -v -count=1 -short ./kgplus/...   # KG+ tests
go test -v -count=1 -short ./llkn/...     # LLKN tests
go test -v -count=1 ./...                  # full suite including LogN=14
go test -run "TestKGPlus/CKKSRotation" ./kgplus/...  # specific subtest
```

## Architecture

### Parent package (`hierkeys`)

Shared utilities: `MasterRotationsForBase`, `DecomposeRotation`, `RotToRot` (parameterized), `ConvertToLattigoConvention`.

### KG+ (`kgplus/`)

Four parameter tiers: Eval, HK, RPrime, RPrimeMaster — see `kgplus/params.go`.

Key pipeline: GenTransmissionKeys (client) → Expand + FinalizeKeys (server) → standard rlwe.GaloisKey.

Ring-switched keys are post-converted from paper convention to lattigo convention via π⁻¹ automorphism. Only supports Standard ring type (not ConjugateInvariant).

### LLKN (`llkn/`)

Two parameter tiers: Eval, Master — see `llkn/params.go`.

Key pipeline: GenTransmissionKeys (client) → DeriveGaloisKeys (server) → paper convention rlwe.GaloisKey.

Convention conversion is applied automatically in DeriveGaloisKeys. Output keys work with standard lattigo evaluators.

Supports both Standard and ConjugateInvariant ring types.

## Known Gotchas

- **CopyLvl direction**: `pol.CopyLvl(level, p1)` copies FROM p1 TO pol. Double-check every call.
- **IMForm before INTT**: R' GadgetCiphertext is NTT+Montgomery. Must IMForm before INTT+extraction, or values mix with non-Montgomery GadgetProduct output.
- **NTT prime constraint (KG+ only)**: All primes must satisfy q ≡ 1 mod 4N (NTT-friendly for degree 2N). LogQ-generated primes for degree N may fail.
- **Convention mismatch (KG+)**: Ring switching produces paper-convention keys. Must post-convert (π⁻¹ automorphism) for standard lattigo evaluator compatibility.
- **Convention conversion**: Both KG+ and LLKN use ConvertToLattigoConvention (π⁻¹ automorphism) to convert RotToRot output from paper convention to lattigo convention.

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single entry point (`TestKGPlus`, `TestLLKN`)
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z"`
- Pre-allocated buffers in Evaluator struct, ConcurrentCopy for concurrency
- Error returns on public API, panics only for internal sanity checks
