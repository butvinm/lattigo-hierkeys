# CLAUDE.md

## Project

Standalone Go library implementing hierarchical rotation key generation for lattigo v6 FHE library.

Based on:

- "Towards Lightweight CKKS" (Cheon, Kang, Park) — https://eprint.iacr.org/2025/720
- "Rotation Key Reduction" (Lee, Lee, Kim, No) — https://eprint.iacr.org/2022/532

## Papers

Reference papers are in `./papers/` (gitignored). Read them for algorithm details.

## Build & Test

```bash
go build ./...
gofmt -w *.go                         # always format before commit
go test -v -count=1 -short ./...     # skip LogN=14 test (~2min)
go test -v -count=1 ./...            # full suite including LogN=14
go test -run "TestHierKeys/CKKSRotation" ./...  # specific subtest
```

## Architecture

Four parameter tiers: Q_eval, P_eval (evaluation), P_hk (consumed by ring switching).
Four rlwe.Parameters: Eval, HK, RPrime, RPrimeMaster — see params.go.

Key pipeline: GenTransmissionKeys (client) → ExpandInRPrime + FinalizeKeys (server) → standard rlwe.GaloisKey.

Ring-switched keys are post-converted from paper convention (automorph-then-keyswitch) to lattigo convention (keyswitch-then-automorph) by applying π⁻¹ to each GadgetCiphertext component.

## Known Gotchas

- **CopyLvl direction**: `pol.CopyLvl(level, p1)` copies FROM p1 TO pol. Double-check every call.
- **IMForm before INTT**: R' GadgetCiphertext is NTT+Montgomery. Must IMForm before INTT+extraction, or values mix with non-Montgomery GadgetProduct output.
- **NTT prime constraint**: All primes must satisfy q ≡ 1 mod 4N (NTT-friendly for degree 2N). LogQ-generated primes for degree N may fail.
- **Convention mismatch**: Ring switching produces paper-convention keys. Must post-convert (π⁻¹ automorphism) for standard lattigo evaluator compatibility.

## Code Style

Follow lattigo conventions:

- `var err error` + `if err = ...; err != nil` pattern
- Test functions: `func testXxx(tc *testContext, t *testing.T)` called from single `TestHierKeys` entry point
- Subtest names: `testString(params, "OpName")` → `"OpName/logN=X/Qi=Y/Pi=Z"`
- Pre-allocated buffers in Evaluator struct, ShallowCopy for concurrency
- Error returns on public API, panics only for internal sanity checks
