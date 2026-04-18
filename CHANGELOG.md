# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-17

Initial release.

### Added

- Parent `hierkeys` package with shared primitives: `MasterKey`,
  `RotToRotEvaluator`, `LevelExpansion`, `IntermediateKeys`, `PubToRot`,
  `MasterRotationsForBase`, `DecomposeRotation`, `GenerateUniquePrimes`.
- `llkn` package — LLKN hierarchical rotation key derivation (no ring
  switching). Supports Standard and ConjugateInvariant ring types.
- `kgplus` package — KG+ hierarchical rotation key derivation with ring
  switching into R' (degree 2N). Standard ring only.
- k-level hierarchies (k≥2) in both schemes, enabling cascaded RotToRot
  derivation at intermediate levels.
- Thread-safe `LevelExpansion.Derive` via `sync.Once` dedup and
  pool-based scratch buffers.
- Single-party and N-out-of-N multiparty key generation support via
  lattigo's `rlwe.KeyGenerator` and `GaloisKeyGenProtocol`.
- Examples: `simple`, `concurrent`, `multiparty` for each scheme
  under `example/`.
- Benchmarks for key sizes, transmission-key generation, and server
  derivation (sequential and concurrent) at LogN=14/15/16.

### Known limitations

- No independent cryptographic audit.
- KG+ does not support ConjugateInvariant ring type.
- LogN=16 benchmark numbers in README are single-host, n=1.
