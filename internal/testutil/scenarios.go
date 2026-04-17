// Package testutil provides shared parameter scenarios for tests and benchmarks.
// Not part of the public API — importable only within this module.
package testutil

// Scenario is a concrete 128-bit-secure parameter set for a given ring degree.
// Used by both benchmarks (256 target rotations, full sparse set) and tests (reduced target set, production-params smoke coverage).
//
// h=N/2 sparse ternary, σ=3.2, Δ=2^40, Q_max from lattice estimator [32].
// Convention: q₀=55b, qᵢ=40b, Pᵢ=55b.
// Hierarchy primes also 55b.
//
// Hierarchy P primes (LogPHK, LogPExtra) must be ≥ max eval prime size.
// Lattigo's gadget decomposition is count-based: dnum = ceil(QCount/PCount),
// each digit holds PCount consecutive Q primes regardless of size.
// Noise blows up by 2^(max_digit_bits − P_bits) when P bits < max digit bits.
// See CLAUDE.md "Noise from GadgetProduct".
type Scenario struct {
	Name   string
	LogN   int
	LogQ   []int // Q prime bit-sizes (eval)
	LogP   []int // P prime bit-sizes (eval)
	LogPHK []int // 2-level LLKN master / KG+ HK P primes
	Base   int   // master rotation base (4 = base-4 decomposition)

	// KG+ 3-level additions.
	// LogPHK3 primes are P^(1) at Levels[1]; LogPExtra primes are P^(2) at Levels[2] (top).
	// Sized for dnum=1 at top when possible.
	LogPHK3   []int
	LogPExtra []int
}

func buildLogQ(n, bitSize int) []int {
	q := make([]int, n)
	for i := range q {
		q[i] = bitSize
	}
	return q
}

// Scenarios covers LogN=14/15/16 at 128-bit security.
// Shared between benchmarks and tests so production params are exercised by both.
var Scenarios = []Scenario{
	{
		// LogN=14: Q_max=429, Q_max(2N)=857.
		// depth=4, dnum_eval=3.
		// PHK = 1×55 (only fits 1 prime in margin=104b after eval QP=325).
		// LLKN dnum_master=7, KG+ dnum_hk=7, dnum_int=7, dnum_top=2.
		Name:      "LogN14_D4_P2",
		LogN:      14,
		LogQ:      append([]int{55}, buildLogQ(4, 40)...),
		LogP:      buildLogQ(2, 55),
		LogPHK:    buildLogQ(1, 55),
		Base:      4,
		LogPHK3:   buildLogQ(1, 55),
		LogPExtra: buildLogQ(7, 55),
	},
	{
		// LogN=15: Q_max=857, Q_max(2N)=1714.
		// depth=9, dnum_eval=3.
		// PHK = 5×55 (fits in margin=277b after eval QP=580).
		// LLKN dnum_master=3, KG+ dnum_hk=3, dnum_int=3, dnum_top=2.
		Name:      "LogN15_D9_P3",
		LogN:      15,
		LogQ:      append([]int{55}, buildLogQ(9, 40)...),
		LogP:      buildLogQ(3, 55),
		LogPHK:    buildLogQ(5, 55),
		Base:      4,
		LogPHK3:   buildLogQ(5, 55),
		LogPExtra: buildLogQ(10, 55),
	},
	{
		// LogN=16: Q_max=1714, Q_max(2N)=3428.
		// depth=27, dnum_eval=6.
		// PHK = 6×55 (fits in margin=359b after eval QP=1355).
		// LLKN dnum_master=6, KG+ dnum_hk=6, dnum_int=6, dnum_top=2.
		Name:      "LogN16_D27_P4",
		LogN:      16,
		LogQ:      append([]int{55}, buildLogQ(27, 40)...),
		LogP:      buildLogQ(4, 55),
		LogPHK:    buildLogQ(6, 55),
		Base:      4,
		LogPHK3:   buildLogQ(6, 55),
		LogPExtra: buildLogQ(25, 55),
	},
}

// ReducedTestTargets returns a small set of target rotations that exercise different decomposition chain lengths.
// Used by tests to verify end-to-end correctness at production scale without the cost of 256-target benchmarks.
//
//	1, 2, 3         — trivial single-step chains
//	7, 17           — non-powers-of-base, multi-step decomposition
//	64              — matches a single master rotation key (base-4, index 3)
//	100, 1000       — mid-range targets with multi-step chains
//	slots - 1       — boundary (near N/2)
func ReducedTestTargets(slots int) []int {
	return []int{1, 2, 3, 7, 17, 64, 100, 1000, slots - 1}
}
