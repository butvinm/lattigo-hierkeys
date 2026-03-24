package hierkeys

// MasterRotationsForBase returns the set of master rotation indices for a
// p-ary number system with the given base and number of slots.
//
// For base=4, nSlots=32768: returns {1, 4, 16, 64, 256, 1024, 4096, 16384}.
// These are powers of base up to nSlots/2 (since rotations are mod nSlots).
//
// With these master keys, any rotation can be decomposed as a sum of at most
// ceil(log_base(nSlots)) master rotations via RotToRot.
func MasterRotationsForBase(base, nSlots int) []int {
	if base < 2 || nSlots < 1 {
		return nil
	}
	rots := make([]int, 0)
	for p := 1; p <= nSlots/2; p *= base {
		rots = append(rots, p)
	}
	return rots
}

// decomposeRotation decomposes a target rotation as a sum of available master
// rotation indices, minimizing the number of steps (= RotToRot operations).
//
// Uses dynamic programming (unbounded knapsack / coin change). This handles
// non-canonical master sets correctly, e.g., decomposeRotation(6, [3, 5]) = [3, 3].
//
// Returns a sequence of master rotation indices whose sum equals target.
// Returns nil if target cannot be decomposed (e.g., target <= 0 or no masters).
func decomposeRotation(target int, masterRots []int) []int {
	if target <= 0 || len(masterRots) == 0 {
		return nil
	}

	// dp[i] = minimum number of steps to reach rotation i, or -1 if unreachable
	// parent[i] = which master rotation was used to reach i
	dp := make([]int, target+1)
	parent := make([]int, target+1)
	for i := range dp {
		dp[i] = -1
		parent[i] = -1
	}
	dp[0] = 0

	for i := 1; i <= target; i++ {
		for _, m := range masterRots {
			prev := i - m
			if prev >= 0 && dp[prev] >= 0 && (dp[i] < 0 || dp[prev]+1 < dp[i]) {
				dp[i] = dp[prev] + 1
				parent[i] = m
			}
		}
	}

	if dp[target] < 0 {
		return nil // unreachable
	}

	// Reconstruct path
	result := make([]int, 0, dp[target])
	for pos := target; pos > 0; pos -= parent[pos] {
		result = append(result, parent[pos])
	}
	return result
}
