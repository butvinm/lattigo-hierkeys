package hierkeys

import "sort"

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
// rotation indices. It uses a greedy approach: repeatedly subtract the largest
// master rotation that fits.
//
// Returns a sequence of master rotation indices whose sum equals target.
// For example, decomposeRotation(7, []int{1, 4}) returns [4, 1, 1, 1].
//
// Returns nil if target cannot be decomposed (e.g., target < 0 or no masters).
func decomposeRotation(target int, masterRots []int) []int {
	if target <= 0 || len(masterRots) == 0 {
		return nil
	}

	// Sort descending for greedy
	sorted := make([]int, len(masterRots))
	copy(sorted, masterRots)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))

	var result []int
	remaining := target
	for remaining > 0 {
		found := false
		for _, m := range sorted {
			if m <= remaining {
				result = append(result, m)
				remaining -= m
				found = true
				break
			}
		}
		if !found {
			return nil // cannot decompose
		}
	}
	return result
}
