// Compare greedy (current) vs MSA-based (LLKN paper Section 4.1)
// decomposition strategies for hierarchical rotation key derivation.
//
// Reports cached entries, max chain depth, and total RotToRot ops for both
// strategies on the real benchmark target sets and a few synthetic cases.
//
// Run: go run scripts/decompcompare/main.go
package main

import (
	"fmt"
	"sort"
	"strings"

	hierkeys "github.com/butvinm/lattigo-hierkeys"
)

// Target sets copied verbatim from benchmark_test.go.
var sparseTargets14 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 54, 64, 90, 96, 128, 160, 180, 192, 205, 218, 224, 245, 256, 261, 263, 270, 288, 320, 356, 360, 376, 384, 448, 450, 459, 512, 540, 570, 576, 585, 630, 640, 646, 654, 713, 720, 760, 768, 793, 810, 828, 838, 840, 896, 900, 913, 990, 1023, 1024, 1080, 1144, 1152, 1170, 1260, 1274, 1280, 1308, 1333, 1339, 1350, 1402, 1440, 1530, 1536, 1576, 1620, 1629, 1710, 1717, 1764, 1792, 1800, 1806, 1829, 1867, 1877, 1906, 1908, 2006, 2007, 2048, 2167, 2188, 2194, 2212, 2254, 2277, 2278, 2279, 2304, 2371, 2402, 2560, 2585, 2657, 2758, 2788, 2818, 2911, 2941, 2963, 2989, 3033, 3072, 3101, 3109, 3113, 3114, 3287, 3437, 3457, 3463, 3584, 3680, 3715, 3764, 3787, 4096, 4140, 4376, 4393, 4465, 4468, 4523, 4563, 4598, 4608, 4730, 4828, 4838, 4932, 4946, 4991, 5067, 5120, 5150, 5202, 5208, 5239, 5243, 5309, 5324, 5418, 5491, 5544, 5600, 5609, 5638, 5720, 5746, 5750, 5772, 5866, 5974, 5978, 6034, 6068, 6075, 6144, 6217, 6255, 6295, 6333, 6357, 6595, 6602, 6612, 6631, 6733, 6795, 6834, 6905, 6943, 7007, 7060, 7099, 7122, 7168, 7254, 7309, 7556, 7581, 7674, 7842, 7972, 8071, 8107, 8143, 8144, 8145, 8146, 8147, 8148, 8149, 8150, 8151, 8152, 8153, 8154, 8155, 8156, 8157, 8158, 8159, 8160, 8161, 8162, 8163, 8164, 8165, 8166, 8167, 8168, 8169, 8170, 8171, 8172, 8173, 8174, 8175, 8176, 8177, 8178, 8179, 8180, 8181, 8182, 8183, 8184, 8185, 8186, 8187, 8188, 8189, 8190, 8191}

var sparseTargets15 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 64, 96, 107, 128, 160, 192, 224, 256, 288, 320, 384, 410, 435, 448, 489, 512, 521, 526, 576, 640, 712, 751, 768, 896, 917, 1024, 1085, 1140, 1152, 1170, 1280, 1292, 1308, 1408, 1425, 1520, 1536, 1585, 1655, 1664, 1675, 1680, 1792, 1825, 1920, 2046, 2048, 2176, 2287, 2304, 2432, 2548, 2560, 2616, 2665, 2678, 2804, 3072, 3151, 3258, 3433, 3457, 3484, 3528, 3583, 3584, 3599, 3612, 3658, 3734, 3753, 3812, 3815, 4011, 4013, 4096, 4334, 4375, 4387, 4423, 4507, 4553, 4555, 4558, 4608, 4742, 4804, 5120, 5156, 5169, 5314, 5515, 5575, 5636, 5821, 5882, 5926, 5978, 6066, 6144, 6202, 6217, 6225, 6228, 6573, 6874, 6913, 6925, 7168, 7360, 7429, 7528, 7574, 8180, 8192, 8280, 8752, 8786, 8929, 8936, 9045, 9126, 9196, 9216, 9293, 9460, 9655, 9675, 9864, 9892, 9981, 10134, 10300, 10404, 10416, 10477, 10486, 10618, 10648, 10739, 10835, 10981, 11088, 11200, 11217, 11275, 11439, 11491, 11499, 11544, 11732, 11763, 11947, 11956, 12067, 12136, 12150, 12433, 12510, 12589, 12666, 12714, 13190, 13203, 13224, 13262, 13465, 13589, 13667, 13810, 13886, 14014, 14119, 14197, 14243, 14359, 14508, 14618, 14961, 15111, 15162, 15347, 15449, 15683, 15944, 16142, 16213, 16335, 16336, 16337, 16338, 16339, 16340, 16341, 16342, 16343, 16344, 16345, 16346, 16347, 16348, 16349, 16350, 16351, 16352, 16353, 16354, 16355, 16356, 16357, 16358, 16359, 16360, 16361, 16362, 16363, 16364, 16365, 16366, 16367, 16368, 16369, 16370, 16371, 16372, 16373, 16374, 16375, 16376, 16377, 16378, 16379, 16380, 16381, 16382, 16383}

var sparseTargets16 = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 32, 64, 96, 128, 160, 181, 192, 213, 224, 256, 288, 320, 362, 384, 448, 512, 543, 576, 640, 724, 768, 820, 870, 896, 905, 977, 1024, 1042, 1086, 1152, 1267, 1280, 1424, 1448, 1502, 1536, 1629, 1792, 1810, 1833, 1991, 2048, 2172, 2280, 2304, 2340, 2353, 2534, 2560, 2583, 2615, 2715, 2849, 2896, 3040, 3071, 3072, 3077, 3170, 3258, 3310, 3350, 3359, 3439, 3584, 3649, 4091, 4096, 4573, 4608, 5095, 5120, 5232, 5330, 5355, 5608, 6144, 6301, 6516, 6866, 7056, 7165, 7168, 7197, 7224, 7315, 7468, 7506, 7624, 7629, 8022, 8025, 8192, 8668, 8749, 8846, 9013, 9106, 9109, 9116, 9216, 9483, 9607, 10627, 11030, 11150, 11271, 11642, 11764, 11851, 11955, 12131, 12404, 12434, 12450, 12456, 13747, 13826, 13849, 14720, 14858, 15055, 15148, 16384, 16560, 17503, 17572, 17857, 17871, 18090, 18251, 18391, 18919, 19310, 19350, 19727, 19783, 19961, 20268, 20600, 20807, 20831, 20953, 20972, 21235, 21296, 21669, 21961, 22175, 22399, 22434, 22550, 22877, 22982, 22998, 23088, 23463, 23893, 23912, 24133, 24271, 24300, 24865, 25019, 25177, 25332, 25428, 26406, 26448, 26524, 26929, 27178, 27333, 27619, 27771, 28028, 28237, 28393, 28486, 29015, 29235, 30222, 30324, 30693, 31366, 31888, 32284, 32425, 32719, 32720, 32721, 32722, 32723, 32724, 32725, 32726, 32727, 32728, 32729, 32730, 32731, 32732, 32733, 32734, 32735, 32736, 32737, 32738, 32739, 32740, 32741, 32742, 32743, 32744, 32745, 32746, 32747, 32748, 32749, 32750, 32751, 32752, 32753, 32754, 32755, 32756, 32757, 32758, 32759, 32760, 32761, 32762, 32763, 32764, 32765, 32766, 32767}

func makeRange(start, end int) []int {
	r := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		r = append(r, i)
	}
	return r
}

// Synthetic cases.
var (
	denseLow         = makeRange(1, 32)
	twoClusters      = append(makeRange(100, 119), makeRange(8000, 8019)...)
	uniformPow2      = []int{1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096}
	uniformlySpread1 = func() []int {
		// 64 targets evenly across [1, 8000]
		r := make([]int, 64)
		for i := range r {
			r[i] = 1 + i*125
		}
		return r
	}()
)

// digitSum returns the sum of digits of n in the given base. For positive p-ary
// master sets, this equals the minimum number of master applications needed to
// add up to n (Algorithm 5 in the LLKN paper).
func digitSum(n, base int) int {
	if n < 0 {
		n = -n
	}
	sum := 0
	for n > 0 {
		sum += n % base
		n /= base
	}
	return sum
}

// greedyStrategy: walk each target from 0 with greedy decomposition; cache
// stepping stones via dedup. This is exactly what the current LevelExpansion
// does (Derive populates entries[] for every visited rotation).
func greedyStrategy(targets []int, masters []int) (entries map[int]bool, maxDepth int) {
	entries = map[int]bool{0: true}
	for _, t := range targets {
		steps := hierkeys.DecomposeRotation(t, masters)
		if steps == nil {
			panic(fmt.Sprintf("cannot decompose %d", t))
		}
		cur := 0
		for _, s := range steps {
			cur += s
			entries[cur] = true
		}
		if len(steps) > maxDepth {
			maxDepth = len(steps)
		}
	}
	return
}

// msaStrategy: minimum spanning arborescence rooted at 0 on the directed
// DAG where every edge goes from a smaller rotation to a larger one and has
// weight = digit-sum of the difference (LLKN Section 4.1, Algorithm 5).
//
// For a DAG with single root, MSA = pick each non-root node's cheapest
// incoming edge. Each target's "best parent" is the predecessor (in 0 ∪ targets,
// strictly smaller) that minimises digit-sum(target - parent).
//
// After choosing parents, walk the resulting tree from the root, applying
// greedy decomposition along each tree edge. The walked stepping stones
// form the cache.
func msaStrategy(targets []int, masters []int, base int) (entries map[int]bool, maxDepth int) {
	// Sort a copy of targets so "smaller predecessors" is well-defined.
	sortedTargets := make([]int, len(targets))
	copy(sortedTargets, targets)
	sort.Ints(sortedTargets)

	// Candidate predecessors for any target: 0 and all strictly smaller targets.
	parent := make(map[int]int, len(sortedTargets))
	for _, t := range sortedTargets {
		bestParent := 0
		bestWeight := digitSum(t, base)
		// Try each smaller target as a candidate parent.
		for _, p := range sortedTargets {
			if p >= t {
				break
			}
			w := digitSum(t-p, base)
			if w < bestWeight {
				bestWeight = w
				bestParent = p
			}
		}
		parent[t] = bestParent
	}

	// Build adjacency list (parent -> children).
	children := make(map[int][]int, len(sortedTargets)+1)
	for t, p := range parent {
		children[p] = append(children[p], t)
	}

	// BFS from root, walking the greedy chain along each tree edge.
	entries = map[int]bool{0: true}
	type item struct{ node, depth int }
	queue := []item{{node: 0, depth: 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, child := range children[cur.node] {
			steps := hierkeys.DecomposeRotation(child-cur.node, masters)
			if steps == nil {
				panic(fmt.Sprintf("cannot decompose %d -> %d", cur.node, child))
			}
			pos := cur.node
			for _, s := range steps {
				pos += s
				entries[pos] = true
			}
			childDepth := cur.depth + len(steps)
			if childDepth > maxDepth {
				maxDepth = childDepth
			}
			queue = append(queue, item{node: child, depth: childDepth})
		}
	}
	return
}

func nextPowerOfTwoGE(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func main() {
	const base = 4
	cases := []struct {
		name    string
		targets []int
		nSlots  int
	}{
		{"sparseTargets14", sparseTargets14, 8192},
		{"sparseTargets15", sparseTargets15, 16384},
		{"sparseTargets16", sparseTargets16, 32768},
		{"denseLow_1_32", denseLow, 8192},
		{"twoClusters_100..119_8000..8019", twoClusters, 8192},
		{"uniformPow2", uniformPow2, 8192},
		{"uniformlySpread64@8000", uniformlySpread1, 8192},
	}

	header := fmt.Sprintf("%-34s %8s %8s %12s %10s %12s %10s %10s %12s",
		"case", "targets", "floor", "g_entries", "g_depth", "m_entries", "m_depth", "saved", "saved%vs_floor")
	fmt.Println(header)
	fmt.Println(strings.Repeat("-", len(header)))

	for _, c := range cases {
		masters := hierkeys.MasterRotationsForBase(base, c.nSlots)
		floor := len(c.targets) + 1 // each target + shift-0; theoretical lower bound

		gEntries, gDepth := greedyStrategy(c.targets, masters)
		mEntries, mDepth := msaStrategy(c.targets, masters, base)

		gC := len(gEntries)
		mC := len(mEntries)
		saved := gC - mC

		savedPctVsFloor := 0.0
		room := gC - floor
		if room > 0 {
			savedPctVsFloor = float64(saved) / float64(room) * 100
		}

		fmt.Printf("%-34s %8d %8d %12d %10d %12d %10d %10d %11.1f%%\n",
			c.name, len(c.targets), floor, gC, gDepth, mC, mDepth, saved, savedPctVsFloor)
	}
}
