package hierkeys

import (
	"fmt"
	"sort"
	"sync"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
)

// RotToRotFunc is the signature for a single RotToRot call, abstracting
// over scheme-specific evaluator configuration.
type RotToRotFunc func(inputKey, masterKey *MasterKey, targetGalEl uint64) (*MasterKey, error)

// IntermediateKeys holds MasterKeys produced by [LevelExpansion.Derive] or
// [ExpandLevel]. Can be serialized, used as input to the next level's
// expansion, or finalized into standard lattigo GaloisKeys.
type IntermediateKeys struct {
	Keys map[int]*MasterKey // indexed by rotation index
}

// LevelExpansion is a thread-safe session for deriving rotation keys at a
// single hierarchy level. Each rotation is computed at most once; concurrent
// calls to [LevelExpansion.Derive] coordinate via internal synchronization.
//
// The library does not spawn goroutines — the caller controls concurrency
// by calling Derive from their own goroutines.
//
// Create with [NewLevelExpansion].
type LevelExpansion struct {
	rotToRot   RotToRotFunc
	params     rlwe.Parameters // target level params (for GaloisElement)
	masterKeys map[int]*MasterKey
	masterRots []int
	nSlots     int

	mu      sync.Mutex
	entries map[int]*expansionEntry
}

type expansionEntry struct {
	key  *MasterKey
	err  error
	once sync.Once
	done chan struct{}
}

// NewLevelExpansion creates a thread-safe expansion session at one hierarchy
// level. shift0Key seeds rotation 0. masterKeys are from the level above.
// rotToRot is called to compute each new rotation.
func NewLevelExpansion(
	rotToRot RotToRotFunc,
	params rlwe.Parameters,
	nSlots int,
	shift0Key *MasterKey,
	masterKeys map[int]*MasterKey,
) *LevelExpansion {
	seed := &expansionEntry{key: shift0Key, done: make(chan struct{})}
	close(seed.done) // shift-0 is immediately available

	entries := make(map[int]*expansionEntry)
	entries[0] = seed

	return &LevelExpansion{
		rotToRot:   rotToRot,
		params:     params,
		masterKeys: masterKeys,
		masterRots: SortedIntKeys(masterKeys),
		nSlots:     nSlots,
		entries:    entries,
	}
}

func (e *LevelExpansion) getOrCreate(rot int) *expansionEntry {
	e.mu.Lock()
	defer e.mu.Unlock()
	if entry, ok := e.entries[rot]; ok {
		return entry
	}
	entry := &expansionEntry{done: make(chan struct{})}
	e.entries[rot] = entry
	return entry
}

// Derive computes the key for the given rotation, walking the decomposition
// chain and blocking on dependencies as needed. Thread-safe: each rotation
// is computed at most once.
func (e *LevelExpansion) Derive(rot int) (*MasterKey, error) {
	normalized := ((rot % e.nSlots) + e.nSlots) % e.nSlots
	if normalized == 0 {
		entry := e.getOrCreate(0)
		<-entry.done
		return entry.key, entry.err
	}

	steps := DecomposeRotation(normalized, e.masterRots)
	if steps == nil {
		return nil, fmt.Errorf("cannot decompose rotation %d from available masters", normalized)
	}

	currentRot := 0
	for _, step := range steps {
		nextRot := currentRot + step
		masterKey := e.masterKeys[step]
		entry := e.getOrCreate(nextRot)
		inputRot := currentRot

		entry.once.Do(func() {
			dep := e.getOrCreate(inputRot)
			<-dep.done
			if dep.err != nil {
				entry.err = fmt.Errorf("dependency rotation %d: %w", inputRot, dep.err)
				close(entry.done)
				return
			}

			galEl := e.params.GaloisElement(nextRot)
			entry.key, entry.err = e.rotToRot(dep.key, masterKey, galEl)
			close(entry.done)
		})

		<-entry.done
		if entry.err != nil {
			return nil, entry.err
		}

		currentRot = nextRot
	}

	entry := e.getOrCreate(normalized)
	return entry.key, entry.err
}

// IntermediateKeys collects results for the requested rotations.
// Call after all Derive calls have completed.
func (e *LevelExpansion) IntermediateKeys(targetRotations []int) *IntermediateKeys {
	e.mu.Lock()
	defer e.mu.Unlock()

	result := &IntermediateKeys{Keys: make(map[int]*MasterKey, len(targetRotations))}
	for _, target := range targetRotations {
		normalized := ((target % e.nSlots) + e.nSlots) % e.nSlots
		if normalized == 0 {
			continue
		}
		if entry, ok := e.entries[normalized]; ok {
			select {
			case <-entry.done:
				if entry.key != nil {
					result.Keys[target] = entry.key
				}
			default:
			}
		}
	}
	return result
}

// ExpandLevel derives keys sequentially using a [LevelExpansion].
// For concurrent derivation, use [NewLevelExpansion] and call Derive
// from goroutines directly.
func ExpandLevel(
	rotToRot RotToRotFunc,
	params rlwe.Parameters,
	nSlots int,
	shift0Key *MasterKey,
	masterKeys map[int]*MasterKey,
	targetRotations []int,
) (*IntermediateKeys, error) {

	if shift0Key == nil {
		return nil, fmt.Errorf("shift-0 key must not be nil")
	}
	if len(masterKeys) == 0 {
		return nil, fmt.Errorf("master keys must not be empty")
	}

	exp := NewLevelExpansion(rotToRot, params, nSlots, shift0Key, masterKeys)
	for _, rot := range targetRotations {
		if _, err := exp.Derive(rot); err != nil {
			return nil, err
		}
	}
	return exp.IntermediateKeys(targetRotations), nil
}

func SortedIntKeys(m map[int]*MasterKey) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
