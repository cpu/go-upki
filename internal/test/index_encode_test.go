package test_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/cpu/go-upki/internal"
	"github.com/cpu/go-upki/internal/test"
)

// TestIndexRoundTrip covers the main encoding properties: filename table
// indexing, entries from multiple filters grouped under a shared log,
// filter-list ordering for overlapping intervals, and misses for
// unknown logs or uncovered timestamps.
func TestIndexRoundTrip(t *testing.T) {
	t.Parallel()

	logA := [32]byte{0xaa}
	logB := [32]byte{0xbb}
	idx := parseIndex(t, test.Index{Filters: []test.IndexFilter{
		{Filename: "a.filter", Coverage: []test.Coverage{
			{LogId: logA, MinTimestamp: 100, MaxTimestamp: 200},
			{LogId: logB, MinTimestamp: 100, MaxTimestamp: 200},
		}},
		{Filename: "b.filter", Coverage: []test.Coverage{
			{LogId: logB, MinTimestamp: 150, MaxTimestamp: 300},
			{LogId: logB, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}})
	defer idx.Close()

	tests := []struct {
		name string
		log  [32]byte
		ts   uint64
		want []string
	}{
		{"log A hit", logA, 150, []string{"a.filter"}},
		{"log B hit first filter", logB, 120, []string{"a.filter"}},
		{"overlap lists filters in order", logB, 180, []string{"a.filter", "b.filter"}},
		{"log B hit second filter", logB, 250, []string{"b.filter"}},
		{"log B hit second interval", logB, 1000, []string{"b.filter"}},
		{"below range", logA, 99, nil},
		{"above range", logA, 201, nil},
		{"gap between intervals", logB, 400, nil},
		{"unknown log", [32]byte{0xff}, 150, nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			names, err := idx.Lookup(tc.log, tc.ts)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			if !slices.Equal(names, tc.want) {
				t.Errorf("Lookup = %q, want %q", names, tc.want)
			}
		})
	}
}

// TestIndexEmpty verifies an index with no filters parses and misses.
func TestIndexEmpty(t *testing.T) {
	t.Parallel()

	idx := parseIndex(t, test.Index{})
	defer idx.Close()

	if names, err := idx.Lookup([32]byte{0xaa}, 150); err != nil || len(names) != 0 {
		t.Errorf("Lookup = (%q, err=%v), want a clean miss", names, err)
	}
}

func parseIndex(t *testing.T, idx test.Index) *internal.Index {
	t.Helper()

	enc := idx.Bytes()
	if !bytes.Equal(enc, idx.Bytes()) {
		t.Fatal("Bytes() is not deterministic")
	}

	parsed, err := internal.NewIndexFromReader(bytes.NewReader(enc), nil)
	if err != nil {
		t.Fatalf("NewIndexFromReader: %v", err)
	}

	return parsed
}
