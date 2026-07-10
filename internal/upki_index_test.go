package internal

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cpu/go-upki/internal/test"
)

func TestLookupEmptyIndex(t *testing.T) {
	t.Parallel()

	cacheDir := writeCacheIndex(t, test.Index{}.Bytes())
	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	id, ts := testInput()
	_, found, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Fatal("expected not found on empty index")
	}
}

func TestLookupNoMatchingLogID(t *testing.T) {
	t.Parallel()

	var logID [32]byte
	for i := range logID {
		logID[i] = 0xcc
	}
	idxFile := test.Index{Filters: []test.IndexFilter{
		{Filename: "test.filter", Coverage: []test.Coverage{
			{LogId: logID, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}
	cacheDir := writeCacheIndex(t, idxFile.Bytes())

	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	id, ts := testInput()
	_, found, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Fatal("expected not found when log id absent")
	}
}

func TestLookupNoMatchingTimestamp(t *testing.T) {
	t.Parallel()

	var logID [32]byte
	for i := range logID {
		logID[i] = 0xbb
	}
	idxFile := test.Index{Filters: []test.IndexFilter{
		{Filename: "test.filter", Coverage: []test.Coverage{
			{LogId: logID, MinTimestamp: 2000, MaxTimestamp: 3000},
		}},
	}}
	cacheDir := writeCacheIndex(t, idxFile.Bytes())

	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	id, ts := testInput()
	_, found, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if found {
		t.Fatal("expected not found when timestamp outside interval")
	}
}

func TestLookupHit(t *testing.T) {
	t.Parallel()

	var logA, logB [32]byte
	for i := range logA {
		logA[i] = 0xaa
	}
	for i := range logB {
		logB[i] = 0xbb
	}
	idxFile := test.Index{Filters: []test.IndexFilter{
		{Filename: "filter-a.filter", Coverage: []test.Coverage{
			{LogId: logA, MinTimestamp: 100, MaxTimestamp: 200},
		}},
		{Filename: "filter-b.filter", Coverage: []test.Coverage{
			{LogId: logB, MinTimestamp: 500, MaxTimestamp: 1500},
			{LogId: logB, MinTimestamp: 2000, MaxTimestamp: 3000},
		}},
	}}
	cacheDir := writeCacheIndex(t, idxFile.Bytes())

	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	id, ts := testInput()
	name, found, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !found {
		t.Fatal("expected hit for log B at ts=1000")
	}
	if name != "filter-b.filter" {
		t.Fatalf("filename: got %q, want %q", name, "filter-b.filter")
	}
}

func TestNewIndexFromReader(t *testing.T) {
	t.Parallel()

	var logID [32]byte
	for i := range logID {
		logID[i] = 0xbb
	}
	idxFile := test.Index{Filters: []test.IndexFilter{
		{Filename: "filter.filter", Coverage: []test.Coverage{
			{LogId: logID, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}

	// No file and no closer. Index reads directly from an in-memory bytes.Reader.
	idx, err := NewIndexFromReader(bytes.NewReader(idxFile.Bytes()), nil)
	if err != nil {
		t.Fatalf("NewIndexFromReader: %v", err)
	}
	// We expect Close to be safe with a nil closer.
	defer idx.Close()

	id, ts := testInput()
	name, found, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !found {
		t.Fatal("expected hit")
	}
	if name != "filter.filter" {
		t.Fatalf("filename: got %q, want %q", name, "filter.filter")
	}
}

func TestLookupConcurrent(t *testing.T) {
	t.Parallel()

	// Multiple logs so lookups fan out to different entry sections.
	// We expect concurrent ReadAt on the same *os.File to be safe.
	var logs [8][32]byte
	var idxFile test.Index
	for i := range logs {
		for j := range logs[i] {
			logs[i][j] = byte(i + 1)
		}
		idxFile.Filters = append(idxFile.Filters, test.IndexFilter{
			// A distinct filter per log.
			Filename: fmt.Sprintf("filter-%d.filter", i),
			Coverage: []test.Coverage{
				{LogId: logs[i], MinTimestamp: 500, MaxTimestamp: 1500},
			},
		})
	}
	cacheDir := writeCacheIndex(t, idxFile.Bytes())

	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	const workers = 16
	const perWorker = 200

	var wg sync.WaitGroup
	wg.Add(workers)
	errs := make(chan error, workers)
	for w := range workers {
		go func(w int) {
			defer wg.Done()
			for i := range perWorker {
				id := logs[(w+i)%len(logs)]
				name, found, err := idx.Lookup(id, 1000)
				if err != nil {
					errs <- fmt.Errorf("worker %d: %v", w, err)
					return
				}
				if !found {
					errs <- fmt.Errorf("worker %d: expected hit", w)
					return
				}
				want := fmt.Sprintf("filter-%d.filter", (w+i)%len(logs))
				if name != want {
					errs <- fmt.Errorf("worker %d: got %q, want %q", w, name, want)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// testInput returns the canonical (log id, timestamp) probe used by the
// Lookup tests; suites place coverage intervals around or outside this
// pair to exercise the hit and miss paths.
func testInput() ([32]byte, uint64) {
	var id [32]byte
	for i := range id {
		id[i] = 0xbb
	}

	return id, 1000
}

func TestInvalidMagic(t *testing.T) {
	t.Parallel()

	cacheDir := writeCacheIndex(t, []byte("wrongmag\x00\x00\x00\x00\x00"))
	_, err := NewIndex(cacheDir)
	if !errors.Is(err, errInvalidIndex) {
		t.Fatalf("want errInvalidIndex, got %v", err)
	}
}

func TestTruncatedAfterMagic(t *testing.T) {
	t.Parallel()

	cacheDir := writeCacheIndex(t, []byte(indexMagic))
	_, err := NewIndex(cacheDir)
	if !errors.Is(err, errInvalidIndex) {
		t.Fatalf("want errInvalidIndex, got %v", err)
	}
}

func TestTruncatedBeforeMagic(t *testing.T) {
	t.Parallel()

	cacheDir := writeCacheIndex(t, []byte("upki"))
	_, err := NewIndex(cacheDir)
	if !errors.Is(err, errInvalidIndex) {
		t.Fatalf("want errInvalidIndex, got %v", err)
	}
}

func TestMissingIndex(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cacheDir, RevocationSubdir), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := NewIndex(cacheDir)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}

func writeCacheIndex(t *testing.T, data []byte) string {
	t.Helper()

	cacheDir := t.TempDir()
	revDir := filepath.Join(cacheDir, RevocationSubdir)
	if err := os.MkdirAll(revDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(revDir, indexFilename), data, 0o644); err != nil {
		t.Fatal(err)
	}

	return cacheDir
}
