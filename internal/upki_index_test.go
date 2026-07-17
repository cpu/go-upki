package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no filters on empty index, got %q", names)
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
	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no filters when log id absent, got %q", names)
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
	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no filters when timestamp outside interval, got %q", names)
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
	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := []string{"filter-b.filter"}; !slices.Equal(names, want) {
		t.Fatalf("filenames: got %q, want %q", names, want)
	}
}

// TestLookupMultipleFilters confirms Lookup returns every filter whose
// interval covers the timestamp, in entry order, skipping non-matching
// intervals without abandoning the rest of the log's entries.
func TestLookupMultipleFilters(t *testing.T) {
	t.Parallel()

	id, ts := testInput()
	idxFile := test.Index{Filters: []test.IndexFilter{
		// Covers the probe.
		{Filename: "filter-a.filter", Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
		// Same log, interval misses the probe: skipped, but must not
		// stop the scan.
		{Filename: "filter-b.filter", Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 2000, MaxTimestamp: 3000},
		}},
		// Same log, overlapping interval also covering the probe.
		{Filename: "filter-c.filter", Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 0, MaxTimestamp: 2000},
		}},
	}}
	cacheDir := writeCacheIndex(t, idxFile.Bytes())

	idx, err := NewIndex(cacheDir)
	if err != nil {
		t.Fatalf("NewIndex: %v", err)
	}
	defer idx.Close()

	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := []string{"filter-a.filter", "filter-c.filter"}; !slices.Equal(names, want) {
		t.Fatalf("filenames: got %q, want %q", names, want)
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
	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := []string{"filter.filter"}; !slices.Equal(names, want) {
		t.Fatalf("filenames: got %q, want %q", names, want)
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
				names, err := idx.Lookup(id, 1000)
				if err != nil {
					errs <- fmt.Errorf("worker %d: %v", w, err)
					return
				}
				want := []string{fmt.Sprintf("filter-%d.filter", (w+i)%len(logs))}
				if !slices.Equal(names, want) {
					errs <- fmt.Errorf("worker %d: got %q, want %q", w, names, want)
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

// TestLookupCorruptEntries covers Lookup's error paths: an entry section
// that can't be fully read, and an entry whose filter index exceeds the
// filename table.
func TestLookupCorruptEntries(t *testing.T) {
	t.Parallel()

	id, ts := testInput()
	enc := test.Index{Filters: []test.IndexFilter{
		{Filename: "test.filter", Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}.Bytes()

	t.Run("truncated entry section", func(t *testing.T) {
		t.Parallel()

		// Chop into the trailing 18-byte entry: header and tables still
		// parse, but reading the entry section comes up short.
		idx, err := NewIndexFromReader(bytes.NewReader(enc[:len(enc)-5]), nil)
		if err != nil {
			t.Fatalf("NewIndexFromReader: %v", err)
		}
		if _, err := idx.Lookup(id, ts); !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})

	t.Run("filter index out of range", func(t *testing.T) {
		t.Parallel()

		// The entry's filter_idx(u16) leads the trailing 18-byte entry;
		// its high byte alone puts the index far past the filename table.
		bad := bytes.Clone(enc)
		bad[len(bad)-18] = 0xff
		idx, err := NewIndexFromReader(bytes.NewReader(bad), nil)
		if err != nil {
			t.Fatalf("NewIndexFromReader: %v", err)
		}
		if _, err := idx.Lookup(id, ts); !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})
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

// TestTruncatedTables covers the tables-read error path: the header
// parses and claims a filename table the file doesn't contain.
func TestTruncatedTables(t *testing.T) {
	t.Parallel()

	// magic | num_filenames(u16)=1 | num_log_ids(u32)=0, then EOF.
	data := append([]byte(indexMagic), 0, 1, 0, 0, 0, 0)
	_, err := NewIndexFromReader(bytes.NewReader(data), nil)
	if !errors.Is(err, errInvalidIndex) {
		t.Fatalf("want errInvalidIndex, got %v", err)
	}
}

// TestFilenameFillsSlot confirms a filename occupying its full 32-byte
// slot (so no NUL padding follows it) round-trips through Lookup.
func TestFilenameFillsSlot(t *testing.T) {
	t.Parallel()

	id, ts := testInput()
	name := strings.Repeat("f", filenameSize-len(".filter")) + ".filter"
	idx, err := NewIndexFromReader(bytes.NewReader(test.Index{Filters: []test.IndexFilter{
		{Filename: name, Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}.Bytes()), nil)
	if err != nil {
		t.Fatalf("NewIndexFromReader: %v", err)
	}
	defer idx.Close()

	names, err := idx.Lookup(id, ts)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if want := []string{name}; !slices.Equal(names, want) {
		t.Fatalf("filenames: got %q, want %q", names, want)
	}
}

// TestReaderAtContractVariants exercises the io.ReaderAt behaviors the
// index must tolerate from custom backends: a reader that reports
// io.EOF alongside a full read ending exactly at EOF (permitted by the
// contract, and common for e.g. HTTP range backends), and one that
// misbehaves by returning a short read with a nil error.
func TestReaderAtContractVariants(t *testing.T) {
	t.Parallel()

	id, ts := testInput()
	enc := test.Index{Filters: []test.IndexFilter{
		{Filename: "test.filter", Coverage: []test.Coverage{
			{LogId: id, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}.Bytes()

	t.Run("eof on exact final read", func(t *testing.T) {
		t.Parallel()

		// The entry section is the file's final bytes, so Lookup's read
		// ends exactly at EOF and must tolerate (n, io.EOF).
		idx, err := NewIndexFromReader(eofReaderAt{bytes.NewReader(enc)}, nil)
		if err != nil {
			t.Fatalf("NewIndexFromReader: %v", err)
		}
		names, err := idx.Lookup(id, ts)
		if err != nil {
			t.Fatalf("Lookup: %v", err)
		}
		if want := []string{"test.filter"}; !slices.Equal(names, want) {
			t.Fatalf("filenames: got %q, want %q", names, want)
		}
	})

	t.Run("short read with nil error", func(t *testing.T) {
		t.Parallel()

		_, err := NewIndexFromReader(shortReaderAt{bytes.NewReader(enc)}, nil)
		if !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})
}

// eofReaderAt converts a full read ending exactly at EOF into
// (n, io.EOF), which the io.ReaderAt contract permits.
type eofReaderAt struct{ r *bytes.Reader }

func (e eofReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, err := e.r.ReadAt(p, off)
	if err == nil && off+int64(n) == e.r.Size() {
		return n, io.EOF
	}

	return n, err
}

// shortReaderAt violates the io.ReaderAt contract by returning fewer
// bytes than requested with a nil error.
type shortReaderAt struct{ r *bytes.Reader }

func (s shortReaderAt) ReadAt(p []byte, off int64) (int, error) {
	n, _ := s.r.ReadAt(p[:len(p)-1], off)

	return n, nil
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
