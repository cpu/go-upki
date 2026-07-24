package internal

import (
	"bytes"
	"encoding/binary"
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

// readAtOnly wraps an io.ReaderAt to hide any Size/Stat method, so the index
// reader cannot learn the underlying length up front. It exercises the
// fallback path where entry-section bounds are only enforced at read time.
type readAtOnly struct{ io.ReaderAt }

// TestLogDirOrder covers the log-directory ordering guard: a directory that
// is not strictly ascending by log id (unsorted or duplicate) is rejected at
// construction, since findLog's binary search relies on that order.
func TestLogDirOrder(t *testing.T) {
	t.Parallel()

	// Two logs, sorted 0xaa < 0xbb by the builder.
	logA := [32]byte{0xaa}
	logB := [32]byte{0xbb}
	enc := test.Index{Filters: []test.IndexFilter{
		{Filename: "a.filter", Coverage: []test.Coverage{{LogId: logA, MinTimestamp: 100, MaxTimestamp: 200}}},
		{Filename: "b.filter", Coverage: []test.Coverage{{LogId: logB, MinTimestamp: 100, MaxTimestamp: 200}}},
	}}.Bytes()

	// The two 42-byte log-dir entries begin right after the header and the
	// two 32-byte filename slots.
	dirStart := headerSize + 2*filenameSize
	e0 := dirStart
	e1 := dirStart + logDirEntrySize

	t.Run("unsorted", func(t *testing.T) {
		t.Parallel()

		// Swap the two directory entries so log ids descend.
		bad := bytes.Clone(enc)
		copy(bad[e0:e0+logDirEntrySize], enc[e1:e1+logDirEntrySize])
		copy(bad[e1:e1+logDirEntrySize], enc[e0:e0+logDirEntrySize])
		if _, err := NewIndexFromReader(bytes.NewReader(bad), nil); !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})

	t.Run("duplicate log id", func(t *testing.T) {
		t.Parallel()

		// Overwrite the second entry's 32-byte log id with the first's.
		bad := bytes.Clone(enc)
		copy(bad[e1:e1+32], enc[e0:e0+32])
		if _, err := NewIndexFromReader(bytes.NewReader(bad), nil); !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})
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

	t.Run("truncated entry section rejected at construction", func(t *testing.T) {
		t.Parallel()

		// Chop into the trailing 18-byte entry: header and tables still
		// parse, but the entry section now runs past the (sized) reader's
		// end, so construction rejects it up front.
		_, err := NewIndexFromReader(bytes.NewReader(enc[:len(enc)-5]), nil)
		if !errors.Is(err, errInvalidIndex) {
			t.Fatalf("want errInvalidIndex, got %v", err)
		}
	})

	t.Run("truncated entry section caught at lookup for sizeless reader", func(t *testing.T) {
		t.Parallel()

		// A reader that does not report its size skips construction's
		// upper-bound check, so the short read is caught at Lookup time.
		idx, err := NewIndexFromReader(readAtOnly{bytes.NewReader(enc[:len(enc)-5])}, nil)
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

	t.Run("entry section offset overlaps tables", func(t *testing.T) {
		t.Parallel()

		// The sole log-dir entry's u64 offset follows its 32-byte log id,
		// after the header and one 32-byte filename slot. Point it at 0 so
		// the entry section would overlap the header/tables.
		bad := bytes.Clone(enc)
		offField := headerSize + filenameSize + 32
		binary.BigEndian.PutUint64(bad[offField:offField+8], 0)
		if _, err := NewIndexFromReader(bytes.NewReader(bad), nil); !errors.Is(err, errInvalidIndex) {
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

// TestFilenameValidation covers the spec's filter filename restrictions:
// names are 1 to 32 bytes of ASCII [A-Za-z0-9.-_] and never "." or "..".
// An index carrying a violating name is rejected at construction, before
// any name can reach a filesystem operation relative to the cache dir.
func TestFilenameValidation(t *testing.T) {
	t.Parallel()

	id, _ := testInput()
	encode := func(name string) []byte {
		return test.Index{Filters: []test.IndexFilter{
			{Filename: name, Coverage: []test.Coverage{
				{LogId: id, MinTimestamp: 500, MaxTimestamp: 1500},
			}},
		}}.Bytes()
	}

	bad := []string{
		"",                   // below the 1-byte minimum
		".",                  // current-directory reference
		"..",                 // parent-directory reference
		"../evil.filter",     // path traversal
		"..\\evil.filter",    // windows path traversal
		"a/b.filter",         // path separator
		"/etc/passwd",        // absolute path
		"sp ace.filter",      // disallowed ASCII (space)
		"tab\t.filter",       // disallowed ASCII (control)
		"caf\xc3\xa9.filter", // non-ASCII (UTF-8 é)
		"high\xff.filter",    // non-ASCII (high byte)
	}
	for _, name := range bad {
		t.Run(fmt.Sprintf("reject %q", name), func(t *testing.T) {
			t.Parallel()

			if _, err := NewIndexFromReader(bytes.NewReader(encode(name)), nil); !errors.Is(err, errInvalidIndex) {
				t.Fatalf("want errInvalidIndex, got %v", err)
			}
		})
	}

	good := []string{
		"a",         // minimum length
		"...",       // only exactly "." and ".." are reserved
		"..hidden",  // leading dots are otherwise fine
		"AZaz09-._", // the full allowed character classes
	}
	for _, name := range good {
		t.Run(fmt.Sprintf("accept %q", name), func(t *testing.T) {
			t.Parallel()

			idx, err := NewIndexFromReader(bytes.NewReader(encode(name)), nil)
			if err != nil {
				t.Fatalf("NewIndexFromReader: %v", err)
			}
			idx.Close()
		})
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
