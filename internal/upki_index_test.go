package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
)

func TestLookupEmptyIndex(t *testing.T) {
	t.Parallel()

	cacheDir := writeCacheIndex(t, (&indexBuilder{}).bytes(t))
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
	b := &indexBuilder{}
	b.add("test.filter", indexEntry{logID: logID, minTS: 500, maxTS: 1500})
	cacheDir := writeCacheIndex(t, b.bytes(t))

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
	b := &indexBuilder{}
	b.add("test.filter", indexEntry{logID: logID, minTS: 2000, maxTS: 3000})
	cacheDir := writeCacheIndex(t, b.bytes(t))

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
	b := &indexBuilder{}
	b.add("filter-a.filter", indexEntry{logID: logA, minTS: 100, maxTS: 200})
	b.add("filter-b.filter",
		indexEntry{logID: logB, minTS: 500, maxTS: 1500},
		indexEntry{logID: logB, minTS: 2000, maxTS: 3000},
	)
	cacheDir := writeCacheIndex(t, b.bytes(t))

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
	b := &indexBuilder{}
	b.add("filter.filter", indexEntry{logID: logID, minTS: 500, maxTS: 1500})

	// No file and no closer. Index reads directly from an in-memory bytes.Reader.
	idx, err := NewIndexFromReader(bytes.NewReader(b.bytes(t)), nil)
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
	b := &indexBuilder{}
	for i := range logs {
		for j := range logs[i] {
			logs[i][j] = byte(i + 1)
		}
		b.add(
			// A distinct filter per log.
			fmt.Sprintf("filter-%d.filter", i),
			indexEntry{logID: logs[i], minTS: 500, maxTS: 1500},
		)
	}
	cacheDir := writeCacheIndex(t, b.bytes(t))

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

// indexBuilder constructs a synthetic index.bin.
//
// Each filter contributes a list of (log_id, min_ts, max_ts) coverage entries
// and the builder groups them by log_id (sorted)
type indexBuilder struct {
	filters []indexFilter
}

func (b *indexBuilder) add(filename string, entries ...indexEntry) {
	b.filters = append(b.filters, indexFilter{filename: filename, entries: entries})
}

func (b *indexBuilder) bytes(t *testing.T) []byte {
	t.Helper()

	type builtEntry struct {
		filterIdx uint8
		minTS     uint64
		maxTS     uint64
	}

	type dirEntry struct {
		logID   [32]byte
		entries []builtEntry
	}

	byLog := map[[32]byte]*dirEntry{}
	for fi, f := range b.filters {
		if len(f.filename) > filenameSize {
			t.Fatalf("test bug: filename %q exceeds %d bytes", f.filename, filenameSize)
		}

		for _, e := range f.entries {
			de, ok := byLog[e.logID]
			if !ok {
				de = &dirEntry{logID: e.logID}
				byLog[e.logID] = de
			}

			de.entries = append(de.entries, builtEntry{
				filterIdx: uint8(fi),
				minTS:     e.minTS,
				maxTS:     e.maxTS,
			})
		}
	}

	dir := make([]*dirEntry, 0, len(byLog))
	for _, de := range byLog {
		dir = append(dir, de)
	}
	sort.Slice(dir, func(i, j int) bool {
		return bytes.Compare(dir[i].logID[:], dir[j].logID[:]) < 0
	})

	hdr := headerSize + len(b.filters)*filenameSize + len(dir)*logDirEntrySize

	var buf bytes.Buffer
	buf.WriteString(indexMagic)
	buf.WriteByte(uint8(len(b.filters)))
	binary.Write(&buf, binary.BigEndian, uint32(len(dir)))

	for _, f := range b.filters {
		slot := make([]byte, filenameSize)
		copy(slot, f.filename)
		buf.Write(slot)
	}

	offset := uint64(hdr)
	for _, de := range dir {
		buf.Write(de.logID[:])
		binary.Write(&buf, binary.BigEndian, offset)
		binary.Write(&buf, binary.BigEndian, uint16(len(de.entries)))
		offset += uint64(len(de.entries) * entrySize)
	}

	for _, de := range dir {
		for _, e := range de.entries {
			buf.WriteByte(e.filterIdx)
			binary.Write(&buf, binary.BigEndian, e.minTS)
			binary.Write(&buf, binary.BigEndian, e.maxTS)
		}
	}

	return buf.Bytes()
}

type indexFilter struct {
	filename string
	entries  []indexEntry
}

type indexEntry struct {
	logID [32]byte
	minTS uint64
	maxTS uint64
}
