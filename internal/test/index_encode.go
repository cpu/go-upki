package test

import (
	"bytes"
	"maps"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// Index describes a test upki revocation index (index.bin).
//
// The on-disk layout is documented in internal/upki_index.go. Pair an
// Index with [Filter]-built filter files to assemble a full revocation
// cache directory for a test scenario.
type Index struct {
	Filters []IndexFilter
}

// IndexFilter is one filter file and the coverage entries it contributes
// to the index.
type IndexFilter struct {
	// Filename is the filter's basename, at most 32 bytes.
	Filename string
	// Coverage lists the (log, timestamp range) intervals this filter
	// covers. Entries for a shared log keep filter-list order, so when
	// intervals overlap lookups return the earlier filter first.
	Coverage []Coverage
}

// Bytes builds the index and returns its wire encoding, suitable for
// internal.NewIndexFromReader or writing out as index.bin.
//
// It panics on inputs the format cannot represent (more than 255 filters,
// filenames longer than 32 bytes).
func (idx Index) Bytes() []byte {
	const (
		magic           = "upkiidx0"
		filenameSize    = 32
		headerSize      = 8 + 1 + 4
		logDirEntrySize = 32 + 8 + 2
		entrySize       = 1 + 8 + 8
	)

	if len(idx.Filters) > 255 {
		panic("test: more than 255 index filters")
	}

	type entry struct {
		filterIdx uint8
		min, max  uint64
	}
	byLog := make(map[[32]byte][]entry)
	for i, f := range idx.Filters {
		if len(f.Filename) > filenameSize {
			panic("test: index filter filename longer than 32 bytes")
		}
		for _, c := range f.Coverage {
			byLog[c.LogId] = append(byLog[c.LogId], entry{uint8(i), c.MinTimestamp, c.MaxTimestamp})
		}
	}

	// The log-id directory must be sorted lexicographically for the
	// reader's binary search.
	logIds := slices.SortedFunc(maps.Keys(byLog), func(a, b [32]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	var out cryptobyte.Builder
	out.AddBytes([]byte(magic))
	out.AddUint8(uint8(len(idx.Filters)))
	out.AddUint32(uint32(len(logIds)))

	for _, f := range idx.Filters {
		slot := make([]byte, filenameSize)
		copy(slot, f.Filename)
		out.AddBytes(slot)
	}

	// Entry sections are packed contiguously after the tables, in log
	// directory order.
	offset := headerSize + filenameSize*len(idx.Filters) + logDirEntrySize*len(logIds)
	for _, id := range logIds {
		out.AddBytes(id[:])
		out.AddUint64(uint64(offset))
		out.AddUint16(uint16(len(byLog[id])))
		offset += entrySize * len(byLog[id])
	}

	for _, id := range logIds {
		for _, e := range byLog[id] {
			out.AddUint8(e.filterIdx)
			out.AddUint64(e.min)
			out.AddUint64(e.max)
		}
	}

	return out.BytesOrPanic()
}
