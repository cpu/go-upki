package internal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// On-disk layout of index.bin. Documented at
// https://github.com/rustls/upki/blob/main/upki/src/revocation/index.rs
//
//	HEADER (13 bytes):
//	  magic:         [8]byte    "upkiidx0"
//	  num_filenames: u8
//	  num_log_ids:   u32 BE
//
//	TABLES (read eagerly):
//	  filename[num_filenames]:   [32]byte  UTF-8, NULL-padded
//	  log_dir[num_log_ids]:                sorted lexicographically by log_id
//	    log_id:      [32]byte
//	    offset:      u64 BE                file offset of entry section
//	    num_entries: u16 BE
//
//	ENTRY SECTIONS (read on demand via ReadAt):
//	  entry[num_entries]:
//	    filter_index:  u8
//	    min_timestamp: u64 BE
//	    max_timestamp: u64 BE
const (
	RevocationSubdir = "revocation"
	indexFilename    = "index.bin"
	indexMagic       = "upkiidx0"
	filenameSize     = 32 // NULL-padded UTF-8 filename slot

	headerSize      = 8 + 1 + 4  // 8 byte magic + num_filenames(u8) + num_log_ids(u32)
	logDirEntrySize = 32 + 8 + 2 // 32 byte log_id + entry-section offset(u64) + count(u16)
	entrySize       = 1 + 8 + 8  // filter_idx(u8) + min_ts(u64) + max_ts(u64)
)

// errInvalidIndex indicates index.bin is malformed (bad magic, truncated,
// out-of-range filter index, etc).
var errInvalidIndex = errors.New("upki: invalid index")

// Index is the in-memory index of revocation filter coverage built from an
// upki revocation index.bin.
//
// Its purpose is to avoid needing to read each of the cached clubcard
// filters into memory for each revocation check.
//
// Constructing an Index reads the fixed header, the filename table, and
// the log-id directory eagerly. Per-log entry sections are read on demand
// via [io.ReaderAt.ReadAt] during [Index.Lookup].
//
// An Index may own a closer (e.g., an [*os.File] opened by [NewIndex]);
// callers must release it with [Index.Close].
//
// Index is safe for concurrent [Index.Lookup] calls: after construction
// only the [io.ReaderAt] is used, and [io.ReaderAt.ReadAt] does not share
// state with itself. Concurrent [Index.Close] with in-flight lookups is
// not supported.
type Index struct {
	filenames []string
	logDir    []byte // packed: numLogs * logDirEntrySize
	numLogs   int
	r         io.ReaderAt
	closer    io.Closer // nil if the caller supplied the ReaderAt
}

// NewIndex opens the cache dir's revocation index file and loads its
// header and lookup tables.
//
// The returned Index keeps a file handle open for on-demand reads of
// entry sections. Callers must call or defer [Index.Close] when done.
func NewIndex(cacheDir string) (*Index, error) {
	path := filepath.Join(cacheDir, RevocationSubdir, indexFilename)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("upki: opening index: %w", err)
	}

	idx, err := NewIndexFromReader(f, f)
	if err != nil {
		f.Close()

		return nil, err
	}

	return idx, nil
}

// NewIndexFromReader builds an Index over a caller-supplied
// [io.ReaderAt].
//
// The reader must cover a full index.bin starting at offset 0.
//
// If closer is non-nil, [Index.Close] will invoke it (e.g., pass an
// [*os.File] to have Close release the file handle). Pass nil when the
// reader has no resources to release (e.g., a [*bytes.Reader]) or when
// the caller owns cleanup itself.
//
// The returned Index eagerly consumes the header and lookup tables from
// r and entry sections are read on demand during [Index.Lookup].
func NewIndexFromReader(r io.ReaderAt, closer io.Closer) (*Index, error) {
	// header is: magic[8] | num_filenames(u8) | num_log_ids(u32 BE).
	var header [headerSize]byte
	if _, err := readFullAt(r, header[:], 0); err != nil {
		return nil, fmt.Errorf("%w: read header: %w", errInvalidIndex, err)
	}
	if !bytes.Equal(header[:8], []byte(indexMagic)) {
		return nil, fmt.Errorf("%w: bad magic", errInvalidIndex)
	}
	numFilenames := int(header[8])
	numLogs := int(binary.BigEndian.Uint32(header[9:13]))

	// Filename table and log dir are contiguous and their sizes are fully
	// determined by the header, so fetch both in one ReadAt.
	filenamesLen := numFilenames * filenameSize
	logDirLen := numLogs * logDirEntrySize
	tables := make([]byte, filenamesLen+logDirLen)
	if _, err := readFullAt(r, tables, int64(headerSize)); err != nil {
		return nil, fmt.Errorf("%w: read tables: %w", errInvalidIndex, err)
	}
	filenamesBuf := tables[:filenamesLen]
	logDir := tables[filenamesLen:]

	filenames := make([]string, numFilenames)
	for i := range numFilenames {
		slot := filenamesBuf[i*filenameSize : (i+1)*filenameSize]
		end := bytes.IndexByte(slot, 0)
		if end < 0 {
			end = filenameSize
		}

		filenames[i] = string(slot[:end])
	}

	return &Index{
		filenames: filenames,
		logDir:    logDir,
		numLogs:   numLogs,
		r:         r,
		closer:    closer,
	}, nil
}

// Close releases the closer supplied at construction, if any.
//
// It is idempotent and safe to call when no closer was supplied.
// It must not be called concurrently with in-flight lookups.
func (idx *Index) Close() error {
	if idx.closer == nil {
		return nil
	}

	err := idx.closer.Close()
	idx.closer = nil

	return err
}

// Lookup finds the filter files that cover the given CT log id at the
// given timestamp, returning the covering filters' basenames in index
// entry order.
//
// It binary-searches the in-memory log-id directory and on a hit issues
// a single [io.ReaderAt.ReadAt] against that log's entry section. Every
// entry whose interval [min, max] contains timestamp contributes its
// filter. A log can have several covering filters for the same instant
// and a conclusive revocation answer may come from any of them, so
// callers must consult all the returned filters, not just the first.
//
// The result is empty (with a nil error) when no entry covers the
// (log id, timestamp). In this case the log is not indexed, or it is
// indexed but the timestamp falls outside every recorded interval.
//
// logID and timestamp are raw [32]byte / uint64 rather than crlite.LogId /
// crlite.Timestamp so this package can stay free of a crlite import; crlite
// already depends on internal, and a back-edge would form an import cycle.
func (idx *Index) Lookup(logID [32]byte, timestamp uint64) ([]string, error) {
	dirOffset, ok := idx.findLog(logID)
	if !ok {
		return nil, nil
	}

	// log-dir entry is: log_id[32] | entry_offset(u64) | count(u16).
	entryOffset := binary.BigEndian.Uint64(idx.logDir[dirOffset+32 : dirOffset+40])
	count := binary.BigEndian.Uint16(idx.logDir[dirOffset+40 : dirOffset+42])

	buf := make([]byte, int(count)*entrySize)
	if _, err := readFullAt(idx.r, buf, int64(entryOffset)); err != nil {
		return nil, fmt.Errorf("%w: read entries: %w", errInvalidIndex, err)
	}

	var filenames []string
	for i := range int(count) {
		// entry is: filter_idx(u8) | min_ts(u64) | max_ts(u64).
		off := i * entrySize
		filterIdx := int(buf[off])
		minTS := binary.BigEndian.Uint64(buf[off+1 : off+9])
		maxTS := binary.BigEndian.Uint64(buf[off+9 : off+17])
		if minTS > timestamp || timestamp > maxTS {
			continue
		}

		if filterIdx >= len(idx.filenames) {
			return nil, fmt.Errorf("%w: entry filter index %d out of range", errInvalidIndex, filterIdx)
		}

		filenames = append(filenames, idx.filenames[filterIdx])
	}

	return filenames, nil
}

// findLog binary-searches the lexicographically-sorted log-id directory
// for logID and returns the byte offset (within idx.logDir) of the
// matching entry, or (0, false) if absent.
//
// Hand-rolled rather than sort.Search / slices.BinarySearchFunc because
// the directory is a packed byte buffer with no element type, and we don't
// want to transform to a slice.
func (idx *Index) findLog(logID [32]byte) (int, bool) {
	lo, hi := 0, idx.numLogs
	target := logID[:]
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		off := mid * logDirEntrySize
		cmp := bytes.Compare(idx.logDir[off:off+32], target)
		switch {
		case cmp < 0:
			lo = mid + 1
		case cmp > 0:
			hi = mid
		default:
			return off, true
		}
	}

	return 0, false
}

func readFullAt(r io.ReaderAt, buf []byte, off int64) (int, error) {
	n, err := r.ReadAt(buf, off)
	if err == io.EOF && n == len(buf) {
		// ReadAt is allowed to return io.EOF on a full read at EOF.
		return n, nil
	}
	if err == nil && n < len(buf) {
		return n, io.ErrUnexpectedEOF
	}

	return n, err
}
