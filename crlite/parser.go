package crlite

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cpu/go-upki/internal"
)

var (
	ErrUnsupportedFormat = errors.New("crlite: unsupported clubcard version")
	ErrDeserialize       = errors.New("crlite: failed to deserialize clubcard")
)

// FromBytes parses a serialized CRLite clubcard.
//
// Only the V4 encoding is supported.
//
// The top-level wire format is:
//
// ```
//
//	struct {
//	    uint8           version;             // V4 == 4
//	    uint8           reserved0;           // MUST be 0
//	    CRLiteCoverage  coverage;
//	    ClubcardIndex   index;
//	    uint8           approx_filter_count;
//	    FilterColumn    approx_filter[approx_filter_count];
//	    FilterColumn    exact_filter;
//	} Clubcard;
//
// ```
//
// where `FilterColumn` is `uint64 words<count>`, a uint32 word-count prefix
// followed by that many big-endian u64 words. The exact filter is encoded
// with its own uint32 word-count prefix.
func FromBytes(data []byte) (*RevocationFilter, error) {
	s := cryptobyte.String(data)

	// The version is a u8 followed by a reserved0 u8 that MUST be zero.
	var version, reserved0 uint8
	if !s.ReadUint8(&version) || !s.ReadUint8(&reserved0) {
		return nil, fmt.Errorf("%w: version", ErrDeserialize)
	}

	// v4 is the only encoding tag this package recognizes.
	if version != 4 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedFormat, version)
	}
	// A future format version may repurpose reserved0 to signal additional
	// metadata, but v4 requires it to be zero.
	if reserved0 != 0 {
		return nil, fmt.Errorf("%w: non-zero reserved0 byte %d", ErrDeserialize, reserved0)
	}

	cov, err := readCoverage(&s)
	if err != nil {
		return nil, err
	}

	filter, err := readFilter(&s)
	if err != nil {
		return nil, err
	}

	if !s.Empty() {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrDeserialize, len(s))
	}

	return &RevocationFilter{coverage: cov, filter: filter}, nil
}

// readCoverage parses the universe coverage map.
//
// ```
//
//	struct {
//	    LogId             log_id;
//	    TimestampInterval interval;
//	} Coverage;
//
//	Coverage coverage<count>;   // uint16 count, then `count` entries
//
// ```
func readCoverage(s *cryptobyte.String) (coverage, error) {
	var count uint16
	if !s.ReadUint16(&count) {
		return nil, fmt.Errorf("%w: coverage count", ErrDeserialize)
	}

	// Each entry is a 32-byte log id plus two u64 timestamps. Reject counts
	// that promise more data than remains before allocating.
	const coverageEntrySize = 32 + 8 + 8
	if uint64(count)*coverageEntrySize > uint64(len(*s)) {
		return nil, fmt.Errorf("%w: coverage count %d exceeds input", ErrDeserialize, count)
	}

	cov := make(coverage, count)
	for i := uint16(0); i < count; i++ {
		id, err := readLogId(s)
		if err != nil {
			return nil, err
		}

		iv, err := readTimestampInterval(s)
		if err != nil {
			return nil, err
		}

		cov[id] = iv
	}

	return cov, nil
}

// coverage maps each CT log id to the inclusive timestamp interval the
// filter is known to cover.
type coverage map[LogId]timestampInterval

// timestampInterval is a closed pair of CT timestamps.
type timestampInterval struct {
	low  Timestamp
	high Timestamp
}

// readLogId parses a CT log identifier.
//
// ```
// opaque LogId[32]: a fixed-width 32-byte SHA-256 digest, no length prefix.
// ```
func readLogId(s *cryptobyte.String) (LogId, error) {
	var id LogId
	if !s.CopyBytes(id[:]) {
		return id, fmt.Errorf("%w: log id", ErrDeserialize)
	}

	return id, nil
}

// readTimestampInterval parses a half-closed pair of CT timestamps.
//
// ```
//
//	struct {
//	    Timestamp low;
//	    Timestamp high;
//	} TimestampInterval;
//
// ```
//
// Each Timestamp is a uint64, big-endian.
func readTimestampInterval(s *cryptobyte.String) (timestampInterval, error) {
	var low, high uint64
	if !s.ReadUint64(&low) || !s.ReadUint64(&high) {
		return timestampInterval{}, fmt.Errorf("%w: timestamp interval", ErrDeserialize)
	}

	return timestampInterval{low: Timestamp(low), high: Timestamp(high)}, nil
}

// readFilter parses the block index + filter columns of a V4 clubcard.
func readFilter(s *cryptobyte.String) (internal.Filter, error) {
	var f internal.Filter

	blocks, err := readBlocks(s)
	if err != nil {
		return f, err
	}
	f.Blocks = blocks

	var columnCount uint8
	if !s.ReadUint8(&columnCount) {
		return f, fmt.Errorf("%w: approx filter column count", ErrDeserialize)
	}

	f.X = make([][]uint64, columnCount)
	for i := range f.X {
		col, err := readU64Seq(s)
		if err != nil {
			return f, fmt.Errorf("approx filter column %d/%d: %w", i, columnCount, err)
		}

		f.X[i] = col
	}

	f.Y, err = readU64Seq(s)
	if err != nil {
		return f, fmt.Errorf("exact filter: %w", err)
	}

	if err := validateBlocks(&f); err != nil {
		return f, err
	}

	return f, nil
}

// validateBlocks checks each block's HRank against the parsed column count
// so [internal.Filter.Contains] cannot index a column that does not exist.
//
// Row offsets and moduli need no validation. Contains() treats out-of-range
// rows as zero (see internal.bitsXorIsZero).
func validateBlocks(f *internal.Filter) error {
	for id, meta := range f.Blocks {
		if meta.HModulus == 0 {
			// Empty block: Contains returns before touching X.
			continue
		}

		if int(meta.HRank) > len(f.X) {
			return fmt.Errorf("%w: block %x rank %d exceeds column count %d",
				ErrDeserialize, id, meta.HRank, len(f.X))
		}
	}

	return nil
}

// readU64Seq parses a `u64 items<count>` sequence: a uint32 word-count prefix
// followed by that many big-endian u64s.
func readU64Seq(s *cryptobyte.String) ([]uint64, error) {
	var count uint32
	if !s.ReadUint32(&count) {
		return nil, fmt.Errorf("%w: u64 seq count", ErrDeserialize)
	}

	// Reject counts that promise more data than remains before allocating,
	// so a short malicious input can't provoke a huge allocation.
	if uint64(count)*8 > uint64(len(*s)) {
		return nil, fmt.Errorf("%w: u64 seq count %d exceeds input", ErrDeserialize, count)
	}

	items := make([]uint64, count)
	for i := range items {
		if !s.ReadUint64(&items[i]) {
			return nil, fmt.Errorf("%w: u64 seq item %d/%d", ErrDeserialize, i, count)
		}
	}

	return items, nil
}

// readBlocks parses the per-block metadata table.
//
// ```
//
//	struct {
//	    opaque    block_id[32];
//	    BlockMeta meta;
//	} IndexEntry;
//
//	IndexEntry index<count>;   // uint32 count, then `count` entries
//
// ```
//
// The wire format encodes an `approx_filter_rank` field per block: the
// number of `X` columns this block's `h` check probes. Ranks vary between
// blocks because the CRLite construction packs progressively smaller
// block ranges into the trailing columns of `X`.
func readBlocks(s *cryptobyte.String) (map[[32]byte]*internal.BlockMeta, error) {
	var count uint32
	if !s.ReadUint32(&count) {
		return nil, fmt.Errorf("%w: index count", ErrDeserialize)
	}

	// Each entry is at least a 32-byte block id plus BlockMeta's fixed
	// fields (see readBlockMeta). Reject counts that promise more data
	// than remains before allocating.
	const minIndexEntrySize = 32 + // block_id
		4 + // approx_filter_m (u32)
		1 + // approx_filter_rank (u8)
		4 + // approx_filter_offset (u32)
		4 + // exact_filter_m (u32)
		4 + // exact_filter_offset (u32)
		1 + // inverted (u8)
		2 // exception count (u16)
	if uint64(count)*minIndexEntrySize > uint64(len(*s)) {
		return nil, fmt.Errorf("%w: index count %d exceeds input", ErrDeserialize, count)
	}

	blocks := make(map[[32]byte]*internal.BlockMeta, count)
	for i := uint32(0); i < count; i++ {
		var id [32]byte
		if !s.CopyBytes(id[:]) {
			return nil, fmt.Errorf("%w: index block id %d/%d", ErrDeserialize, i, count)
		}

		meta, err := readBlockMeta(s)
		if err != nil {
			return nil, err
		}

		if _, dup := blocks[id]; dup {
			return nil, fmt.Errorf("%w: duplicate index block id", ErrDeserialize)
		}

		blocks[id] = meta
	}

	return blocks, nil
}

// readBlockMeta parses one block's metadata.
//
// ```
//
//	struct {
//	    uint8  len;
//	    opaque serial[len];
//	} Exception;                        // serial as opaque<0..2^8-1>
//
//	struct {
//	    uint32    approx_filter_m;       // -> HModulus
//	    uint8     approx_filter_rank;    // -> HRank
//	    uint32    approx_filter_offset;  // -> HOffset
//	    uint32    exact_filter_m;        // -> GModulus
//	    uint32    exact_filter_offset;   // -> GOffset
//	    uint8     inverted;
//	    Exception exceptions<count>;     // uint16 count, then `count` serials
//	} BlockMeta;
//
// ```
func readBlockMeta(s *cryptobyte.String) (*internal.BlockMeta, error) {
	var (
		hMod, hOff, gMod, gOff uint32
		rank, inverted         uint8
	)
	if !s.ReadUint32(&hMod) ||
		!s.ReadUint8(&rank) ||
		!s.ReadUint32(&hOff) ||
		!s.ReadUint32(&gMod) ||
		!s.ReadUint32(&gOff) ||
		!s.ReadUint8(&inverted) {
		return nil, fmt.Errorf("%w: block meta header", ErrDeserialize)
	}

	// inverted is a polarity flag that MUST be either 0 or 1.
	if inverted > 1 {
		return nil, fmt.Errorf("%w: inverted flag %d not 0 or 1", ErrDeserialize, inverted)
	}

	var count uint16
	if !s.ReadUint16(&count) {
		return nil, fmt.Errorf("%w: block meta exception count", ErrDeserialize)
	}

	exceptions := make(map[string]struct{}, count)
	for i := uint16(0); i < count; i++ {
		var serial cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&serial) {
			return nil, fmt.Errorf("%w: block meta exception %d/%d", ErrDeserialize, i, count)
		}

		exceptions[string(serial)] = struct{}{}
	}

	return &internal.BlockMeta{
		HOffset:    uint64(hOff),
		HModulus:   uint64(hMod),
		HRank:      rank,
		GOffset:    uint64(gOff),
		GModulus:   uint64(gMod),
		Exceptions: exceptions,
		Inverted:   inverted != 0,
	}, nil
}
