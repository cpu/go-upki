// Package internal implements the in-memory query side of the clubcard
// membership test.
//
// The data structure and membership test are described in J. M. Schanck,
// "Clubcards for the WebPKI: Smaller Certificate Revocation Tests in Theory
// and Practice," 2025 IEEE Symposium on Security and Privacy (SP), San
// Francisco, CA, USA, 2025.
//
// Section references of the form §N or §N.M throughout this package refer
// to that paper, accessible at
// <https://jmschanck.info/papers/20250327-clubcard.pdf>
//
// This implementation is narrowly scoped to 32-byte block identifiers
// (matching issuer SPKI hash) and with ribbon width w = 256 (W = 4 64-bit
// limbs), matching CRLite. Construction of clubcards is out of scope.
//
// Notably the storage layout differs from the paper's row-major X matrix.
// Instead, X is stored column-major as one bit-packed []uint64 per column,
// matching the CRLite V4 wire format implemented in the
// mozilla/clubcard-crlite Rust crate[1].
//
// [1]: https://github.com/mozilla/clubcard-crlite
package internal

import (
	"encoding/binary"
	"math/bits"
)

// Filter is an in-memory clubcard filter.
//
// `X[c]` holds column `c` of the approximate membership query filter,
// bit-packed little-endian. e.g. bit `i` lives in `X[c][i/64]` at position
// `i % 64`.
//
// Y holds the 1-bit retrieval function vector in the same packing.
//
// Blocks is keyed by 32-byte issuer SPKI hash (§4.2 BlockId).
type Filter struct {
	X      [][]uint64
	Y      []uint64
	Blocks map[[32]byte]*BlockMeta
}

// Contains evaluates the §3 Query algorithm for an element `u` described
// by `a` = SHA256(IssuerSPKIHash || SerialNumber) along with the raw serial.
//
// Deferring the [Filter.Blocks] lookup to the caller keeps the
// "is the issuer enrolled?" decision in the CRLite layer.
//
// The returned bool already accounts for [BlockMeta.Inverted].
func (f *Filter) Contains(meta *BlockMeta, a [32]byte, serial []byte) bool {
	// Empty block (`Ri` = ∅): `u` ∉ `Ri` for every `u`. Inversion flips to
	// "every `u` is in `Ri`" (§3.1, "compact encoding of empty blocks").
	//
	// This check also short-circuits the `t % HModulus` divide-by-zero
	// below.
	if meta.HModulus == 0 {
		return meta.Inverted
	}

	aLimbs := bytesToLimbs(a)
	// Force a leading 1 in the coefficient vector. Ribbon retrieval
	// requires the equation passed to InsertEquation to be aligned
	// (low bit set) for construction's Gaussian elimination to work
	// (§2.4 "aligned representative", §4.3).
	aLimbs[0] |= 1
	t := aLimbs[3] // §4.3 step 3: high 64 bits, little-endian => limb 3

	hRow := meta.HOffset + (t % meta.HModulus)
	for i := uint8(0); i < meta.HRank; i++ {
		if !bitsXorIsZero(f.X[i], hRow, aLimbs) {
			return meta.Inverted
		}
	}

	if meta.GModulus != 0 {
		gRow := meta.GOffset + (t % meta.GModulus)
		if !bitsXorIsZero(f.Y, gRow, aLimbs) {
			return meta.Inverted
		}
	}

	if _, isException := meta.Exceptions[string(serial)]; isException {
		return meta.Inverted
	}

	return !meta.Inverted
}

// BlockMeta is BlockMeta(i) from §3. It is the data needed to evaluate
// `Ri`-membership for one block.
//
// HOffset/HModulus parameterise §4.3 CRLiteRibbonHash for `hi`; G* for
// `gi`. The §3 per-block `δi` row offset is pre-folded into HOffset (and
// GOffset) by the wire format, so no separate bit-offset field appears
// here.
//
// HRank is `ki`: the number of [Filter.X] columns this block's `hi` check
// probes. Per §3 "Omitting zeros", X has a staircase of zero coefficients
// in its bottom-right, so trailing columns may not extend to every
// block. Instead, HRank is the source of truth for which columns apply.
type BlockMeta struct {
	HOffset  uint64
	HModulus uint64
	HRank    uint8

	GOffset  uint64
	GModulus uint64

	// Exceptions is `Fi`: serials known to be insertion failures from
	// the construction of Y.
	//
	// Stored as raw serial bytes (no DER tag/length wrapper), converted to a
	// string (no []byte keys in Go maps).
	Exceptions map[string]struct{}

	// Inverted swaps the member/non-member returns from Query.
	// See §3.1 "Rank zero blocks".
	Inverted bool
}

// bytesToLimbs reads `a` as four little-endian uint64 limbs.
//
// Limb 3 is the "high 64 bits" used by §4.3 CRLiteRibbonHash to derive `t`.
func bytesToLimbs(a [32]byte) [W]uint64 {
	return [W]uint64{
		binary.LittleEndian.Uint64(a[0:8]),
		binary.LittleEndian.Uint64(a[8:16]),
		binary.LittleEndian.Uint64(a[16:24]),
		binary.LittleEndian.Uint64(a[24:32]),
	}
}

// bitsXorIsZero reports whether the dot product of coef with the
// 256 bits of column starting at rowOffset is 0 over GF(2).
//
// Rows past the end of column read as zero.
func bitsXorIsZero(column []uint64, rowOffset uint64, coef [W]uint64) bool {
	limb := rowOffset / 64
	shift := rowOffset % 64

	var r uint64
	for i := limb; i < min(uint64(len(column)), limb+W); i++ {
		tmp := column[i] >> shift
		if shift != 0 && i+1 < uint64(len(column)) {
			tmp |= column[i+1] << (64 - shift)
		}
		r ^= tmp & coef[i-limb]
	}

	return bits.OnesCount64(r)&1 == 0
}

// W is the §4.3 ribbon width in 64-bit limbs (w = 256).
const W = 4
