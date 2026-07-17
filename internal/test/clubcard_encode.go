package test

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/binary"
	"math/bits"
	"math/rand/v2"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// Section references (§N) refer to the clubcard paper unless otherwise noted
// See the internal package docs for the full paper citation.

// Filter describes a test filter enrolling one block per issuer.
type Filter struct {
	Issuers  []Issuer
	Coverage []Coverage
}

// Issuer is one enrolled issuer block and its universe of serials.
//
// NotRevoked serials round out the block's universe. The exact filter only
// guarantees a StatusGood result for serials it encoded at build time, so
// any serial a test expects to be "good" must be listed here. Querying a
// serial in neither list may falsely report revoked.
type Issuer struct {
	// SpkiHash is the issuer's SPKI SHA-256 hash (the block id).
	SpkiHash [32]byte
	// Revoked holds the raw serials (no DER wrapper) to mark revoked.
	// Each must be at most 255 bytes.
	Revoked [][]byte
	// NotRevoked holds the raw serials to mark not revoked.
	NotRevoked [][]byte
}

// Coverage is one CT log's claimed timestamp range, inclusive on both ends,
// in milliseconds since the epoch.
type Coverage struct {
	LogId        [32]byte
	MinTimestamp uint64
	MaxTimestamp uint64
}

// Bytes builds the filter and returns its V4 wire encoding, suitable for
// crlite.FromBytes. It panics on inputs the wire format cannot represent
// (serials longer than 255 bytes).
//
// Builds are deterministic: the solver's free variables come from a
// fixed-seed PRNG, so the same Filter always yields identical bytes.
func (f Filter) Bytes() []byte {
	rng := rand.New(rand.NewPCG(0, 0))

	blocks := make([]block, 0, len(f.Issuers))
	for _, iss := range f.Issuers {
		blocks = append(blocks, buildBlock(iss, rng))
	}

	// Sort by descending rank so that every column i is a prefix of
	// blocks (exactly those with rank > i), giving each block a single
	// approx offset shared by all the columns that include it. The id
	// tie-break keeps builds deterministic.
	slices.SortFunc(blocks, func(a, b block) int {
		if c := cmp.Compare(b.rank, a.rank); c != 0 {
			return c
		}

		return bytes.Compare(a.id[:], b.id[:])
	})

	maxRank, hOff, gOff := 0, 0, 0
	for i := range blocks {
		b := &blocks[i]
		maxRank = max(maxRank, b.rank)
		if b.rank > 0 {
			b.hOffset = hOff
			hOff += 64 * len(b.approxSegs[0])
		}
		if b.exactM > 0 {
			b.gOffset = gOff
			gOff += 64 * len(b.exactSeg)
		}
	}

	// Serialize, mirroring crlite/parser.go
	var out cryptobyte.Builder
	out.AddBytes([]byte{4, 0}) // version(u8)=4, reserved0(u8)=0

	out.AddUint16(uint16(len(f.Coverage)))
	for _, c := range f.Coverage {
		out.AddBytes(c.LogId[:])
		out.AddUint64(c.MinTimestamp)
		out.AddUint64(c.MaxTimestamp)
	}

	out.AddUint32(uint32(len(blocks)))
	for _, b := range blocks {
		out.AddBytes(b.id[:])
		out.AddUint32(uint32(b.approxM))
		out.AddUint8(uint8(b.rank))
		out.AddUint32(uint32(b.hOffset))
		out.AddUint32(uint32(b.exactM))
		out.AddUint32(uint32(b.gOffset))
		if b.inverted {
			out.AddUint8(1)
		} else {
			out.AddUint8(0)
		}
		out.AddUint16(uint16(len(b.exceptions)))
		for _, serial := range b.exceptions {
			out.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) {
				c.AddBytes(serial)
			})
		}
	}

	out.AddUint8(uint8(maxRank))
	for i := 0; i < maxRank; i++ {
		var col []uint64
		for _, b := range blocks {
			if b.rank > i {
				col = append(col, b.approxSegs[i]...)
			}
		}
		addU64Seq(&out, col)
	}

	var y []uint64
	for _, b := range blocks {
		y = append(y, b.exactSeg...)
	}
	addU64Seq(&out, y)

	return out.BytesOrPanic()
}

// block is one issuer's solved ribbons plus its index entry fields.
type block struct {
	id       [32]byte
	inverted bool

	approxM    int
	rank       int
	hOffset    int
	approxSegs [][]uint64 // one solution segment per rank

	exactM     int
	gOffset    int
	exactSeg   []uint64
	exceptions [][]byte
}

// buildBlock solves one issuer's approximate and exact ribbons.
//
// Unlike the reference builder, blocks are solved independently rather
// than chained through cross-block back-substitution: solve's trailing
// zero padding guarantees any 256-bit query window starting in this
// block's rows stays inside its own segment, so concatenating segments
// with per-block offsets yields a valid filter.
func buildBlock(iss Issuer, rng *rand.Rand) block {
	revoked := hashAll(iss.SpkiHash, iss.Revoked)
	good := hashAll(iss.SpkiHash, iss.NotRevoked)
	nR, nU := len(revoked), len(revoked)+len(good)

	// R == U gets the §3.1 empty inverted block encoding (m == 0), and
	// an empty R the non-inverted equivalent.
	b := block{id: iss.SpkiHash, inverted: nR > 0 && nR == nU}
	if nR == 0 || b.inverted {
		return b
	}

	// Approximate filter sizing, following the reference builder: 2%
	// row overhead, rank = floor(log2(|U \ R| / |R|)) columns.
	b.approxM = nR + nR/50
	if 2*nR < nU {
		b.rank = bits.Len(uint((nU-nR)/nR)) - 1
	}

	if b.rank > 0 {
		r := newRibbon(b.approxM)
		for _, it := range revoked {
			r.insert(it.equation(b.approxM, 0))
		}
		b.approxSegs = make([][]uint64, b.rank)
		for i := range b.approxSegs {
			b.approxSegs[i] = r.solve(rng)
		}
	}

	// passesApprox reports whether the approximate filter would pass
	// `it` through to the exact filter. Rank-zero blocks pass everything.
	passesApprox := func(it item) bool {
		eq := it.equation(b.approxM, 0)
		for _, seg := range b.approxSegs {
			if eq.eval(seg) != 0 {
				return false
			}
		}

		return true
	}

	// The exact filter's universe is everything that survives the
	// approximate filter: all revoked serials plus approx false
	// positives. Revoked (homogeneous, b = 0) insertions never fail, so
	// inserting them first guarantees exceptions only record not-revoked
	// serials, matching the reference builder.
	universe := revoked
	for _, it := range good {
		if passesApprox(it) {
			universe = append(universe, it)
		}
	}
	b.exactM = len(universe) + len(universe)/50

	r := newRibbon(b.exactM)
	for i, it := range universe {
		var rhs uint64
		if i >= nR {
			rhs = 1
		}
		if !r.insert(it.equation(b.exactM, rhs)) {
			b.exceptions = append(b.exceptions, it.serial)
		}
	}
	b.exactSeg = r.solve(rng)

	return b
}

// item is one serial's precomputed hash material.
type item struct {
	// a holds SHA256(issuer || serial) as little-endian limbs with the
	// low bit forced, exactly as the query side derives its coefficient
	// vector (§4.3, §2.4 alignment).
	a      [4]uint64
	serial []byte
}

// equation hashes the item into block row space: row = t % m plus the
// constant term b (0 to include in the encoded set, 1 to exclude).
func (it item) equation(m int, b uint64) equation {
	return equation{s: it.a[3] % uint64(m), a: it.a, b: b}
}

func hashAll(issuer [32]byte, serials [][]byte) []item {
	items := make([]item, 0, len(serials))
	for _, serial := range serials {
		if len(serial) > 255 {
			panic("test: serial longer than 255 bytes")
		}

		sum := sha256.Sum256(slices.Concat(issuer[:], serial))

		it := item{serial: serial}
		for i := range it.a {
			it.a[i] = binary.LittleEndian.Uint64(sum[i*8:])
		}
		it.a[0] |= 1

		items = append(items, it)
	}

	return items
}

// equation is a GF(2) linear functional over the solution vector.
//
// bit i of a (0 <= i < 256) is the coefficient of solution bit s+i,
// and b is the constant term.
//
// An equation is considered "aligned" when a[0]&1 == 1.
type equation struct {
	s uint64
	a [4]uint64
	b uint64
}

func (e *equation) isZero() bool {
	return e.a == [4]uint64{}
}

// add xors other into e (requires e.s == other.s) and re-aligns so the
// lowest set coefficient sits at bit 0, bumping s to match.
func (e *equation) add(other *equation) {
	for i := range e.a {
		e.a[i] ^= other.a[i]
	}
	e.b ^= other.b
	if e.isZero() {
		return
	}

	for e.a[0] == 0 {
		e.a[0], e.a[1], e.a[2], e.a[3] = e.a[1], e.a[2], e.a[3], 0
		e.s += 64
	}

	k := uint64(bits.TrailingZeros64(e.a[0]))
	if k == 0 {
		return
	}
	for i := 0; i < 3; i++ {
		e.a[i] = e.a[i]>>k | e.a[i+1]<<(64-k)
	}
	e.a[3] >>= k
	e.s += k
}

// eval computes the inner product (mod 2) of e's coefficients with the
// solution column z.
func (e *equation) eval(z []uint64) uint64 {
	limb := int(e.s / 64)
	shift := e.s % 64

	var r uint64
	for i := limb; i < min(len(z), limb+4); i++ {
		tmp := z[i] >> shift
		if shift != 0 && i+1 < len(z) {
			tmp |= z[i+1] << (64 - shift)
		}
		r ^= tmp & e.a[i-limb]
	}

	return uint64(bits.OnesCount64(r) & 1)
}

// ribbon is a linear system under construction.
//
// Non-zero rows[i] always have s == i.
type ribbon struct {
	rows []equation
}

func newRibbon(m int) *ribbon {
	return &ribbon{rows: make([]equation, m)}
}

// insert adds eq to the system using Algorithm 1 of
// <https://arxiv.org/pdf/2103.02515>, reporting false when eq is
// inconsistent with the rows already present (an "exception").
func (r *ribbon) insert(eq equation) bool {
	for {
		if eq.isZero() {
			return eq.b == 0
		}
		for uint64(len(r.rows)) <= eq.s {
			r.rows = append(r.rows, equation{})
		}
		cur := &r.rows[eq.s]
		if cur.isZero() {
			*cur = eq
			return true
		}
		eq.add(cur)
	}
}

// solve back-substitutes one solution column. Free variables are drawn
// from rng so repeated solves yield distinct columns. The column carries 4
// words of zero padding because the query side always reads a full 256-bit
// window starting at any row < m.
func (r *ribbon) solve(rng *rand.Rand) []uint64 {
	z := make([]uint64, (len(r.rows)+63)/64+4)
	for i := len(r.rows) - 1; i >= 0; i-- {
		var zi uint64
		if r.rows[i].isZero() {
			zi = rng.Uint64() & 1
		} else {
			zi = r.rows[i].eval(z) ^ r.rows[i].b
		}
		z[i/64] |= zi << (i % 64)
	}

	return z
}

func addU64Seq(out *cryptobyte.Builder, words []uint64) {
	out.AddUint32(uint32(len(words)))
	for _, w := range words {
		out.AddUint64(w)
	}
}
