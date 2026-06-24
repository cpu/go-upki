package internal

import "testing"

// TestBytesToLimbs pins the little-endian limb ordering used throughout
// the package: byte 0 ends up in the LSB of limb 0, byte 31 ends up in
// the MSB of limb 3.
func TestBytesToLimbs(t *testing.T) {
	t.Parallel()

	var a [32]byte
	a[0] = 0x01
	a[31] = 0x80
	limbs := bytesToLimbs(a)
	if limbs[0] != 0x01 {
		t.Errorf("limb[0] = %#x, want 0x01", limbs[0])
	}
	if limbs[3] != uint64(0x80)<<56 {
		t.Errorf("limb[3] = %#x, want %#x", limbs[3], uint64(0x80)<<56)
	}
}

// TestTrivialBlocks covers §3.1's "Rank zero blocks": a block with
// HModulus=0 (`Ri` = ∅). Non-inverted encodes "no member", inverted
// encodes "everything in `Ui`".
func TestTrivialBlocks(t *testing.T) {
	t.Parallel()

	f := &Filter{}
	var a [32]byte

	if got := f.Contains(&BlockMeta{Inverted: true}, a, nil); !got {
		t.Errorf("inverted trivial block: Contains = false, want true")
	}
	if got := f.Contains(&BlockMeta{}, a, nil); got {
		t.Errorf("plain trivial block: Contains = true, want false")
	}
}

// TestInvertedException covers the interaction between the exception
// set and inversion: an `Fi` hit produces "not in R" pre-flip (§3 Query
// step 7), the §3.1 inversion swap flips it back to "in R".
//
// The block is constructed degenerately (HModulus=1 with an all-zero X
// column) so the linear checks trivially pass, and we exercise step 7
// directly. This is not literally §3.1's "Rank zero blocks" trick, that
// requires HModulus=0, but it isolates the F_i + Inverted interaction.
func TestInvertedException(t *testing.T) {
	t.Parallel()

	f := &Filter{
		X: [][]uint64{make([]uint64, 4)},
		Y: make([]uint64, 4),
	}
	meta := &BlockMeta{
		HModulus: 1, HRank: 1, GModulus: 1,
		Exceptions: map[string]struct{}{"\x99\x99": {}},
		Inverted:   true,
	}
	var a [32]byte
	if got := f.Contains(meta, a, []byte{0x99, 0x99}); !got {
		t.Errorf("inverted+F_i serial: Contains = false, want true")
	}
}

// TestNonInvertedException tests an `Fi` hit produces "not in R"; a non-`Fi`
// query against the otherwise-trivial block produces "in R".
func TestNonInvertedException(t *testing.T) {
	t.Parallel()

	f := &Filter{
		X: [][]uint64{make([]uint64, 4)},
		Y: make([]uint64, 4),
	}
	meta := &BlockMeta{
		HModulus: 1, HRank: 1, GModulus: 1,
		Exceptions: map[string]struct{}{"bad": {}},
	}
	var a [32]byte

	if got := f.Contains(meta, a, []byte("bad")); got {
		t.Errorf("F_i hit (non-inverted) = true, want false")
	}
	if got := f.Contains(meta, a, []byte("ok")); !got {
		t.Errorf("non-F_i (non-inverted, trivial block) = false, want true")
	}
}

// TestLinearReject exercises the linear-algebra path. We pick a `a` with
// bit 2 of its limb-0 set, then plant column[2] = 1. Contains XORs the
// column bits at every set position of `a`, so the result is
// column[0] ^ column[2] = 0 ^ 1 = 1, triggering rejection.
//
// (Bit 0 is implicit because Contains forces aLimbs[0]'s low bit to 1.)
func TestLinearReject(t *testing.T) {
	t.Parallel()

	var a [32]byte
	a[0] = 0x04 // bit 2 of limb 0

	x := [][]uint64{make([]uint64, 4)}
	setRowBit(x, 0, 2)

	f := &Filter{X: x, Y: make([]uint64, 4)}
	meta := &BlockMeta{HModulus: 1, HRank: 1, GModulus: 1}

	if got := f.Contains(meta, a, nil); got {
		t.Errorf("Contains = true, want false (h·X != 0)")
	}

	// Also plant column[0] = 1. Now the XOR pairs the implicit bit-0
	// probe with the explicit bit-2 probe: 1 ^ 1 = 0, the linear check
	// passes again.
	setRowBit(x, 0, 0)
	if got := f.Contains(meta, a, nil); !got {
		t.Errorf("with paired bits: Contains = false, want true")
	}
}

// TestLinearRejectMultiColumn exercises HRank > 1. Planting the
// offending bit in each column in turn (and only in that column) and
// asserting each plant triggers rejection proves the loop visits every
// column in [0, HRank).
func TestLinearRejectMultiColumn(t *testing.T) {
	t.Parallel()

	var a [32]byte
	a[0] = 0x04 // bit 2

	meta := &BlockMeta{HModulus: 1, HRank: 3, GModulus: 1}

	for col := 0; col < int(meta.HRank); col++ {
		x := [][]uint64{make([]uint64, 4), make([]uint64, 4), make([]uint64, 4)}
		setRowBit(x, col, 2)
		f := &Filter{X: x, Y: make([]uint64, 4)}
		if got := f.Contains(meta, a, nil); got {
			t.Errorf("plant in column %d: Contains = true, want false", col)
		}
	}
}

// TestBlockRowOffset checks that HOffset is applied. With HOffset=256
// and HModulus=1, hRow=256, so the linear check probes rows [256, 512).
// Planting at row 256+2 makes the check fail. Planting only at row 2
// (outside the window) does not.
func TestBlockRowOffset(t *testing.T) {
	t.Parallel()

	var a [32]byte
	a[0] = 0x04 // bit 2

	const totalRows = 512
	x := [][]uint64{make([]uint64, totalRows/64)}
	setRowBit(x, 0, 256+2)

	f := &Filter{X: x, Y: make([]uint64, 4)}
	meta := &BlockMeta{HOffset: 256, HModulus: 1, HRank: 1, GModulus: 1}

	if got := f.Contains(meta, a, nil); got {
		t.Errorf("in-window plant: Contains = true, want false")
	}

	// Move the plant outside the [256, 512) window. Linear check passes.
	for i := range x[0] {
		x[0][i] = 0
	}
	setRowBit(x, 0, 2)
	if got := f.Contains(meta, a, nil); !got {
		t.Errorf("out-of-window plant: Contains = false, want true")
	}
}

// setRowBit sets bit `row` of column `col` of the column-major matrix X.
func setRowBit(x [][]uint64, col int, row uint64) {
	x[col][row>>6] |= uint64(1) << (row & 63)
}

// TestYReject exercises the §3 Query step 6 path: `gi(u) · y != 0`
// returns non-member. The X check is trivial (all-zero column passes);
// the Y vector has the offending bit so the second linear check fails.
func TestYReject(t *testing.T) {
	t.Parallel()

	var a [32]byte
	a[0] = 0x04 // bit 2

	y := make([]uint64, 4)
	y[0] |= 1 << 2 // plant bit 2 of Y

	f := &Filter{X: [][]uint64{make([]uint64, 4)}, Y: y}
	meta := &BlockMeta{HModulus: 1, HRank: 1, GModulus: 1}

	if got := f.Contains(meta, a, nil); got {
		t.Errorf("Y plant: Contains = true, want false (g·y != 0)")
	}
}
