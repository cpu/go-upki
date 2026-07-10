package test_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cpu/go-upki/crlite"
	"github.com/cpu/go-upki/internal/test"
)

// TestRoundTrip builds a filter with enough not-revoked serials that the
// approximate filter has rank > 0, exercising both the X columns and the
// exact filter on the query side.
func TestRoundTrip(t *testing.T) {
	t.Parallel()

	revoked := serials("revoked", 3)
	notRevoked := serials("good", 200)
	filter := testFilter(t, revoked, notRevoked)

	for _, s := range revoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusRevoked)
	}
	for _, s := range notRevoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusGood)
	}
}

// TestRoundTripRankZero uses a small universe (2|R| >= |U|) so the
// approximate filter has rank 0 and every result rides on the exact filter.
func TestRoundTripRankZero(t *testing.T) {
	t.Parallel()

	revoked := serials("revoked", 3)
	notRevoked := serials("good", 4)
	filter := testFilter(t, revoked, notRevoked)

	for _, s := range revoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusRevoked)
	}
	for _, s := range notRevoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusGood)
	}
}

// TestRoundTripMultiIssuer enrolls three blocks with different shapes (rank
// > 0, rank 0, and empty inverted) so the per-block index offsets are
// non-trivial, and checks every serial against its own issuer.
func TestRoundTripMultiIssuer(t *testing.T) {
	t.Parallel()

	issuers := []test.Issuer{
		{SpkiHash: crlite.IssuerSpkiHash{0xaa}, Revoked: serials("a-revoked", 3), NotRevoked: serials("a-good", 200)},
		{SpkiHash: crlite.IssuerSpkiHash{0xbb}, Revoked: serials("b-revoked", 3), NotRevoked: serials("b-good", 4)},
		{SpkiHash: crlite.IssuerSpkiHash{0xcc}, Revoked: serials("c-revoked", 2)},
	}
	filter := parseFilter(t, test.Filter{
		Issuers: issuers,
		Coverage: []test.Coverage{
			{LogId: testLog, MinTimestamp: 100, MaxTimestamp: 200},
		},
	})

	for _, iss := range issuers {
		issuer := crlite.IssuerSpkiHash(iss.SpkiHash)
		for _, s := range iss.Revoked {
			checkStatus(t, filter, issuer, s, covered(), crlite.StatusRevoked)
		}
		for _, s := range iss.NotRevoked {
			checkStatus(t, filter, issuer, s, covered(), crlite.StatusGood)
		}
	}

	// An issuer that isn't one of the three blocks is not enrolled.
	key := crlite.NewKey(crlite.IssuerSpkiHash{0xdd}, []byte("any-serial"))
	if got := filter.Contains(&key, covered()); got != crlite.StatusNotEnrolled {
		t.Errorf("Contains(other issuer) = %v, want StatusNotEnrolled", got)
	}
}

func TestRoundTripCoverageAndEnrollment(t *testing.T) {
	t.Parallel()

	revoked := serials("revoked", 3)
	filter := testFilter(t, revoked, serials("good", 4))

	// Timestamps outside [100, 200] and unknown logs are not covered.
	checkStatus(t, filter, testIssuer, revoked[0],
		[]crlite.LogTimestamp{{LogId: testLog, Timestamp: 99}}, crlite.StatusNotCovered)
	checkStatus(t, filter, testIssuer, revoked[0],
		[]crlite.LogTimestamp{{LogId: testLog, Timestamp: 201}}, crlite.StatusNotCovered)
	checkStatus(t, filter, testIssuer, revoked[0],
		[]crlite.LogTimestamp{{LogId: crlite.LogId{0xff}, Timestamp: 150}}, crlite.StatusNotCovered)

	// An issuer other than the enrolled one is not enrolled.
	key := crlite.NewKey(crlite.IssuerSpkiHash{4, 5, 6}, revoked[0])
	if got := filter.Contains(&key, covered()); got != crlite.StatusNotEnrolled {
		t.Errorf("Contains(other issuer) = %v, want StatusNotEnrolled", got)
	}

	// Coverage metadata round-trips.
	if got := filter.NewestCoverageCutoff(); got != 200 {
		t.Errorf("NewestCoverageCutoff = %d, want 200", got)
	}
	if got, ok := filter.CoverageCutoffForLog(testLog); !ok || got != 200 {
		t.Errorf("CoverageCutoffForLog = (%d, %v), want (200, true)", got, ok)
	}
}

// TestRoundTripAllRevoked covers the empty inverted block encoding (R == U):
// every serial for the enrolled issuer reports revoked, even ones the
// builder never saw.
func TestRoundTripAllRevoked(t *testing.T) {
	t.Parallel()

	revoked := serials("revoked", 2)
	filter := testFilter(t, revoked, nil)

	for _, s := range revoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusRevoked)
	}
	checkStatus(t, filter, testIssuer, []byte("never-seen"), covered(), crlite.StatusRevoked)
}

// TestRoundTripNoneRevoked covers the empty non-inverted block encoding
// (R == 0): every serial for the enrolled issuer reports good.
func TestRoundTripNoneRevoked(t *testing.T) {
	t.Parallel()

	notRevoked := serials("good", 3)
	filter := testFilter(t, nil, notRevoked)

	for _, s := range notRevoked {
		checkStatus(t, filter, testIssuer, s, covered(), crlite.StatusGood)
	}
	checkStatus(t, filter, testIssuer, []byte("never-seen"), covered(), crlite.StatusGood)
}

func testFilter(t *testing.T, revoked, notRevoked [][]byte) *crlite.RevocationFilter {
	t.Helper()

	return parseFilter(t, test.Filter{
		Issuers: []test.Issuer{
			{SpkiHash: testIssuer, Revoked: revoked, NotRevoked: notRevoked},
		},
		Coverage: []test.Coverage{
			{LogId: testLog, MinTimestamp: 100, MaxTimestamp: 200},
		},
	})
}

func parseFilter(t *testing.T, f test.Filter) *crlite.RevocationFilter {
	t.Helper()

	enc := f.Bytes()
	if !bytes.Equal(enc, f.Bytes()) {
		t.Fatal("Bytes() is not deterministic")
	}

	parsed, err := crlite.FromBytes(enc)
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}

	return parsed
}

func checkStatus(t *testing.T, filter *crlite.RevocationFilter, issuer crlite.IssuerSpkiHash, serial []byte, ts []crlite.LogTimestamp, want crlite.Status) {
	t.Helper()

	key := crlite.NewKey(issuer, serial)
	if got := filter.Contains(&key, ts); got != want {
		t.Errorf("Contains(serial %q) = %v, want %v", serial, got, want)
	}
}

func serials(prefix string, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = fmt.Appendf(nil, "%s-%d", prefix, i)
	}

	return out
}

func covered() []crlite.LogTimestamp {
	return []crlite.LogTimestamp{{LogId: testLog, Timestamp: 150}}
}

var (
	testIssuer = crlite.IssuerSpkiHash{1, 2, 3}
	testLog    = crlite.LogId{9, 9, 9}
)
