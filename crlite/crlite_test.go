package crlite

import (
	"encoding/base64"
	"errors"
	"os"
	"testing"

	"github.com/cpu/go-upki/internal/test"
)

// TestContains exercises the membership-query path against a known-good
// (DigiCert) and known-revoked (GTS Root R1) certificate.
//
// The (issuer SPKI hash, serial, SCT log+timestamp) tuples below were pulled
// from upki/revoke-test/test-sites.json[0], and paired with the matching filter
// from `upki fetch`.
//
// [0]: https://github.com/rustls/upki/blob/7f993e21ea212d3f7b6813017d33140e91bbd6d0/revoke-test/test-sites.json
func TestContains(t *testing.T) {
	t.Parallel()

	filter := loadFilter(t)

	tests := []struct {
		name             string
		issuerSpkiSha256 string // base64
		serial           string // base64
		scts             []LogTimestamp
		want             Status
	}{
		{
			name:             "DigiCert TLS ECC P384 Root G5",
			issuerSpkiSha256: "LsOdqDFw3goo/G8jjeEPxe+JSJ7aFp1RF5Ih4/2ZvFY=",
			serial:           "Dkb521uxnu6ORfLc3CYMyg==",
			scts: []LogTimestamp{
				{LogId: LogId(mustDecodeBase64Array32(t, "wjF+V0UZo0XufzjespBB68fCIVoiv3/Vta12mtkOUs0=")), Timestamp: 1781427700554},
				{LogId: LogId(mustDecodeBase64Array32(t, "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=")), Timestamp: 1781427700550},
				{LogId: LogId(mustDecodeBase64Array32(t, "lE5Dh/rswe+B8xkkJqgYZQHH0184AgE/cmd9VTcuGdg=")), Timestamp: 1781427700588},
			},
			want: StatusGood,
		},
		{
			name:             "GTS Root R1 (revoked)",
			issuerSpkiSha256: "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE=",
			serial:           "APpDYjsNxwPIEFP8ZGvsOiA=",
			scts: []LogTimestamp{
				{LogId: LogId(mustDecodeBase64Array32(t, "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=")), Timestamp: 1782115694558},
				{LogId: LogId(mustDecodeBase64Array32(t, "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=")), Timestamp: 1782115694514},
			},
			want: StatusRevoked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := IssuerSpkiHash(mustDecodeBase64Array32(t, tc.issuerSpkiSha256))
			serial := mustDecodeBase64(t, tc.serial)
			key := NewKey(issuer, serial)

			got := filter.Contains(&key, tc.scts)
			if got != tc.want {
				t.Errorf("Contains = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNotCovered verifies that an SCT log id outside the filter's
// coverage map produces StatusNotCovered, even for a revoked serial.
func TestNotCovered(t *testing.T) {
	t.Parallel()

	filter := loadTestFilter(t)

	var unknownLog LogId
	unknownLog[0] = 0xff

	key := NewKey(testFilterIssuer, testFilterSerial)
	scts := []LogTimestamp{{LogId: unknownLog, Timestamp: 150}}
	if got := filter.Contains(&key, scts); got != StatusNotCovered {
		t.Errorf("Contains = %v, want StatusNotCovered", got)
	}
}

// TestNotEnrolled verifies that an issuer that isn't in the filter's
// block index produces StatusNotEnrolled even when the SCT is covered.
func TestNotEnrolled(t *testing.T) {
	t.Parallel()

	filter := loadTestFilter(t)

	unknownIssuer := IssuerSpkiHash{0xdd}
	key := NewKey(unknownIssuer, []byte("any-serial"))

	scts := []LogTimestamp{{LogId: testFilterLog, Timestamp: 150}}
	if got := filter.Contains(&key, scts); got != StatusNotEnrolled {
		t.Errorf("Contains = %v, want StatusNotEnrolled", got)
	}
}

// TestFromBytesTruncation walks prefixes of a valid filter and asserts
// FromBytes returns an error (and never panics).
func TestFromBytesTruncation(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("testdata/20260624-1-default.filter.delta")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	// we use a small stride that's dense enough to hit nearly all codec error
	// branches but that still runs quickly.
	for n := 0; n < len(data); n += 3 {
		if _, err := FromBytes(data[:n]); err == nil {
			t.Fatalf("FromBytes(data[:%d]) succeeded; want error", n)
		}
	}
}

func TestNewestCoverageCutoff(t *testing.T) {
	t.Parallel()

	filter := loadTestFilter(t)

	// loadTestFilter covers two logs with cutoffs 200 and 300; the
	// newest wins.
	if got := filter.NewestCoverageCutoff(); got != 300 {
		t.Errorf("NewestCoverageCutoff = %d, want 300", got)
	}
}

func TestCoverageCutoffForLog(t *testing.T) {
	t.Parallel()

	filter := loadTestFilter(t)

	if got, ok := filter.CoverageCutoffForLog(testFilterLog); !ok || got != 200 {
		t.Errorf("CoverageCutoffForLog(covered) = (%d, %v), want (200, true)", got, ok)
	}

	var unknown LogId
	if got, ok := filter.CoverageCutoffForLog(unknown); ok {
		t.Errorf("CoverageCutoffForLog(zero) = (%d, true), expected ok=false", got)
	}
}

// TestFromBytesUnsupportedVersion verifies a non-V4 version tag is
// rejected with ErrUnsupportedFormat.
func TestFromBytesUnsupportedVersion(t *testing.T) {
	t.Parallel()

	enc := test.Filter{}.Bytes()
	enc[0] = 5
	if _, err := FromBytes(enc); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("want ErrUnsupportedFormat, got %v", err)
	}
}

// TestFromBytesNonZeroReserved0 verifies a non-zero reserved0 byte after
// the version is rejected with ErrDeserialize.
func TestFromBytesNonZeroReserved0(t *testing.T) {
	t.Parallel()

	enc := test.Filter{}.Bytes()
	enc[1] = 1
	if _, err := FromBytes(enc); !errors.Is(err, ErrDeserialize) {
		t.Fatalf("want ErrDeserialize, got %v", err)
	}
}

// TestFromBytesTrailingData verifies bytes past a well-formed filter are
// rejected with ErrDeserialize.
func TestFromBytesTrailingData(t *testing.T) {
	t.Parallel()

	enc := append(test.Filter{}.Bytes(), 0x00)
	if _, err := FromBytes(enc); !errors.Is(err, ErrDeserialize) {
		t.Fatalf("want ErrDeserialize, got %v", err)
	}
}

// TestFromBytesDuplicateBlock verifies two index entries sharing a block
// id are rejected with ErrDeserialize.
func TestFromBytesDuplicateBlock(t *testing.T) {
	t.Parallel()

	dup := test.Issuer{SpkiHash: testFilterIssuer, Revoked: [][]byte{testFilterSerial}}
	enc := test.Filter{Issuers: []test.Issuer{dup, dup}}.Bytes()
	if _, err := FromBytes(enc); !errors.Is(err, ErrDeserialize) {
		t.Fatalf("want ErrDeserialize, got %v", err)
	}
}

var (
	testFilterIssuer = IssuerSpkiHash{1, 2, 3}
	testFilterLog    = LogId{9, 9, 9}
	testFilterSerial = []byte("revoked-serial")
)

// loadTestFilter builds and parses a small synthetic filter enrolling
// testFilterIssuer with testFilterSerial revoked and coverage of two logs.
func loadTestFilter(t *testing.T) *RevocationFilter {
	t.Helper()

	f := test.Filter{
		Issuers: []test.Issuer{{
			SpkiHash: testFilterIssuer,
			Revoked:  [][]byte{testFilterSerial},
		}},
		Coverage: []test.Coverage{
			{LogId: testFilterLog, MinTimestamp: 100, MaxTimestamp: 200},
			{LogId: [32]byte{8, 8, 8}, MinTimestamp: 100, MaxTimestamp: 300},
		},
	}

	filter, err := FromBytes(f.Bytes())
	if err != nil {
		t.Fatalf("FromBytes: %v", err)
	}

	return filter
}

func loadFilter(t *testing.T) *RevocationFilter {
	t.Helper()

	const path = "testdata/20260624-1-default.filter.delta"

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	c, err := FromBytes(data)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	return c
}

func mustDecodeBase64(t *testing.T, s string) []byte {
	t.Helper()

	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode %q: %v", s, err)
	}

	return b
}

func mustDecodeBase64Array32(t *testing.T, s string) [32]byte {
	t.Helper()

	b := mustDecodeBase64(t, s)
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(b))
	}

	var out [32]byte
	copy(out[:], b)

	return out
}
