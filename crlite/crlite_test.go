package crlite

import (
	"encoding/base64"
	"os"
	"testing"
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
// coverage map produces StatusNotCovered.
func TestNotCovered(t *testing.T) {
	t.Parallel()

	filter := loadFilter(t)

	// Use the real revoked GTS issuer + serial, but with an SCT log id
	// that won't be in the coverage map.
	var unknownLog LogId
	unknownLog[0] = 0xff

	issuer := IssuerSpkiHash(mustDecodeBase64Array32(t, "OdSlmQD9NWJh4EbcOHBxkhygPwNSwA9Q91eounfbcoE="))
	serial := mustDecodeBase64(t, "APpDYjsNxwPIEFP8ZGvsOiA=")
	key := NewKey(issuer, serial)

	scts := []LogTimestamp{{LogId: unknownLog, Timestamp: 1782115694514}}
	if got := filter.Contains(&key, scts); got != StatusNotCovered {
		t.Errorf("Contains = %v, want StatusNotCovered", got)
	}
}

// TestNotEnrolled verifies that an issuer that isn't in the filter's
// block index produces StatusNotEnrolled even when the SCT is covered.
func TestNotEnrolled(t *testing.T) {
	t.Parallel()

	filter := loadFilter(t)

	var unknownIssuer IssuerSpkiHash // all-zeros, overwhelmingly unlikely in any filter
	key := NewKey(unknownIssuer, []byte("any-serial"))

	// Reuse a covered SCT (the same log that appeared in TestContains).
	scts := []LogTimestamp{
		{LogId: LogId(mustDecodeBase64Array32(t, "1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc=")), Timestamp: 1782115694514},
	}
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

	filter := loadFilter(t)
	got := filter.NewestCoverageCutoff()
	if got == 0 {
		t.Fatalf("NewestCoverageCutoff = 0, expected non-zero")
	}

	// Sanity: should be on the order of a recent CT timestamp (ms since
	// epoch)
	if got < 1_700_000_000_000 || got > 1_800_000_000_000 {
		t.Errorf("NewestCoverageCutoff = %d, expected something near 2026", got)
	}
}

func TestCoverageCutoffForLog(t *testing.T) {
	t.Parallel()

	filter := loadFilter(t)

	// A LogId known to be covered by this filter (pulled from one of the
	// revoke-test SCTs that successfully reached Revoked status).
	covered := LogId(mustDecodeBase64Array32(t,
		"1219ENGn9XfCx+lf1wC/+YLJM1pl4dCzAXMXwMjFaXc="))
	got, ok := filter.CoverageCutoffForLog(covered)
	if !ok {
		t.Fatalf("CoverageCutoffForLog(covered) = (_, false), expected ok=true")
	}
	if got == 0 {
		t.Errorf("CoverageCutoffForLog(covered) = 0, expected non-zero")
	}

	// An all-zeros LogId is overwhelmingly unlikely to appear in the
	// coverage map.
	var unknown LogId
	if got, ok := filter.CoverageCutoffForLog(unknown); ok {
		t.Errorf("CoverageCutoffForLog(zero) = (%d, true), expected ok=false", got)
	}
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
