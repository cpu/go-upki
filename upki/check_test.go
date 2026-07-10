package upki

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/cpu/go-upki/internal"
	"github.com/cpu/go-upki/internal/test"
)

func TestCheckChainTooShort(t *testing.T) {
	t.Parallel()

	cases := [][]*x509.Certificate{
		nil,
		{},
		{newTestCert(t, nil, nil)},
	}
	for i, chain := range cases {
		c := &Checker{} // no idx needed, error fires before any lookup
		_, err := c.Check(chain)
		if !errors.Is(err, ErrChainTooShort) {
			t.Errorf("case %d: want ErrChainTooShort, got %v", i, err)
		}
	}
}

// TestCheckerOpenClose confirms NewChecker + Close work against a cache
// dir: index.bin opens, header validates, file handle releases.
func TestCheckerOpenClose(t *testing.T) {
	t.Parallel()

	c, err := NewChecker(writeTestCache(t, test.Index{}, nil))
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// TestCheck exercises the top-level upki.Check wrapper (open + check
// + close in one shot).
func TestCheck(t *testing.T) {
	t.Parallel()

	leaf := &x509.Certificate{}
	chain := []*x509.Certificate{leaf, leaf}

	status, err := Check(writeTestCache(t, test.Index{}, nil), chain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusNotCovered {
		t.Fatalf("status: got %v, want StatusNotCovered", status)
	}
}

// TestCheckerNoSCTs confirms a chain whose leaf has no embedded SCTs
// returns StatusNotCovered with a nil error rather than failing the
// check. A bare x509.Certificate has no Extensions, which is the
// simplest way to exercise that code path.
func TestCheckerNoSCTs(t *testing.T) {
	t.Parallel()

	leaf := &x509.Certificate{}
	chain := []*x509.Certificate{leaf, leaf}

	c, err := NewChecker(writeTestCache(t, test.Index{}, nil))
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	defer c.Close()

	status, err := c.Check(chain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusNotCovered {
		t.Fatalf("status: got %v, want StatusNotCovered", status)
	}
}

// TestCheckerCheck exercises the full Check path against a synthetic
// cache: SCT extraction, index lookup, filter load, and the crlite
// membership query.
func TestCheckerCheck(t *testing.T) {
	t.Parallel()

	coveredLog := fillLogID(0x11)
	issuer := newTestCert(t, nil, nil)
	otherIssuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	coverage := []test.Coverage{{LogId: coveredLog, MinTimestamp: 500, MaxTimestamp: 1500}}
	filterBytes := test.Filter{
		Issuers: []test.Issuer{{
			SpkiHash:   issuerHash,
			Revoked:    [][]byte{{42}},
			NotRevoked: [][]byte{{43}},
		}},
		Coverage: coverage,
	}.Bytes()
	cacheDir := writeTestCache(t,
		test.Index{Filters: []test.IndexFilter{{Filename: "t.filter", Coverage: coverage}}},
		map[string][]byte{"t.filter": filterBytes},
	)

	c, err := NewChecker(cacheDir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	coveredSCT := buildSCTExtension(t, []SCT{{LogID: coveredLog, Timestamp: 1000}})
	uncoveredSCT := buildSCTExtension(t, []SCT{{LogID: fillLogID(0x77), Timestamp: 1000}})
	// Truncated outer octet string, per TestEmbeddedSCTsMalformed.
	badSCT := &pkix.Extension{Id: embeddedSCTOID, Value: []byte{0x04, 0x05, 0x00}}

	tests := []struct {
		name    string
		chain   []*x509.Certificate
		want    Status
		wantErr bool
	}{
		{"revoked", []*x509.Certificate{newTestCert(t, big.NewInt(42), coveredSCT), issuer}, StatusRevoked, false},
		{"not revoked", []*x509.Certificate{newTestCert(t, big.NewInt(43), coveredSCT), issuer}, StatusNotRevoked, false},
		{"sct not covered", []*x509.Certificate{newTestCert(t, big.NewInt(42), uncoveredSCT), issuer}, StatusNotCovered, false},
		{"issuer not enrolled", []*x509.Certificate{newTestCert(t, big.NewInt(42), coveredSCT), otherIssuer}, StatusNotCovered, false},
		{"malformed scts", []*x509.Certificate{newTestCert(t, big.NewInt(42), badSCT), issuer}, StatusNotCovered, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			status, err := c.Check(tc.chain)
			if (err != nil) != tc.wantErr {
				t.Fatalf("Check error = %v, wantErr %v", err, tc.wantErr)
			}
			if status != tc.want {
				t.Errorf("Check = %v, want %v", status, tc.want)
			}
		})
	}
}

// TestCheckerCheckMalformedSerial confirms Check surfaces a RawSerial
// failure: the leaf carries a parseable SCT extension covered by the
// cache's filter, but garbage in RawTBSCertificate, so the serial
// cannot be extracted.
func TestCheckerCheckMalformedSerial(t *testing.T) {
	t.Parallel()

	coveredLog := fillLogID(0x11)
	issuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	coverage := []test.Coverage{{LogId: coveredLog, MinTimestamp: 500, MaxTimestamp: 1500}}
	filterBytes := test.Filter{
		Issuers:  []test.Issuer{{SpkiHash: issuerHash, Revoked: [][]byte{{42}}}},
		Coverage: coverage,
	}.Bytes()
	cacheDir := writeTestCache(t,
		test.Index{Filters: []test.IndexFilter{{Filename: "t.filter", Coverage: coverage}}},
		map[string][]byte{"t.filter": filterBytes},
	)

	c, err := NewChecker(cacheDir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	defer c.Close()

	ext := buildSCTExtension(t, []SCT{{LogID: coveredLog, Timestamp: 1000}})
	leaf := &x509.Certificate{
		Extensions:        []pkix.Extension{*ext},
		RawTBSCertificate: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	status, err := c.Check([]*x509.Certificate{leaf, issuer})
	if !errors.Is(err, ErrMalformedTBSCertificate) {
		t.Fatalf("Check error = %v, want ErrMalformedTBSCertificate", err)
	}
	if status != StatusNotCovered {
		t.Errorf("Check = %v, want StatusNotCovered", status)
	}
}

// TestCheckerCheckIndexLookupError confirms Check surfaces an index
// lookup failure. The index header and tables parse, but the entry
// section is truncated so the per-SCT lookup errors.
func TestCheckerCheckIndexLookupError(t *testing.T) {
	t.Parallel()

	coveredLog := fillLogID(0x11)
	enc := test.Index{Filters: []test.IndexFilter{
		{Filename: "t.filter", Coverage: []test.Coverage{
			{LogId: coveredLog, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}.Bytes()
	// Chop into the trailing 17-byte entry so Lookup's entry-section
	// read comes up short.
	c, err := NewCheckerWith(readerAtNopCloser{bytes.NewReader(enc[:len(enc)-5])}, nil)
	if err != nil {
		t.Fatalf("NewCheckerWith: %v", err)
	}
	defer c.Close()

	ext := buildSCTExtension(t, []SCT{{LogID: coveredLog, Timestamp: 1000}})
	chain := []*x509.Certificate{newTestCert(t, big.NewInt(1), ext), newTestCert(t, nil, nil)}
	status, err := c.Check(chain)
	if err == nil {
		t.Fatal("Check succeeded, want index lookup error")
	}
	if status != StatusNotCovered {
		t.Errorf("Check = %v, want StatusNotCovered", status)
	}
}

// TestCheckerFilterErrors covers Check's error paths for filter files
// that the index references but that cannot be opened or parsed.
func TestCheckerFilterErrors(t *testing.T) {
	t.Parallel()

	logMissing := fillLogID(0x33)
	logBad := fillLogID(0x44)
	cacheDir := writeTestCache(t, test.Index{Filters: []test.IndexFilter{
		{Filename: "missing.filter", Coverage: []test.Coverage{
			{LogId: logMissing, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
		{Filename: "bad.filter", Coverage: []test.Coverage{
			{LogId: logBad, MinTimestamp: 500, MaxTimestamp: 1500},
		}},
	}}, map[string][]byte{"bad.filter": []byte("not a clubcard")})

	c, err := NewChecker(cacheDir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	issuer := newTestCert(t, nil, nil)
	tests := []struct {
		name string
		log  [32]byte
	}{
		{"filter file missing", logMissing},
		{"filter file corrupt", logBad},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ext := buildSCTExtension(t, []SCT{{LogID: tc.log, Timestamp: 1000}})
			chain := []*x509.Certificate{newTestCert(t, big.NewInt(1), ext), issuer}
			status, err := c.Check(chain)
			if err == nil {
				t.Fatal("Check succeeded, want error")
			}
			if status != StatusNotCovered {
				t.Errorf("Check = %v, want StatusNotCovered", status)
			}
		})
	}
}

// TestNewCheckerWith exercises the custom-backend constructor: an
// in-memory index reader paired with a DirOpener.
func TestNewCheckerWith(t *testing.T) {
	t.Parallel()

	coveredLog := fillLogID(0x11)
	issuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	coverage := []test.Coverage{{LogId: coveredLog, MinTimestamp: 500, MaxTimestamp: 1500}}
	filterBytes := test.Filter{
		Issuers:  []test.Issuer{{SpkiHash: issuerHash, Revoked: [][]byte{{42}}}},
		Coverage: coverage,
	}.Bytes()
	idx := test.Index{Filters: []test.IndexFilter{{Filename: "t.filter", Coverage: coverage}}}
	cacheDir := writeTestCache(t, idx, map[string][]byte{"t.filter": filterBytes})

	c, err := NewCheckerWith(
		readerAtNopCloser{bytes.NewReader(idx.Bytes())},
		DirOpener{Dir: filepath.Join(cacheDir, internal.RevocationSubdir)},
	)
	if err != nil {
		t.Fatalf("NewCheckerWith: %v", err)
	}
	defer c.Close()

	ext := buildSCTExtension(t, []SCT{{LogID: coveredLog, Timestamp: 1000}})
	chain := []*x509.Certificate{newTestCert(t, big.NewInt(42), ext), issuer}
	status, err := c.Check(chain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusRevoked {
		t.Errorf("Check = %v, want StatusRevoked", status)
	}
}

// TestNewCheckerWithInvalidIndex confirms a malformed index is rejected
// at construction.
func TestNewCheckerWithInvalidIndex(t *testing.T) {
	t.Parallel()

	_, err := NewCheckerWith(readerAtNopCloser{bytes.NewReader([]byte("junk"))}, nil)
	if err == nil {
		t.Fatal("NewCheckerWith succeeded on junk index, want error")
	}
}

// TestCheckMissingCache confirms Check surfaces NewChecker failures for
// a cache dir with no index.
func TestCheckMissingCache(t *testing.T) {
	t.Parallel()

	leaf := &x509.Certificate{}
	_, err := Check(t.TempDir(), []*x509.Certificate{leaf, leaf})
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}

// readerAtNopCloser adapts an io.ReaderAt with no resources to release
// (e.g. a bytes.Reader) into an IndexReader.
type readerAtNopCloser struct{ io.ReaderAt }

func (readerAtNopCloser) Close() error { return nil }

// writeTestCache lays out a temp upki cache dir holding idx as its
// revocation index.bin plus the given filter files (basename -> bytes).
func writeTestCache(t *testing.T, idx test.Index, filters map[string][]byte) string {
	t.Helper()

	cacheDir := t.TempDir()
	revDir := filepath.Join(cacheDir, internal.RevocationSubdir)
	if err := os.MkdirAll(revDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revDir, "index.bin"), idx.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, data := range filters {
		if err := os.WriteFile(filepath.Join(revDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return cacheDir
}

func TestDirOpener(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	want := []byte("hello upki")
	const filename = "filter-a.filter"
	if err := os.WriteFile(filepath.Join(dir, filename), want, 0o644); err != nil {
		t.Fatal(err)
	}

	rc, err := DirOpener{Dir: dir}.Open(filename)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rc.Close()

	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("payload: got %q, want %q", got, want)
	}
}

func TestDirOpenerMissing(t *testing.T) {
	t.Parallel()

	_, err := DirOpener{Dir: t.TempDir()}.Open("nope.filter")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}
