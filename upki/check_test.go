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

// TestCheckerCheckAggregation exercises Check's handling of multiple
// covering filters.
//
// A filter that can't answer for the leaf's issuer (not enrolled) must
// not mask another filter that can, a conclusive "not revoked" must not
// mask a later revocation, and a revoked answer short-circuits without
// reading the remaining filters.
func TestCheckerCheckAggregation(t *testing.T) {
	t.Parallel()

	logA, logB := fillLogID(0x11), fillLogID(0x22)
	issuer := newTestCert(t, nil, nil)
	otherIssuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	otherHash := sha256.Sum256(otherIssuer.RawSubjectPublicKeyInfo)

	covA := test.Coverage{LogId: logA, MinTimestamp: 0, MaxTimestamp: 2000}
	covB := test.Coverage{LogId: logB, MinTimestamp: 0, MaxTimestamp: 2000}
	// An interval for log A that misses the SCT timestamps used below.
	covALate := test.Coverage{LogId: logA, MinTimestamp: 2000, MaxTimestamp: 3000}

	// enrolled builds a filter that can answer for issuer: serial 42 is
	// revoked, serial 43 is not.
	enrolled := func(cov ...test.Coverage) []byte {
		return test.Filter{
			Issuers: []test.Issuer{{
				SpkiHash:   issuerHash,
				Revoked:    [][]byte{{42}},
				NotRevoked: [][]byte{{43}},
			}},
			Coverage: cov,
		}.Bytes()
	}
	// notEnrolled builds a filter that enrolls only otherIssuer, so it
	// is inconclusive for chains issued by issuer.
	notEnrolled := func(cov ...test.Coverage) []byte {
		return test.Filter{
			Issuers:  []test.Issuer{{SpkiHash: otherHash, Revoked: [][]byte{{7}}}},
			Coverage: cov,
		}.Bytes()
	}
	// goodFor42 builds a filter that conclusively answers "not revoked"
	// for serial 42.
	goodFor42 := func(cov ...test.Coverage) []byte {
		return test.Filter{
			Issuers: []test.Issuer{{
				SpkiHash:   issuerHash,
				Revoked:    [][]byte{{9}},
				NotRevoked: [][]byte{{42}},
			}},
			Coverage: cov,
		}.Bytes()
	}

	tests := []struct {
		name   string
		idx    test.Index
		files  map[string][]byte
		serial int64
		scts   []SCT
		want   Status
	}{
		{
			// The filter covering the first SCT can't answer for our
			// issuer and the verdict comes from the second SCT's filter.
			name: "continues past not enrolled to revoked",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files:  map[string][]byte{"f0.filter": notEnrolled(covA), "f1.filter": enrolled(covB)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:   StatusRevoked,
		},
		{
			name: "continues past not enrolled to not revoked",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files:  map[string][]byte{"f0.filter": notEnrolled(covA), "f1.filter": enrolled(covB)},
			serial: 43,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:   StatusNotRevoked,
		},
		{
			// Every covering filter is inconclusive, so the cache can't
			// determine the certificate's status.
			name: "all covering filters not enrolled",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files:  map[string][]byte{"f0.filter": notEnrolled(covA), "f1.filter": notEnrolled(covB)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:   StatusNotCovered,
		},
		{
			// A revoked verdict short-circuits: f1's file is absent from
			// disk, so Check would error if it read past the verdict.
			name: "revoked stops before later filters",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files:  map[string][]byte{"f0.filter": enrolled(covA)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:   StatusRevoked,
		},
		{
			// A "not revoked" answer must not short-circuit: a later
			// covering filter revokes the certificate and revocation wins.
			name: "not revoked does not stop the check",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files:  map[string][]byte{"f0.filter": goodFor42(covA), "f1.filter": enrolled(covB)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:   StatusRevoked,
		},
		{
			// One log, two covering filters: the verdict comes from the
			// second even though the first is inconclusive.
			name: "second filter for the same log revokes",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covA}},
			}},
			files:  map[string][]byte{"f0.filter": notEnrolled(covA), "f1.filter": enrolled(covA)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}},
			want:   StatusRevoked,
		},
		{
			name: "second filter for the same log answers not revoked",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covA}},
			}},
			files:  map[string][]byte{"f0.filter": notEnrolled(covA), "f1.filter": enrolled(covA)},
			serial: 43,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}},
			want:   StatusNotRevoked,
		},
		{
			// An entry whose interval misses the SCT is skipped without
			// reading its filter (f0's file is absent), and the scan
			// continues to the covering entry for the same log.
			name: "non-matching interval skipped without load",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covALate}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covA}},
			}},
			files:  map[string][]byte{"f1.filter": enrolled(covA)},
			serial: 42,
			scts:   []SCT{{LogID: logA, Timestamp: 1000}},
			want:   StatusRevoked,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewChecker(writeTestCache(t, tc.idx, tc.files))
			if err != nil {
				t.Fatalf("NewChecker: %v", err)
			}
			defer c.Close()

			ext := buildSCTExtension(t, tc.scts)
			chain := []*x509.Certificate{newTestCert(t, big.NewInt(tc.serial), ext), issuer}
			status, err := c.Check(chain)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if status != tc.want {
				t.Errorf("Check = %v, want %v", status, tc.want)
			}
		})
	}
}

// TestCheckerCheckInconsistentIndex covers the index/filter coverage
// disagreement rule: when every filter the index selects reports that it
// covers none of the leaf's SCTs, Check surfaces ErrInconsistentIndex
// instead of a silent StatusNotCovered. Any filter that can answer (even
// just "not enrolled") suppresses the error.
func TestCheckerCheckInconsistentIndex(t *testing.T) {
	t.Parallel()

	logA, logB := fillLogID(0x11), fillLogID(0x22)
	issuer := newTestCert(t, nil, nil)
	otherIssuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	otherHash := sha256.Sum256(otherIssuer.RawSubjectPublicKeyInfo)

	covA := test.Coverage{LogId: logA, MinTimestamp: 0, MaxTimestamp: 2000}
	covB := test.Coverage{LogId: logB, MinTimestamp: 0, MaxTimestamp: 2000}
	// A log A interval disjoint from the SCT timestamps used below: a
	// filter carrying it contradicts an index entry claiming covA.
	covALate := test.Coverage{LogId: logA, MinTimestamp: 3000, MaxTimestamp: 4000}

	filter := func(spki [32]byte, cov ...test.Coverage) []byte {
		return test.Filter{
			Issuers:  []test.Issuer{{SpkiHash: spki, Revoked: [][]byte{{42}}, NotRevoked: [][]byte{{43}}}},
			Coverage: cov,
		}.Bytes()
	}

	tests := []struct {
		name    string
		idx     test.Index
		files   map[string][]byte
		serial  int64
		scts    []SCT
		want    Status
		wantErr error
	}{
		{
			// The index's only selected filter disavows the SCT.
			name: "single filter disagrees",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
			}},
			files:   map[string][]byte{"f0.filter": filter(issuerHash, covALate)},
			serial:  42,
			scts:    []SCT{{LogID: logA, Timestamp: 1000}},
			want:    StatusNotCovered,
			wantErr: ErrInconsistentIndex,
		},
		{
			name: "every filter disagrees",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files: map[string][]byte{
				"f0.filter": filter(issuerHash, covALate),
				"f1.filter": filter(issuerHash, covALate),
			},
			serial:  42,
			scts:    []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:    StatusNotCovered,
			wantErr: ErrInconsistentIndex,
		},
		{
			// A not-enrolled answer still confirms the filter covers the
			// SCTs, so one contradicting filter is tolerated.
			name: "not enrolled filter suppresses the error",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files: map[string][]byte{
				"f0.filter": filter(issuerHash, covALate),
				"f1.filter": filter(otherHash, covB),
			},
			serial:  42,
			scts:    []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:    StatusNotCovered,
			wantErr: nil,
		},
		{
			name: "conclusive filter suppresses the error",
			idx: test.Index{Filters: []test.IndexFilter{
				{Filename: "f0.filter", Coverage: []test.Coverage{covA}},
				{Filename: "f1.filter", Coverage: []test.Coverage{covB}},
			}},
			files: map[string][]byte{
				"f0.filter": filter(issuerHash, covALate),
				"f1.filter": filter(issuerHash, covB),
			},
			serial:  43,
			scts:    []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}},
			want:    StatusNotRevoked,
			wantErr: nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, err := NewChecker(writeTestCache(t, tc.idx, tc.files))
			if err != nil {
				t.Fatalf("NewChecker: %v", err)
			}
			defer c.Close()

			ext := buildSCTExtension(t, tc.scts)
			chain := []*x509.Certificate{newTestCert(t, big.NewInt(tc.serial), ext), issuer}
			status, err := c.Check(chain)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Check error = %v, want %v", err, tc.wantErr)
			}
			if status != tc.want {
				t.Errorf("Check = %v, want %v", status, tc.want)
			}
		})
	}
}

// TestCheckerCheckFilterLoadedOnce confirms Check reads a filter file at
// most once, even when it covers several of the leaf's SCTs.
func TestCheckerCheckFilterLoadedOnce(t *testing.T) {
	t.Parallel()

	logA, logB := fillLogID(0x11), fillLogID(0x22)
	issuer := newTestCert(t, nil, nil)
	issuerHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)

	coverage := []test.Coverage{
		{LogId: logA, MinTimestamp: 0, MaxTimestamp: 2000},
		{LogId: logB, MinTimestamp: 0, MaxTimestamp: 2000},
	}
	filterBytes := test.Filter{
		Issuers:  []test.Issuer{{SpkiHash: issuerHash, Revoked: [][]byte{{41}}, NotRevoked: [][]byte{{42}}}},
		Coverage: coverage,
	}.Bytes()
	idx := test.Index{Filters: []test.IndexFilter{{Filename: "shared.filter", Coverage: coverage}}}

	opener := &countingOpener{files: map[string][]byte{"shared.filter": filterBytes}, opens: map[string]int{}}
	c, err := NewCheckerWith(readerAtNopCloser{bytes.NewReader(idx.Bytes())}, opener)
	if err != nil {
		t.Fatalf("NewCheckerWith: %v", err)
	}
	defer c.Close()

	// Both SCTs resolve to shared.filter, and it answers "not revoked" for
	// the first, so a second (redundant) load would go unnoticed without
	// counting opens.
	ext := buildSCTExtension(t, []SCT{{LogID: logA, Timestamp: 1000}, {LogID: logB, Timestamp: 1000}})
	chain := []*x509.Certificate{newTestCert(t, big.NewInt(42), ext), issuer}
	status, err := c.Check(chain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if status != StatusNotRevoked {
		t.Errorf("Check = %v, want StatusNotRevoked", status)
	}
	if got := opener.opens["shared.filter"]; got != 1 {
		t.Errorf("shared.filter opened %d times, want 1", got)
	}
}

// countingOpener is an in-memory FilterOpener that records how many
// times each filename is opened.
type countingOpener struct {
	files map[string][]byte
	opens map[string]int
}

func (o *countingOpener) Open(filename string) (io.ReadCloser, error) {
	o.opens[filename]++
	data, ok := o.files[filename]
	if !ok {
		return nil, os.ErrNotExist
	}

	return io.NopCloser(bytes.NewReader(data)), nil
}

// TestCheckerCheckMalformedSerial confirms Check surfaces a RawSerial
// failure: the leaf carries a parseable SCT extension but garbage in
// RawTBSCertificate, so the serial cannot be extracted.
func TestCheckerCheckMalformedSerial(t *testing.T) {
	t.Parallel()

	c, err := NewChecker(writeTestCache(t, test.Index{}, nil))
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	defer c.Close()

	ext := buildSCTExtension(t, []SCT{{LogID: fillLogID(0x11), Timestamp: 1000}})
	leaf := &x509.Certificate{
		Extensions:        []pkix.Extension{*ext},
		RawTBSCertificate: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	status, err := c.Check([]*x509.Certificate{leaf, newTestCert(t, nil, nil)})
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
