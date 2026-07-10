// Integration tests requiring a populated upki revocation cache dir.
//
// Tests in this file are skipped unless UPKI_CACHE_DIR is set.
// CI populates it by running upki fetch + tools/crlite-reencode.
package upki_test

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpu/go-upki/crlite"
	"github.com/cpu/go-upki/upki"
)

// TestClubcardDeser deserializes every clubcard filter listed in the
// cache's manifest, confirming the V4-format on-disk filters parse.
func TestClubcardDeser(t *testing.T) {
	t.Parallel()

	cacheDir := requireCacheDir(t)

	manifest, err := upki.LoadManifest(cacheDir)
	if err != nil {
		t.Fatalf("loading from UPKI_CACHE_DIR=%q failed: %v", cacheDir, err)
	}
	if len(manifest.Files) == 0 {
		t.Fatalf("manifest has no files")
	}

	for _, f := range manifest.Files {
		path := filepath.Join(cacheDir, "revocation", f.Filename)

		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading manifest file %q: %v", path, err)
		}

		// We expect to be able to parse every clubcard filter file listed in
		// the manifest without error.
		_, err = crlite.FromBytes(data)
		if err != nil {
			t.Errorf("deserializing clubcard filter file %q: %v", path, err)
		}
	}
}

// TestManifest confirms LoadManifest results from a real cache are broadly OK.
func TestManifest(t *testing.T) {
	t.Parallel()

	cacheDir := requireCacheDir(t)

	m, err := upki.LoadManifest(cacheDir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	got := m.GeneratedTime()
	if got.IsZero() {
		t.Fatal("GeneratedTime is zero")
	}
	floor := time.Date(2026, time.June, 30, 0, 0, 0, 0, time.UTC)
	if got.Before(floor) {
		t.Fatalf("GeneratedTime %s is before %s; manifest GeneratedAt=%d looks unwired or wrong",
			got, floor, m.GeneratedAt)
	}

	if len(m.Files) < 1 {
		t.Errorf("Files count is suspiciously low: %d", len(m.Files))
	}
}

// TestCheckerHappyPath dials a real public HTTPS endpoint, grabs the
// verified chain, and runs it through Checker.Check.
func TestCheckerHappyPath(t *testing.T) {
	t.Parallel()

	cacheDir := requireCacheDir(t)

	host := os.Getenv("UPKI_CHECK_HOST")
	if host == "" {
		host = "binaryparadox.net:443"
	}

	dialer := &tls.Dialer{Config: &tls.Config{}}
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(dialCtx, "tcp", host)
	if err != nil {
		t.Skipf("dialing %s failed (offline?): %v", host, err)
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	if len(state.VerifiedChains) == 0 {
		t.Fatalf("no verified chains from %s", host)
	}

	c, err := upki.NewChecker(cacheDir)
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	defer c.Close()

	chain := state.VerifiedChains[0]
	status, err := c.Check(chain)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}

	switch status {
	case upki.StatusRevoked:
		t.Fatalf("unexpected Revoked status for %s leaf", host)
	case upki.StatusNotRevoked, upki.StatusNotCovered:
		t.Logf("status for %s: %v (chain length %d)", host, status, len(chain))
	default:
		t.Fatalf("unexpected status: %v", status)
	}
}

// requireCacheDir returns the value of UPKI_CACHE_DIR or skips the
// test if it is unset.
func requireCacheDir(t *testing.T) string {
	t.Helper()

	dir := os.Getenv("UPKI_CACHE_DIR")
	if dir == "" {
		t.Skip("set UPKI_CACHE_DIR to exercise this test")
	}

	return dir
}
