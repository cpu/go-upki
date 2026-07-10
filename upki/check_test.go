package upki

import (
	"crypto/x509"
	"errors"
	"io"
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

	c, err := NewChecker(writeTestCache(t, test.Index{}))
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

	status, err := Check(writeTestCache(t, test.Index{}), chain)
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

	c, err := NewChecker(writeTestCache(t, test.Index{}))
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

// writeTestCache lays out a temp upki cache dir holding idx as its
// revocation index.bin.
func writeTestCache(t *testing.T, idx test.Index) string {
	t.Helper()

	cacheDir := t.TempDir()
	revDir := filepath.Join(cacheDir, internal.RevocationSubdir)
	if err := os.MkdirAll(revDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revDir, "index.bin"), idx.Bytes(), 0o644); err != nil {
		t.Fatal(err)
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
