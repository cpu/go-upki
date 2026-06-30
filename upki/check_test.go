package upki

import (
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
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
