package upki

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cpu/go-upki/internal"
)

func TestLoadManifest(t *testing.T) {
	t.Parallel()

	cacheDir := writeTestManifest(t,
		`{"generated_at": 1750000000, "files": [{"filename": "a.filter"}, {"filename": "b.filter"}]}`)

	m, err := LoadManifest(cacheDir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if m.GeneratedAt != 1750000000 {
		t.Errorf("GeneratedAt = %d, want 1750000000", m.GeneratedAt)
	}
	if want := time.Unix(1750000000, 0).UTC(); !m.GeneratedTime().Equal(want) {
		t.Errorf("GeneratedTime = %v, want %v", m.GeneratedTime(), want)
	}
	if len(m.Files) != 2 || m.Files[0].Filename != "a.filter" || m.Files[1].Filename != "b.filter" {
		t.Errorf("Files = %+v, want a.filter + b.filter", m.Files)
	}
}

func TestLoadManifestMissing(t *testing.T) {
	t.Parallel()

	_, err := LoadManifest(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want os.ErrNotExist, got %v", err)
	}
}

func TestLoadManifestInvalid(t *testing.T) {
	t.Parallel()

	_, err := LoadManifest(writeTestManifest(t, "not json"))
	if err == nil {
		t.Fatal("LoadManifest succeeded on invalid JSON, want error")
	}
}

func writeTestManifest(t *testing.T, data string) string {
	t.Helper()

	cacheDir := t.TempDir()
	revDir := filepath.Join(cacheDir, internal.RevocationSubdir)
	if err := os.MkdirAll(revDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(revDir, "manifest.json"), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	return cacheDir
}
