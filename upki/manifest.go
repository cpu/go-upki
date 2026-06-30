package upki

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cpu/go-upki/internal"
)

// LoadManifest reads and parses <cacheDir>/revocation/manifest.json.
func LoadManifest(cacheDir string) (*Manifest, error) {
	path := filepath.Join(cacheDir, internal.RevocationSubdir, "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("upki: reading manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("upki: unmarshaling manifest: %w", err)
	}

	return &manifest, nil
}

// Manifest is the parsed contents the upki revocation cache dir manifest.
//
// For the purposes of go-upki we only expose the GeneratedAt timestamp and
// list of filter files. Other unused fields are elided.
type Manifest struct {
	// GeneratedAt is the UNIX timestamp (seconds) at which the manifest
	// was produced.
	GeneratedAt uint64 `json:"generated_at"`
	// Files lists the filter files described by this manifest.
	Files []ManifestFile `json:"files"`
}

// GeneratedTime returns [Manifest.GeneratedAt] as a [time.Time] in UTC.
func (m *Manifest) GeneratedTime() time.Time {
	return time.Unix(int64(m.GeneratedAt), 0).UTC()
}

// ManifestFile describes one filter file in the cache.
//
// For the purposes of go-upki expose the filename of an included filter file.
// Other unused fields are elided.
type ManifestFile struct {
	// Filename is the basename of the file inside the revocation cache
	// directory.
	Filename string `json:"filename"`
}
