package upki

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cpu/go-upki/crlite"
	"github.com/cpu/go-upki/internal"
)

// Check answers "is the leaf certificate in chain revoked?" using the
// upki cache at cacheDir.
//
// See [Checker.Check] for the chain ordering contract.
//
// Check opens and closes the cache index for every call. For repeated
// lookups against the same cache, construct a [Checker] once and reuse
// it.
func Check(cacheDir string, chain []*x509.Certificate) (Status, error) {
	c, err := NewChecker(cacheDir)
	if err != nil {
		return StatusNotCovered, err
	}
	defer c.Close()

	return c.Check(chain)
}

// Status is the outcome of a revocation [Check].
//
//go:generate go tool stringer -type=Status -trimprefix=Status
type Status int

const (
	// StatusNotCovered means the cache could not determine the
	// certificate's status. Reasons include: the leaf has no embedded
	// SCTs, no filter covers any of the SCT (log id, timestamp) pairs,
	// or covering filters were found but every one reported the issuer
	// as not enrolled.
	StatusNotCovered Status = iota
	// StatusRevoked means a covering filter listed the certificate as
	// revoked.
	StatusRevoked
	// StatusNotRevoked means at least one covering filter answered
	// conclusively that the certificate is not in its revoked set, and
	// no covering filter listed it as revoked.
	StatusNotRevoked
)

// NewChecker opens the upki cache at cacheDir and prepares it for
// revocation lookups.
//
// The returned Checker reads its index and filter files from the local
// filesystem. Use [NewCheckerWith] to supply a custom index or filter
// backend (e.g., HTTP-backed).
//
// A Checker is safe for concurrent [Checker.Check] calls: the index is
// read via [io.ReaderAt] and the filter opener is consulted per call.
//
// Returns an error if the cache dir's revocation index cannot be opened
// or its header is invalid.
func NewChecker(cacheDir string) (*Checker, error) {
	idx, err := internal.NewIndex(cacheDir)
	if err != nil {
		return nil, err
	}

	opener := DirOpener{Dir: filepath.Join(cacheDir, internal.RevocationSubdir)}

	return &Checker{idx: idx, opener: opener}, nil
}

// NewCheckerWith builds a [Checker] that reads its index via r and
// resolves clubcard filter files via opener.
//
// The Checker takes ownership of r and the underlying [io.Closer] is
// invoked by [Checker.Close]. r must cover a full index.bin starting at
// offset 0.
//
// Returns an error if the header cannot be read or is malformed.
func NewCheckerWith(r IndexReader, opener FilterOpener) (*Checker, error) {
	idx, err := internal.NewIndexFromReader(r, r)
	if err != nil {
		return nil, err
	}

	return &Checker{idx: idx, opener: opener}, nil
}

// Checker holds an opened revocation cache and answers repeated
// revocation checks against it.
//
// A Checker must be released with [Checker.Close].
//
// Checker is safe for concurrent [Checker.Check] calls, provided the
// supplied [FilterOpener] is itself safe for concurrent use. The
// bundled [DirOpener] is safe for concurrent use. [Checker.Close]
// must not be called concurrent with lookup operations.
type Checker struct {
	idx    *internal.Index
	opener FilterOpener
}

// Close releases the underlying index (and any file handle it holds).
//
// It must not be called concurrent with lookups.
func (c *Checker) Close() error {
	return c.idx.Close()
}

// Check answers "is the leaf certificate revoked?" for the given chain.
//
// chain[0] must be the end-entity (leaf) certificate and chain[1] must
// be its immediate issuer. If the chain contains less than 2 certificates
// ErrChainTooShort is returned.
//
// A leaf with no embedded SCTs returns [StatusNotCovered] with a nil
// error, since CRLite has no way to pick a covering filter without
// them. A leaf with malformed SCTs returns [StatusNotCovered] and an
// error.
//
// Several filters may cover the leaf's SCTs, and a filter that can't
// answer for the leaf's issuer (not enrolled) must not mask another
// that can. Check therefore queries every covering filter.
//
// A revoked answer from any filter wins immediately, a conclusive
// "not revoked" is remembered but only trusted once no remaining filter
// revokes, and only if every filter is inconclusive is the result
// [StatusNotCovered]. Each distinct filter file is opened and parsed
// at most once per Check call.
//
// Note that the signature on the leaf is not re-verified and Check
// trusts the caller has already done that. This is designed to be used
// in a context like a [tls.Config.VerifyPeerCertificate] callback
// invoked _after_ normal path building, and provided only already
// verified chains.
func (c *Checker) Check(chain []*x509.Certificate) (Status, error) {
	if len(chain) < 2 {
		return StatusNotCovered, ErrChainTooShort
	}
	leaf, issuer := chain[0], chain[1]

	scts, err := EmbeddedSCTs(leaf)
	if err != nil {
		return StatusNotCovered, fmt.Errorf("upki: extracting SCTs: %w", err)
	}
	if len(scts) == 0 {
		return StatusNotCovered, nil
	}

	serial, err := RawSerial(leaf)
	if err != nil {
		return StatusNotCovered, fmt.Errorf("upki: extracting serial: %w", err)
	}
	key := crlite.NewKey(sha256.Sum256(issuer.RawSubjectPublicKeyInfo), serial)
	timestamps := make([]crlite.LogTimestamp, len(scts))
	for i, s := range scts {
		timestamps[i] = crlite.LogTimestamp{LogId: s.LogID, Timestamp: s.Timestamp}
	}

	// Query each filter covering any of the leaf's SCTs, skipping
	// filters already queried. Contains probes every timestamp, so a
	// second query of the same filter can't answer differently.
	notRevoked := false
	seen := make(map[string]bool)
	for _, s := range scts {
		filenames, err := c.idx.Lookup(s.LogID, uint64(s.Timestamp))
		if err != nil {
			return StatusNotCovered, fmt.Errorf("upki: index lookup: %w", err)
		}

		for _, filename := range filenames {
			if seen[filename] {
				continue
			}
			seen[filename] = true

			status, err := c.queryFilter(filename, &key, timestamps)
			if err != nil {
				return StatusNotCovered, err
			}
			switch status {
			case crlite.StatusRevoked:
				return StatusRevoked, nil
			case crlite.StatusGood:
				// Conclusive, but a later filter may still revoke. Remember
				// the result but keep looking.
				notRevoked = true
			default:
				// StatusNotCovered and StatusNotEnrolled both mean the
				// filter couldn't answer for this issuer or these
				// timestamps. Keep looking.
			}
		}
	}

	if notRevoked {
		return StatusNotRevoked, nil
	}

	return StatusNotCovered, nil
}

// queryFilter loads and parses the named filter file, then evaluates
// the (key, timestamps) membership query against it.
func (c *Checker) queryFilter(filename string, key *crlite.LookupKey, timestamps []crlite.LogTimestamp) (crlite.Status, error) {
	filterBytes, err := readFilter(c.opener, filename)
	if err != nil {
		return crlite.StatusNotCovered, fmt.Errorf("upki: reading filter %s: %w", filename, err)
	}

	filter, err := crlite.FromBytes(filterBytes)
	if err != nil {
		return crlite.StatusNotCovered, fmt.Errorf("upki: parsing filter %s: %w", filename, err)
	}

	return filter.Contains(key, timestamps), nil
}

// IndexReader supplies the bytes of an upki revocation index.bin to
// [NewCheckerWith].
//
// Implementations may back this with an [*os.File], an HTTP endpoint
// using range requests, or any other random-access blob store.
//
// The [io.Closer] half is invoked by [Checker.Close]. Wrap a
// zero-cleanup source (e.g., a [*bytes.Reader]) with [io.NopCloser]-style
// glue if it has nothing to release.
type IndexReader interface {
	io.ReaderAt
	io.Closer
}

// FilterOpener opens a clubcard filter file by its basename.
//
// Implementations may back this with the local filesystem
// (see [DirOpener]), with an HTTP endpoint, or any other blob
// store. The returned [io.ReadCloser] is consumed once and
// closed by the caller.
type FilterOpener interface {
	Open(filename string) (io.ReadCloser, error)
}

// DirOpener is a [FilterOpener] that serves filter files from a
// cache directory on the local filesystem.
type DirOpener struct {
	// Dir is the directory containing filter files (typically
	// `~/.cache/upki/revocation` or similar).
	Dir string
}

// Open opens the named filter file inside d.Dir.
func (d DirOpener) Open(filename string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(d.Dir, filename))
}

func readFilter(o FilterOpener, filename string) ([]byte, error) {
	rc, err := o.Open(filename)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return io.ReadAll(rc)
}

// ErrChainTooShort is returned by [Check] and [Checker.Check] when the
// supplied chain has fewer than 2 certificates.
var ErrChainTooShort = errors.New("upki: chain must contain at least 2 certificates (leaf + issuer)")
