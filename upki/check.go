package upki

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

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
// filesystem, and reopens the index automatically when a concurrent
// cache update supersedes it. Use [NewCheckerWith] to supply custom
// index and filter backends (e.g., HTTP-backed).
//
// Returns an error if the cache dir's revocation index cannot be opened
// or is malformed.
func NewChecker(cacheDir string) (*Checker, error) {
	opener := DirOpener{Dir: filepath.Join(cacheDir, internal.RevocationSubdir)}

	return NewCheckerWith(opener, opener)
}

// NewCheckerWith builds a [Checker] that opens its revocation index via
// index and resolves clubcard filter files via filters.
//
// The index is opened and parsed immediately. The Checker owns each
// [IndexReader] that index returns, closing it from [Checker.Close] or
// when a reopened index replaces it. index is invoked again whenever a
// check finds a covering filter file missing, which the cache
// atomicity contract makes evidence that the held index was superseded
// by a cache update (see [Checker.Check]).
//
// Returns an error if the index cannot be opened or is malformed.
func NewCheckerWith(index IndexOpener, filters FilterOpener) (*Checker, error) {
	idx, err := openIndex(index)
	if err != nil {
		return nil, err
	}

	return &Checker{idx: idx, indexes: index, opener: filters}, nil
}

// openIndex invokes opener and parses the result into an index that
// owns the returned reader.
func openIndex(opener IndexOpener) (*internal.Index, error) {
	r, err := opener.OpenIndex()
	if err != nil {
		return nil, fmt.Errorf("upki: opening index: %w", err)
	}

	idx, err := internal.NewIndexFromReader(r, r)
	if err != nil {
		r.Close()

		return nil, err
	}

	return idx, nil
}

// Checker holds an opened revocation cache and answers repeated
// revocation checks against it.
//
// A Checker must be released with [Checker.Close].
//
// Checker is safe for concurrent [Checker.Check] calls, provided the
// supplied [FilterOpener] and [IndexOpener] are themselves safe for
// concurrent use. The bundled [DirOpener] is safe for concurrent use.
// [Checker.Close] may be called concurrent with checks: in-flight
// checks either complete against the index they hold or fail once they
// observe the closed state.
type Checker struct {
	// mu guards idx. Each check snapshots idx under the read lock and
	// holds the lock for the check's full duration, so a reopen (which
	// swaps and closes idx under the write lock) can't invalidate the
	// index mid-check.
	mu      sync.RWMutex
	idx     *internal.Index
	indexes IndexOpener
	opener  FilterOpener
}

// Close releases the underlying index (and any file handle it holds).
//
// It is idempotent. Checks in flight when Close is called either
// complete first or report an error.
func (c *Checker) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.idx == nil {
		return nil
	}

	err := c.idx.Close()
	c.idx = nil

	return err
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
// If every filter the index selects turns out not to cover any of the
// leaf's SCTs, the index and filter files contradict each other and
// Check returns [StatusNotCovered] with [ErrInconsistentIndex].
//
// A covering filter file that fails to open because it does not exist
// means the cache was updated after the Checker's index was opened: the
// cache atomicity contract guarantees an index only names filter files
// present when it became visible, so the held index must have been
// superseded. Check reopens the index via the [IndexOpener] and retries
// from scratch, a bounded number of times, before surfacing the error.
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

	for reopens := 0; ; reopens++ {
		status, idx, err := c.checkOnce(&key, scts, timestamps)
		if err == nil || !errors.Is(err, fs.ErrNotExist) || reopens == maxIndexReopens {
			return status, err
		}

		// A filter named by our index is gone, so the index has been
		// superseded by a cache update. Swap in the current one and
		// retry the check from the top.
		if rerr := c.reopenIndex(idx); rerr != nil {
			return StatusNotCovered, fmt.Errorf("upki: reopening superseded index: %w", rerr)
		}
	}
}

// maxIndexReopens bounds how many times a single [Checker.Check] call
// reopens a superseded index before surfacing the missing-filter error,
// per the spec's allowance to bound retries under pathological cache
// update patterns.
const maxIndexReopens = 2

// checkOnce runs one pass of the check procedure. It snapshots the
// Checker's index and holds it for the pass's full duration, as the
// spec's cache atomicity contract requires, and returns the snapshot
// for [Checker.reopenIndex]'s staleness comparison.
func (c *Checker) checkOnce(key *crlite.LookupKey, scts []SCT, timestamps []crlite.LogTimestamp) (Status, *internal.Index, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	idx := c.idx
	if idx == nil {
		return StatusNotCovered, nil, errCheckerClosed
	}

	// Query each filter covering any of the leaf's SCTs, skipping
	// filters already queried. Contains probes every timestamp, so a
	// second query of the same filter can't answer differently.
	notRevoked := false
	queried, notCovered := 0, 0
	seen := make(map[string]bool)
	for _, s := range scts {
		filenames, err := idx.Lookup(s.LogID, uint64(s.Timestamp))
		if err != nil {
			return StatusNotCovered, idx, fmt.Errorf("upki: index lookup: %w", err)
		}

		for _, filename := range filenames {
			if seen[filename] {
				continue
			}
			seen[filename] = true

			status, err := c.queryFilter(filename, key, timestamps)
			if err != nil {
				return StatusNotCovered, idx, err
			}
			queried++
			switch status {
			case crlite.StatusRevoked:
				return StatusRevoked, idx, nil
			case crlite.StatusGood:
				// Conclusive, but a later filter may still revoke. Remember
				// the result but keep looking.
				notRevoked = true
			case crlite.StatusNotCovered:
				// The index claimed this filter covers one of the leaf's
				// SCTs but the filter's own coverage disagrees. Tolerated
				// unless every covering filter is in the same state.
				notCovered++
			default:
				// StatusNotEnrolled means the filter couldn't answer for
				// this issuer. Keep looking.
			}
		}
	}

	if notRevoked {
		return StatusNotRevoked, idx, nil
	}
	if queried > 0 && notCovered == queried {
		return StatusNotCovered, idx, ErrInconsistentIndex
	}

	return StatusNotCovered, idx, nil
}

// reopenIndex swaps in a freshly opened index, unless another check
// already replaced the stale snapshot (or Close ran), in which case the
// caller simply retries against the current state.
//
// The open and parse happen under the write lock: index.bin is small,
// and holding the lock keeps concurrent failing checks from racing
// duplicate replacements.
func (c *Checker) reopenIndex(stale *internal.Index) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.idx != stale {
		return nil
	}

	idx, err := openIndex(c.indexes)
	if err != nil {
		return err
	}

	c.idx.Close()
	c.idx = idx

	return nil
}

// errCheckerClosed is returned by checks that begin (or retry) after
// [Checker.Close] released the index.
var errCheckerClosed = errors.New("upki: checker is closed")

// ErrInconsistentIndex is returned by [Check] and [Checker.Check] when the
// index selected covering filters for the leaf's SCTs but every selected
// filter reported that it covers none of them. The index and the filter
// files disagree about coverage, so the cache can't be trusted to answer
// and the disagreement surfaces as an error rather than a silent
// [StatusNotCovered].
var ErrInconsistentIndex = errors.New("upki: index and filters disagree: no selected filter covers the leaf's SCTs")

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

// IndexOpener opens the upki revocation index (index.bin) for a
// [Checker].
//
// It is invoked once when the Checker is constructed, and again each
// time a check must reopen a superseded index (see [Checker.Check]).
// Every call must return a new independent reader over the index bytes
// currently visible in the cache.
//
// [DirOpener] implements IndexOpener for a local cache directory. An
// HTTP backend might implement it by starting a fresh range-request
// session against its index URL. Use [IndexOpenerFunc] to adapt a
// closure (e.g., over an in-memory snapshot).
type IndexOpener interface {
	OpenIndex() (IndexReader, error)
}

// IndexOpenerFunc adapts a function to an [IndexOpener].
type IndexOpenerFunc func() (IndexReader, error)

// OpenIndex invokes f.
func (f IndexOpenerFunc) OpenIndex() (IndexReader, error) { return f() }

// IndexReader supplies the bytes of an upki revocation index.bin,
// returned by an [IndexOpener].
//
// Implementations may back this with an [*os.File], an HTTP endpoint
// using range requests, or any other random-access blob store.
//
// The [io.Closer] half is invoked when the [Checker] releases the
// index, from [Checker.Close] or when a reopened index replaces it.
// Wrap a zero-cleanup source (e.g., a [*bytes.Reader]) with
// [io.NopCloser]-style glue if it has nothing to release.
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
//
// A filter that does not exist must be reported with an error matching
// [io/fs.ErrNotExist] (an HTTP backend should map a 404 response to
// it): the [Checker] relies on that signal to detect that its index
// has been superseded by a cache update and to retry against a fresh
// one.
type FilterOpener interface {
	Open(filename string) (io.ReadCloser, error)
}

// DirOpener is an [IndexOpener] and [FilterOpener] serving a revocation
// cache directory on the local filesystem.
type DirOpener struct {
	// Dir is the directory containing index.bin and the filter files
	// (typically `~/.cache/upki/revocation` or similar).
	Dir string
}

// Open opens the named filter file inside d.Dir.
func (d DirOpener) Open(filename string) (io.ReadCloser, error) {
	return os.Open(filepath.Join(d.Dir, filename))
}

// OpenIndex opens the revocation index (index.bin) inside d.Dir.
func (d DirOpener) OpenIndex() (IndexReader, error) {
	return os.Open(filepath.Join(d.Dir, internal.IndexFilename))
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
