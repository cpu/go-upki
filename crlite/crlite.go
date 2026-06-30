// Package crlite implements parsing and lookups for Mozilla CRLite clubcard
// filters (V4 encoded).
//
// Typically, you will want to use the higher-level Go upki package instead of
// this lower-level package in order to perform efficient revocation checking
// using a directory of cached filters.
package crlite

import (
	"crypto/sha256"

	"github.com/cpu/go-upki/internal"
)

// RevocationFilter is a parsed CRLite filter.
//
// Build one with [FromBytes] and look up revocation status with
// [RevocationFilter.Contains].
type RevocationFilter struct {
	coverage coverage
	filter   internal.Filter
}

// Contains evaluates the revocation filter against key, trying each
// (logId, timestamp) pair until one falls within a covered interval.
//
// If no covered interval is found, the result is [StatusNotCovered].
func (c *RevocationFilter) Contains(key *LookupKey, timestamps []LogTimestamp) Status {
	for _, t := range timestamps {
		status := c.containsAt(key, t)
		if status == StatusNotCovered {
			continue
		}

		return status
	}

	return StatusNotCovered
}

// LookupKey is the (issuer, serial) pair identifying a certificate, together
// with the precomputed SHA-256(issuer || serial) used by the filter hashing.
type LookupKey struct {
	Issuer           IssuerSpkiHash
	Serial           []byte
	IssuerSerialHash [32]byte
}

// IssuerSpkiHash is the SHA-256 hash of an issuer's SubjectPublicKeyInfo.
type IssuerSpkiHash [32]byte

// NewKey constructs a LookupKey, combining the issuer SPKI hash and serial.
func NewKey(issuer IssuerSpkiHash, serial []byte) LookupKey {
	h := sha256.New()
	h.Write(issuer[:])
	h.Write(serial)
	var sum [32]byte
	h.Sum(sum[:0])

	return LookupKey{Issuer: issuer, Serial: serial, IssuerSerialHash: sum}
}

// Status is a [RevocationFilter.Contains] membership result.
//
//go:generate go tool stringer -type=Status -trimprefix=Status
type Status int

const (
	// StatusGood indicates the certificate is not revoked.
	StatusGood Status = iota
	// StatusNotCovered indicates none of the supplied SCTs falls within
	// a (CT log, timestamp interval) pair that this filter covers.
	//
	// Revocation status can't be determined without updated filters.
	StatusNotCovered
	// StatusNotEnrolled indicates the certificate's issuer is not in
	// the filter's block index.
	//
	// Revocation status can't be determined without updated filters.
	StatusNotEnrolled
	// StatusRevoked indicates the certificate has been revoked.
	StatusRevoked
)

// NewestCoverageCutoff returns the most recent upper-bound CT timestamp
// across all CT logs covered by this filter, or 0 if no logs are covered.
//
// Use this to decide whether the filter is fresh enough for your purposes.
//
// For per-log granularity (e.g. confirming a specific CT log you care
// about is fresh), use [RevocationFilter.CoverageCutoffForLog].
func (c *RevocationFilter) NewestCoverageCutoff() Timestamp {
	var newest Timestamp
	for _, iv := range c.coverage {
		if iv.high > newest {
			newest = iv.high
		}
	}

	return newest
}

// CoverageCutoffForLog returns the upper-bound CT timestamp this filter
// covers for the given CT log id.
//
// The second return is false if the log is not in the filter's coverage map.
func (c *RevocationFilter) CoverageCutoffForLog(id LogId) (Timestamp, bool) {
	iv, ok := c.coverage[id]
	if !ok {
		return 0, false
	}

	return iv.high, true
}

// LogTimestamp is a (CT log id, SCT timestamp) pair extracted from an
// embedded SCT list.
//
// [RevocationFilter.Contains] takes a slice of these as input for the
// clubcard universe-membership check.
type LogTimestamp struct {
	LogId     LogId
	Timestamp Timestamp
}

// LogId is a 32-byte CT log identifier (SHA-256 of the log's public key).
type LogId [32]byte

// Timestamp is a big-endian millisecond-since-epoch CT timestamp.
type Timestamp uint64

// containsAt is a single (logId, timestamp) membership probe.
func (c *RevocationFilter) containsAt(key *LookupKey, t LogTimestamp) Status {
	iv, ok := c.coverage[t.LogId]
	if !ok || t.Timestamp < iv.low || t.Timestamp > iv.high {
		return StatusNotCovered
	}

	meta, ok := c.filter.Blocks[key.Issuer]
	if !ok {
		return StatusNotEnrolled
	}

	if c.filter.Contains(meta, key.IssuerSerialHash, key.Serial) {
		return StatusRevoked
	}

	return StatusGood
}
