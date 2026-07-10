package crlite

import (
	"testing"

	"github.com/cpu/go-upki/internal/test"
)

// FuzzFromBytes exercises the V4 clubcard deserializer and, for inputs that
// parse successfully, the query path over the parsed filter. Neither may
// panic, no matter how malformed the input.
func FuzzFromBytes(f *testing.F) {
	issuerA := [32]byte{0xA1, 0xA2}
	issuerB := [32]byte{0xB1, 0xB2}
	issuerC := [32]byte{0xC1, 0xC2}
	logID := [32]byte{0x10, 0x20}

	// A representative filter: a mixed block, an all-revoked (inverted)
	// block, and an empty block.
	seed := test.Filter{
		Issuers: []test.Issuer{
			{
				SpkiHash:   issuerA,
				Revoked:    [][]byte{{0x01}, {0x02, 0x03}},
				NotRevoked: [][]byte{{0x04}, {0x05, 0x06}, {0x07}},
			},
			{
				SpkiHash: issuerB,
				Revoked:  [][]byte{{0x08}},
			},
			{
				SpkiHash:   issuerC,
				NotRevoked: [][]byte{{0x09}},
			},
		},
		Coverage: []test.Coverage{
			{LogId: logID, MinTimestamp: 100, MaxTimestamp: 200},
		},
	}
	f.Add(seed.Bytes())
	f.Add([]byte{4, 0}) // bare version tag

	f.Fuzz(func(t *testing.T, data []byte) {
		rf, err := FromBytes(data)
		if err != nil {
			return
		}

		// Build probe timestamps from the parsed coverage (interval edges
		// hit the covered path) plus a log id unlikely to be covered.
		var timestamps []LogTimestamp
		for id, iv := range rf.coverage {
			timestamps = append(timestamps,
				LogTimestamp{LogId: id, Timestamp: iv.low},
				LogTimestamp{LogId: id, Timestamp: iv.high})
			if len(timestamps) >= 16 {
				break
			}
		}
		timestamps = append(timestamps, LogTimestamp{LogId: LogId{0xFF}, Timestamp: 150})

		// Query a handful of enrolled blocks, and one unenrolled issuer.
		serials := [][]byte{nil, {0x01}, {0xAB, 0xCD, 0xEF}}
		queried := 0
		for id := range rf.filter.Blocks {
			for _, serial := range serials {
				rf.Contains(new(NewKey(id, serial)), timestamps)
			}

			queried++
			if queried >= 8 {
				break
			}
		}

		rf.Contains(new(NewKey(IssuerSpkiHash{0x42}, []byte{0x01})), timestamps)
	})
}
