package internal

import (
	"bytes"
	"testing"

	"github.com/cpu/go-upki/internal/test"
)

// FuzzIndex exercises index.bin deserialization and, for inputs that parse
// successfully, [Index.Lookup] against both fuzzer-chosen and
// directory-present log ids. Neither may panic, no matter how malformed the
// input.
func FuzzIndex(f *testing.F) {
	logA := [32]byte{0xA1, 0xA2}
	logB := [32]byte{0xB1, 0xB2}

	seed := test.Index{
		Filters: []test.IndexFilter{
			{
				Filename: "2026-01-01.filter",
				Coverage: []test.Coverage{
					{LogId: logA, MinTimestamp: 100, MaxTimestamp: 200},
				},
			},
			{
				Filename: "2026-01-02.filter.delta",
				Coverage: []test.Coverage{
					{LogId: logA, MinTimestamp: 150, MaxTimestamp: 250},
					{LogId: logB, MinTimestamp: 300, MaxTimestamp: 400},
				},
			},
		},
	}
	f.Add(seed.Bytes(), logA[:], uint64(150))
	f.Add([]byte("upkiidx0"), []byte{}, uint64(0)) // bare magic

	f.Fuzz(func(t *testing.T, data, logID []byte, timestamp uint64) {
		idx, err := NewIndexFromReader(bytes.NewReader(data), nil)
		if err != nil {
			return
		}

		var id [32]byte
		copy(id[:], logID)
		_, _ = idx.Lookup(id, timestamp)

		// Also probe log ids actually present in the directory so lookups
		// reach the entry-section parsing.
		for i := 0; i < idx.numLogs && i < 8; i++ {
			copy(id[:], idx.logDir[i*logDirEntrySize:])
			_, _ = idx.Lookup(id, timestamp)
		}
	})
}
