package upki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

func TestEmbeddedSCTsAbsent(t *testing.T) {
	t.Parallel()

	cert := newTestCert(t, nil, nil)
	scts, err := EmbeddedSCTs(cert)
	if err != nil {
		t.Fatalf("EmbeddedSCTs: %v", err)
	}
	if scts != nil {
		t.Fatalf("expected nil scts on absent extension, got %v", scts)
	}
}

func TestEmbeddedSCTsRoundTrip(t *testing.T) {
	t.Parallel()

	want := []SCT{
		{LogID: fillLogID(0x11), Timestamp: 1700000000000},
		{LogID: fillLogID(0x22), Timestamp: 1700000123456},
	}
	cert := newTestCert(t, nil, buildSCTExtension(t, want))

	got, err := EmbeddedSCTs(cert)
	if err != nil {
		t.Fatalf("EmbeddedSCTs: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("len: got %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].LogID != want[i].LogID {
			t.Errorf("scts[%d].LogID: got %x, want %x", i, got[i].LogID, want[i].LogID)
		}
		if got[i].Timestamp != want[i].Timestamp {
			t.Errorf("scts[%d].Timestamp: got %d, want %d", i, got[i].Timestamp, want[i].Timestamp)
		}
	}
}

func TestEmbeddedSCTsMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ext  []byte
	}{
		{"truncated outer octet string", []byte{0x04, 0x05, 0x00}}, // claims 5 bytes, gives 1
		{"truncated v1 sct", buildSerializedSCTExtension(t, []byte{0x00}).Value},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cert := newTestCert(t, nil, &pkix.Extension{
				Id:    embeddedSCTOID,
				Value: tc.ext,
			})

			_, err := EmbeddedSCTs(cert)
			if !errors.Is(err, ErrMalformedSCTExtension) {
				t.Fatalf("want ErrMalformedSCTExtension, got %v", err)
			}
		})
	}
}

func TestEmbeddedSCTsIgnoresUnknownVersions(t *testing.T) {
	t.Parallel()

	want := []SCT{
		{LogID: fillLogID(0x11), Timestamp: 1700000000000},
		{LogID: fillLogID(0x22), Timestamp: 1700000123456},
	}
	ext := buildSerializedSCTExtension(t,
		encodeTestSCT(want[0]),
		[]byte{0x01, 0x07, 0x00, 0x00, 0x01, '?'},
		encodeTestSCT(want[1]),
	)
	cert := newTestCert(t, nil, ext)

	got, err := EmbeddedSCTs(cert)
	if err != nil {
		t.Fatalf("EmbeddedSCTs: %v", err)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("EmbeddedSCTs: got %v, want %v", got, want)
	}
}

func TestRawSerial(t *testing.T) {
	t.Parallel()

	cert := newTestCert(t, big.NewInt(42), nil)
	got, err := RawSerial(cert)
	if err != nil {
		t.Fatalf("RawSerial: %v", err)
	}
	if !bytes.Equal(got, []byte{42}) {
		t.Fatalf("RawSerial: got %x, want 2a", got)
	}
}

func TestRawSerialPreservesSignByte(t *testing.T) {
	t.Parallel()

	// Serial with high bit set; DER prefixes a 0x00 sign byte that
	// *big.Int parsing drops. RawSerial must keep it.
	serialInt := []byte{0x80, 0xab, 0xcd, 0xef}
	serial := new(big.Int).SetBytes(serialInt)
	cert := newTestCert(t, serial, nil)

	got, err := RawSerial(cert)
	if err != nil {
		t.Fatalf("RawSerial: %v", err)
	}
	want := slices.Concat([]byte{0x00}, serialInt)
	if !bytes.Equal(got, want) {
		t.Fatalf("RawSerial: got %x, want %x", got, want)
	}
}

// newTestCert generates a self-signed ECDSA certificate with the given
// serial and an optional extra extension. A nil serial is auto-generated
// by x509.CreateCertificate per RFC 5280 §4.1.2.2.
func newTestCert(t *testing.T, serial *big.Int, extra *pkix.Extension) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	if extra != nil {
		tmpl.ExtraExtensions = []pkix.Extension{*extra}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	return cert
}

// buildSCTExtension encodes scts into the on-wire SCT-list extension
// shape and returns a pkix.Extension with the correct OID.
//
// The TLS-encoded SerializedSCT we build only carries the fields
// EmbeddedSCTs actually reads (version, log id, timestamp, extensions
// length-prefix) and a zero-length signature payload. It is only useful
// for unit testing purposes.
func buildSCTExtension(t *testing.T, scts []SCT) *pkix.Extension {
	t.Helper()

	serialized := make([][]byte, 0, len(scts))
	for _, s := range scts {
		serialized = append(serialized, encodeTestSCT(s))
	}
	return buildSerializedSCTExtension(t, serialized...)
}

func encodeTestSCT(s SCT) []byte {
	ser := []byte{0x00} // version v1
	ser = append(ser, s.LogID[:]...)
	ser = binary.BigEndian.AppendUint64(ser, uint64(s.Timestamp))
	ser = append(ser, 0x00, 0x00) // empty CtExtensions (uint16 length-prefix)

	// Skip signature: EmbeddedSCTs reads up through the extensions
	// length-prefix and then discards the rest of the SerializedSCT,
	// so we don't need to append anything for it.
	return ser
}

func buildSerializedSCTExtension(t *testing.T, scts ...[]byte) *pkix.Extension {
	t.Helper()

	var list []byte
	for _, sct := range scts {
		list = binary.BigEndian.AppendUint16(list, uint16(len(sct)))
		list = append(list, sct...)
	}
	inner := binary.BigEndian.AppendUint16(nil, uint16(len(list)))
	inner = append(inner, list...)

	return &pkix.Extension{
		Id:    embeddedSCTOID,
		Value: wrapInOctetString(t, inner),
	}
}

func wrapInOctetString(t *testing.T, inner []byte) []byte {
	t.Helper()

	var b cryptobyte.Builder
	b.AddASN1OctetString(inner)
	out, err := b.Bytes()
	if err != nil {
		t.Fatalf("AddASN1OctetString: %v", err)
	}

	return out
}

func fillLogID(b byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = b
	}

	return id
}
