// crlite-query checks an end-entity certificate against a CRLite V4 filter.
//
// It:
//  1. Parses the filter, issuer cert, and end-entity cert (PEM or DER).
//  2. Verifies the EE cert signature with the issuer's public key.
//  3. Confirms the EE cert is not expired.
//  4. Pulls (logId, timestamp) pairs from the EE cert's embedded SCT
//     extension.
//  5. Queries the filter and prints Good / Revoked / Unknown.
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cpu/go-upki/crlite"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <filter> <issuer certificate> <end entity certificate>\n", os.Args[0])
		os.Exit(1)
	}
	filterPath, issuerPath, eePath := os.Args[1], os.Args[2], os.Args[3]

	filterBytes, err := os.ReadFile(filterPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not read filter")
		os.Exit(1)
	}
	filter, err := crlite.FromBytes(filterBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not parse filter")
		os.Exit(1)
	}

	issuer, err := readCert(issuerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not read issuer certificate")
		os.Exit(1)
	}
	ee, err := readCert(eePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Could not read end-entity certificate")
		os.Exit(1)
	}

	if err := ee.CheckSignatureFrom(issuer); err != nil {
		fmt.Fprintln(os.Stderr, "Invalid signature (wrong issuer certificate?)")
		os.Exit(1)
	}

	now := time.Now()
	if now.Before(ee.NotBefore) || now.After(ee.NotAfter) {
		fmt.Fprintln(os.Stderr, "End-entity certificate is expired")
		os.Exit(1)
	}

	scts, err := embeddedSCTs(ee)
	if err != nil || len(scts) == 0 {
		fmt.Fprintln(os.Stderr, "End entity certificate has no SCTs")
		os.Exit(1)
	}

	rawSerial, err := rawSerial(ee)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not extract serial: %v\n", err)
		os.Exit(1)
	}

	issuerSpkiHash := crlite.IssuerSpkiHash(sha256.Sum256(issuer.RawSubjectPublicKeyInfo))
	timestamps := make([]crlite.LogTimestamp, len(scts))
	for i, s := range scts {
		timestamps[i] = crlite.LogTimestamp{LogId: s.LogID, Timestamp: s.Timestamp}
	}

	fmt.Println(filter.Contains(new(crlite.NewKey(issuerSpkiHash, rawSerial)), timestamps))
}

func readCert(path string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	der := bytes
	if block, _ := pem.Decode(bytes); block != nil {
		der = block.Bytes
	}

	return x509.ParseCertificate(der)
}

// rawSerial pulls the certificate's serial INTEGER out of RawTBSCertificate
// as its DER-encoded contents, preserving any leading sign byte.
//
//	TBSCertificate ::= SEQUENCE {
//	    version [0] EXPLICIT INTEGER DEFAULT v1,
//	    serialNumber CertificateSerialNumber,
//	    ...
//	}
func rawSerial(c *x509.Certificate) ([]byte, error) {
	tbs := cryptobyte.String(c.RawTBSCertificate)
	var inner cryptobyte.String
	if !tbs.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("malformed tbsCertificate")
	}

	// Skip optional [0] EXPLICIT version, if present.
	if inner.PeekASN1Tag(asn1.Tag(0).Constructed().ContextSpecific()) {
		var version cryptobyte.String
		if !inner.ReadASN1(&version, asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, fmt.Errorf("malformed version")
		}
	}

	var serial cryptobyte.String
	if !inner.ReadASN1(&serial, asn1.INTEGER) {
		return nil, fmt.Errorf("malformed serial")
	}

	return serial, nil
}

// embeddedSCTs decodes the SignedCertificateTimestampList extension (RFC 6962
// §3.3) and returns each SCT's log id and timestamp.
//
// The extension value is an OCTET STRING whose contents are the TLS-encoded:
//
//	opaque SerializedSCT<1..2^16-1>;
//	struct { SerializedSCT sct_list<1..2^16-1>; } SignedCertificateTimestampList;
//
// and each SerializedSCT is a TLS-encoded:
//
//	struct {
//	  Version sct_version;            // u8, v1 == 0
//	  LogID id;                       // 32 bytes
//	  uint64 timestamp;
//	  CtExtensions extensions;        // opaque<0..2^16-1>
//	  digitally-signed struct { ... } signature;
//	} SignedCertificateTimestamp;
func embeddedSCTs(c *x509.Certificate) ([]sct, error) {
	var raw []byte
	for _, ext := range c.Extensions {
		// OID 1.3.6.1.4.1.11129.2.4.2 (RFC 6962 §3.3).
		if ext.Id.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}

	// Strip the outer OCTET STRING wrapper.
	outer := cryptobyte.String(raw)
	var inner cryptobyte.String
	if !outer.ReadASN1(&inner, asn1.OCTET_STRING) || !outer.Empty() {
		return nil, fmt.Errorf("malformed SCT extension")
	}

	var listBytes cryptobyte.String
	if !inner.ReadUint16LengthPrefixed(&listBytes) || !inner.Empty() {
		return nil, fmt.Errorf("malformed SCT list")
	}

	var out []sct
	for !listBytes.Empty() {
		var serialized cryptobyte.String
		if !listBytes.ReadUint16LengthPrefixed(&serialized) {
			return nil, fmt.Errorf("malformed serialized SCT")
		}

		var version uint8
		if !serialized.ReadUint8(&version) || version != 0 {
			return nil, fmt.Errorf("unsupported SCT version")
		}

		var s sct
		if !serialized.CopyBytes(s.LogID[:]) {
			return nil, fmt.Errorf("malformed SCT log id")
		}

		var ts uint64
		if !serialized.ReadUint64(&ts) {
			return nil, fmt.Errorf("malformed SCT timestamp")
		}
		s.Timestamp = crlite.Timestamp(ts)

		// Skip extensions and signature; we don't need them.
		var ext cryptobyte.String
		if !serialized.ReadUint16LengthPrefixed(&ext) {
			return nil, fmt.Errorf("malformed SCT extensions")
		}

		// The remainder is the digitally-signed signature; ignore.
		out = append(out, s)
	}

	return out, nil
}

type sct struct {
	LogID     crlite.LogId
	Timestamp crlite.Timestamp
}
