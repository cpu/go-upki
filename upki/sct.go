package upki

import (
	"crypto/x509"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cpu/go-upki/crlite"
)

// EmbeddedSCTs decodes the RFC 6962 SignedCertificateTimestampList
// extension from cert and returns one [SCT] per entry.
//
// Returns (nil, nil) when the extension is absent. A cert with no
// embedded SCTs simply has no CRLite coverage signal.
//
// ErrMalformedSCTExtension is returned if the extension is present but
// malformed.
//
// See RFC 6962 §3.3 for more information.
func EmbeddedSCTs(cert *x509.Certificate) ([]SCT, error) {
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(embeddedSCTOID) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}

	// The contents of the ASN.1 OCTET STRING embedded in an OCSP extension
	// or X509v3 certificate extension are as follows:
	//
	//	opaque SerializedSCT<1..2^16-1>;
	//	struct {
	//    serializedSCT sct_list<1..2^16-1>;
	//  } SignedCertificateTimestampList;

	outer := cryptobyte.String(raw)
	var inner cryptobyte.String
	if !outer.ReadASN1(&inner, asn1.OCTET_STRING) || !outer.Empty() {
		return nil, fmt.Errorf("%w: outer wrapper", ErrMalformedSCTExtension)
	}

	var listBytes cryptobyte.String
	if !inner.ReadUint16LengthPrefixed(&listBytes) || !inner.Empty() {
		return nil, fmt.Errorf("%w: sct list", ErrMalformedSCTExtension)
	}

	var out []SCT
	for !listBytes.Empty() {
		var serialized cryptobyte.String
		if !listBytes.ReadUint16LengthPrefixed(&serialized) {
			return nil, fmt.Errorf("%w: serialized sct", ErrMalformedSCTExtension)
		}

		//	struct {
		//	  Version sct_version;            // u8, v1 == 0
		//	  LogID id;                       // 32 bytes
		//	  uint64 timestamp;
		//	  CtExtensions extensions;        // opaque<0..2^16-1>
		//	  digitally-signed struct {
		//	    ...
		//	  };
		//	} SignedCertificateTimestamp;

		var version uint8
		if !serialized.ReadUint8(&version) || version != 0 {
			return nil, fmt.Errorf("%w: unsupported sct version", ErrMalformedSCTExtension)
		}

		var s SCT
		if !serialized.CopyBytes(s.LogID[:]) {
			return nil, fmt.Errorf("%w: sct log id", ErrMalformedSCTExtension)
		}

		var ts uint64
		if !serialized.ReadUint64(&ts) {
			return nil, fmt.Errorf("%w: sct timestamp", ErrMalformedSCTExtension)
		}
		s.Timestamp = crlite.Timestamp(ts)

		// Validate (but discard) the CtExtensions length prefix to
		// catch truncated SCTs. The trailing signature is not parsed:
		// the outer length-prefix already delimits this SerializedSCT.
		var ext cryptobyte.String
		if !serialized.ReadUint16LengthPrefixed(&ext) {
			return nil, fmt.Errorf("%w: sct extensions", ErrMalformedSCTExtension)
		}

		out = append(out, s)
	}

	return out, nil
}

// SCT is a parsed Signed Certificate Timestamp from a leaf certificate's
// embedded SCT extension.
//
// It carries the two fields CRLite needs to pick covering filters: the
// CT log's identifier and the log's reported issuance timestamp.
//
// Important: The SCT's signature is intentionally not retained.
// In the revocation checking context as assume the CT log inclusion
// proof was already validated.
type SCT struct {
	LogID     crlite.LogId
	Timestamp crlite.Timestamp
}

// ErrMalformedSCTExtension is returned by [EmbeddedSCTs] when the SCT
// extension is present but cannot be parsed.
var ErrMalformedSCTExtension = errors.New("upki: malformed SCT extension")

// RFC 6962 §3.3
var embeddedSCTOID = []int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// RawSerial returns the certificate's serial number as the DER-encoded
// contents of the serialNumber INTEGER, preserving any leading sign
// byte.
//
// In contrast, [x509.Certificate.SerialNumber] is a *big.Int which discards
// the leading sign byte. CRLite hashes the original DER bytes as a lookup
// input, so we parse the raw serial DER ourselves here.
func RawSerial(cert *x509.Certificate) ([]byte, error) {
	//	TBSCertificate ::= SEQUENCE {
	//	    version [0] EXPLICIT INTEGER DEFAULT v1,
	//	    serialNumber CertificateSerialNumber,
	//	    ...
	//	}
	tbs := cryptobyte.String(cert.RawTBSCertificate)
	var inner cryptobyte.String
	if !tbs.ReadASN1(&inner, asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: outer sequence", ErrMalformedTBSCertificate)
	}

	// Skip optional [0] EXPLICIT version, if present.
	if inner.PeekASN1Tag(asn1.Tag(0).Constructed().ContextSpecific()) {
		var version cryptobyte.String
		if !inner.ReadASN1(&version, asn1.Tag(0).Constructed().ContextSpecific()) {
			return nil, fmt.Errorf("%w: version", ErrMalformedTBSCertificate)
		}
	}

	var serial cryptobyte.String
	if !inner.ReadASN1(&serial, asn1.INTEGER) {
		return nil, fmt.Errorf("%w: serial", ErrMalformedTBSCertificate)
	}

	return serial, nil
}

// ErrMalformedTBSCertificate is returned by [RawSerial] when the raw
// TBSCertificate cannot be parsed enough to extract the serial number.
var ErrMalformedTBSCertificate = errors.New("upki: malformed TBSCertificate")
