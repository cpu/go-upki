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

	"github.com/cpu/go-upki/crlite"
	"github.com/cpu/go-upki/upki"
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

	scts, err := upki.EmbeddedSCTs(ee)
	if err != nil || len(scts) == 0 {
		fmt.Fprintln(os.Stderr, "End entity certificate has no SCTs")
		os.Exit(1)
	}

	rawSerial, err := upki.RawSerial(ee)
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
