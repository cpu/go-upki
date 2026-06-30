// upki-https is a demonstration HTTPS client that consults a local
// upki revocation cache before accepting a server certificate.
//
// Usage:
//
//	upki-https [-cache-dir <dir>] [-strict] <url>
//
// The client performs the normal TLS verification path, then in a
// VerifyPeerCertificate callback opens the upki cache and consults
// CRLite for each verifiedChains entry. Under the default policy a
// connection is rejected only when revocation is confirmed; under
// -strict, a connection is also rejected when no chain produces a
// definitive non-revoked answer (i.e. every chain is NotCovered).
//
// Per-chain errors (cache read failures, malformed SCT extension,
// etc.) are treated as NotCovered for that chain. Only an inability
// to open the cache itself produces a hard error.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/cpu/go-upki/upki"
)

func main() {
	cacheDir := flag.String("cache-dir", defaultCacheDir(), "path to the upki cache directory")
	strict := flag.Bool("strict", false, "reject connection when no chain produces a definitive non-revoked answer")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s [-cache-dir <dir>] [-strict] <url>\n", os.Args[0])
		os.Exit(2)
	}
	target := flag.Arg(0)

	if _, err := url.Parse(target); err != nil {
		fmt.Fprintf(os.Stderr, "invalid url %q: %v\n", target, err)
		os.Exit(2)
	}

	pol := policyDefault
	if *strict {
		pol = policyStrict
	}

	if err := fetch(target, *cacheDir, pol); err != nil {
		fmt.Fprintf(os.Stderr, "connection failed: %v\n", err)
		os.Exit(1)
	}
}

type policy int

const (
	policyDefault policy = iota // reject only on confirmed revocation
	policyStrict                // additionally reject if no chain is definitively NotRevoked
)

func fetch(target, cacheDir string, pol policy) error {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				VerifyPeerCertificate: verifier(cacheDir, pol),
			},
		},
	}

	resp, err := client.Get(target)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	fmt.Printf("connected: %s %s\n", resp.Proto, resp.Status)
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		return fmt.Errorf("reading body: %w", err)
	}

	return nil
}

// verifier returns a tls.Config.VerifyPeerCertificate callback that
// consults the upki cache at cacheDir for each verified chain and
// applies the cross-chain policy reduction.
func verifier(cacheDir string, pol policy) func([][]byte, [][]*x509.Certificate) error {
	return func(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			// Reachable when InsecureSkipVerify is set.
			return errors.New("no verified chains")
		}

		checker, err := upki.NewChecker(cacheDir)
		if err != nil {
			return fmt.Errorf("opening upki cache at %s: %w", cacheDir, err)
		}
		defer checker.Close()

		var sawNotRevoked bool
		for i, chain := range verifiedChains {
			status, err := checker.Check(chain)
			if err != nil {
				// Per-chain errors collapse to "unknown". We log the err
				// and move on.
				fmt.Fprintf(
					os.Stderr,
					"chain %d: error checking (treating as unknown): %v\n",
					i, err,
				)
				continue
			}

			switch status {
			case upki.StatusRevoked:
				return fmt.Errorf("leaf certificate revoked (chain %d)", i)
			case upki.StatusNotRevoked:
				sawNotRevoked = true
			}
		}

		if !sawNotRevoked && pol == policyStrict {
			return errors.New("strict policy: no chain produced a definitive non-revoked answer")
		}

		return nil
	}
}

func defaultCacheDir() string {
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "upki")
	}

	return ""
}
