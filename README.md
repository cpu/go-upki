# go-upki

CRLite revocation checking in Go, backed by an [`upki`][upki] cache.

Integrates the revocation data cache provided by the [`upki`][upki]
CLI for revocation checking in the Go ecosystem, without requiring 
`cgo` and linking the `upki` FFI library.

Fetching filter data (and creating new filters from revocation
information) is out-of-scope. Only the 
[V4 upki-revocation data format][upki-revocation] is supported.

A place to experiment with API design before proposing a path towards
built-in stdlib support in `crypto/tls`.

## `upki` package

The [`upki`](./upki) package answers "is this certificate revoked?"
given a cache directory and an already-verified certificate chain.
Designed to drop into a [`tls.Config.VerifyPeerCertificate`][vpc]
callback:

```go
checker, err := upki.NewChecker(cacheDir)
if err != nil {
    return err
}
defer checker.Close()

status, err := checker.Check(verifiedChain)
switch status {
case upki.StatusRevoked:    // reject
case upki.StatusNotRevoked: // accept
case upki.StatusNotCovered: // caller's policy
}
```

See [`cmd/upki-https`](./cmd/upki-https) for a small HTTPS client demo
that wires this into a real TLS handshake with a configurable policy
for the "unknown" case.

## Low-level clubcard access

The [`crlite`](./crlite) package parses a single V4 clubcard filter
file directly, without the cache/index machinery. See
[`cmd/crlite-query`](./cmd/crlite-query) for a small example that
checks one certificate against one filter file.

## References

- [Clubcards for the WebPKI][paper], J. M. Schanck, IEEE S&P 2025.
- [upki-revocation data format specification][upki-revocation].

[upki]: https://github.com/rustls/upki
[upki-revocation]: https://c2sp.org/upki-revocation@latest
[vpc]: https://pkg.go.dev/crypto/tls#Config.VerifyPeerCertificate
[paper]: https://ieeexplore.ieee.org/document/11023370
