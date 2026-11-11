# go-upki

CRLite revocation checking in Go, backed by an [`upki`][upki] cache.

Integrates the revocation data cache provided by the [`upki`][upki]
CLI for revocation checking in the Go ecosystem, without requiring 
`cgo` and linking the `upki` FFI library (see
[rustls/upki-go-demo][rustls-upki-go-demo] for an example of this approach).

Fetching filter data (and creating new filters from revocation
information) is out-of-scope. Only the V4 clubcard filter format, and the
"upkiidx1" index file format from the [v1.0.0 upki-revocation][upki-revocation]
specification are supported.

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

## Testing

`go test ./...` runs the unit tests. The integration tests in the
[`upki`](./upki) package additionally need a real cache populated by
[`upki fetch`][upki] and are skipped unless `UPKI_CACHE_DIR` points at
the `cache-dir` reported by `upki show-config`:

```sh
upki fetch
UPKI_CACHE_DIR=<cache-dir> go test ./...
```

CI does the same with a pinned `upki-cli` release against the public
`https://upki.rustls.dev/revocation/` mirror.

## References

- [Clubcards for the WebPKI][paper], J. M. Schanck, IEEE S&P 2025.
- [upki-revocation data format specification][upki-revocation].

[upki]: https://github.com/rustls/upki
[rustls-upki-go-demo]: https://github.com/rustls/upki-go-demo
[upki-revocation]: https://c2sp.org/upki-revocation@v1.0.0
[vpc]: https://pkg.go.dev/crypto/tls#Config.VerifyPeerCertificate
[paper]: https://ieeexplore.ieee.org/document/11023370
