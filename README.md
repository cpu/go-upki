# go-upki

CRLite clubcard parser and revocation checking library, implemented in Go.

`go-upki` reads V4 Mozilla CRLite filters and answers revocation queries
against them. See `cmd/crlite-query` for a stand-alone example command.

It's assumed filter data is made available, and kept up-to-date
by a packaged [upki] tool invoked by the host system on a regular schedule.

Fetching filter data, or creating new filters from revocation information is
out-of-scope. Only the [V4 upki-revocation data format][upki-revocation] is
supported.

See also J. M. Schanck, ["Clubcards for the WebPKI"][paper] (IEEE S&P 2025).

[upki]: https://github.com/rustls/upki/blob/7f993e21ea212d3f7b6813017d33140e91bbd6d0/PACKAGING.md
[upki-revocation]: https://c2sp.org/upki-revocation@latest
[paper]: https://ieeexplore.ieee.org/document/11023370
