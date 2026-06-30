# crlite-reencode

Re-encodes the clubcard filters in a [`upki`][upki] revocation cache as V4.

```
crlite-reencode --src <upki cache dir> --dest <output cache dir>
```

Reads `revocation/manifest.json` and each filter listed from the src dir, 
re-encodes each filter as V4, copies `index.bin` verbatim, and writes an 
updated `manifest.json` (w/ recomputed sizes + SHA-256 hashes) into `--dest`.

## Why this exists

`upki fetch` currently writes V3-encoded clubcard filters, but
[`go-upki`][go-upki] only parses V4. This tool bridges that gap so CI
(and local dev) can exercise the Go side against real upstream data without
waiting on upstream migration to V4.

**Temporary.** Once `upki fetch` writes V4 directly this tool should be
deleted along with the CI job that runs it.

[upki]: https://github.com/rustls/upki
[go-upki]: https://github.com/cpu/go-upki
