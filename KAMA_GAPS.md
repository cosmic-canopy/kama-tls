# Gaps found in kama, from building @kama/tls

Found while building the TLS package that `@kama/postgres` depends on. It is written **for the cstar
project**: each entry is reduced to the smallest program that shows it, and each was **run** on the
version named, never inferred from the spec. This file is excluded from the published package, as it is
in `@kama/sodium` and `@kama/postgres`. Gaps hit by postgres are in `../kama-postgres/KAMA_GAPS.md`.

**Current compiler:** `kama 0.9.519+g28136440`, the dev build at `../cstar/out/Darwin-arm64/kama`. KTLS-1 to KTLS-3
were re-run on it, each with the repro as filed, before moving to FIXED. They were filed against `0.9.486`.

**Priorities:**
- **HIGH:** wrong or dangerous behaviour, or a permanent bad publish.
- **MED:** a correct program that does not build, or a capability missing, with a workaround that costs
  something.
- **LOW:** ergonomics or docs.

**We are not attached to any workaround.** Each entry names where its workaround lives, so it can be
deleted when the gap closes.

---

## OPEN

None.

---

## FIXED — kept for the record

All three were filed against 0.9.486 and verified fixed on 0.9.519 with the repro as filed. Each workaround is
gone from this package.

### KTLS-1 · MED · A file-private `comptime` constant used by a generic type was missing from the C when another package instantiated it — FIXED in 0.9.488

Fixed by cstar `efa8220c`: a private `comptime` that a generic body reads is defined in the header. The repro
builds and exits 7 without exporting `LIMIT`. `src/stream.kama` spells the engine's result codes and the
record-sized chunk as `comptime` constants again (`WANT_READ`, `CLOSED`, `TRUNCATED`, `CERT_VERIFY_FAILED`,
`CHUNK`), and the tests instantiate `TlsStream<PipeEnd>` and `TlsStream<TcpStream>` from another package.

### KTLS-2 · MED · Indexing a view that a call returned passed `check` and failed in clang — FIXED in 0.9.489

Fixed by cstar `5d5c47ad`: an indexed value is held in a temporary. The repro builds and exits 98 (`'b'`). The
tests' `carries` takes the message as a `const ref string` again and indexes `msg.bytes()[got + i]` directly.

### KTLS-3 · LOW · Without `ConstView` imported, `s.bytes()` reported "`kama_string` has no method `bytes`" — FIXED in 0.9.490

Fixed by cstar `9a69fc30`. The repro now says:

```
noimport.kama:3:0: error: `string.bytes()` returns a `ConstView<uint8>`, and this program has no `std::collections::ConstView` — add `import { std::collections::ConstView };`
```

---

## Checked and NOT a gap

Nothing yet.
