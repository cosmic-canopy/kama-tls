# Gaps found in kama, from building @kama/tls

Found while building the TLS package that `@kama/postgres` depends on. It is written **for the cstar
project**: each entry is reduced to the smallest program that shows it, and each was **run** on the
version named, never inferred from the spec. This file is excluded from the published package, as it is
in `@kama/sodium` and `@kama/postgres`. Gaps hit by postgres are in `../kama-postgres/KAMA_GAPS.md`.

**Current compiler:** `kama 0.9.486+gea6cae46`, the dev build at `../cstar/out/Darwin-arm64/kama`.

**Priorities:**
- **HIGH:** wrong or dangerous behaviour, or a permanent bad publish.
- **MED:** a correct program that does not build, or a capability missing, with a workaround that costs
  something.
- **LOW:** ergonomics or docs.

**We are not attached to any workaround.** Each entry names where its workaround lives, so it can be
deleted when the gap closes.

---

## OPEN

### KTLS-1 · MED · A file-private `comptime` constant used by a generic type is missing from the C when another package instantiates it

**Status:** open. Reproduces on 0.9.486.

**Symptom.** `kama check` passes. `kama build` then fails in clang with "use of undeclared identifier".
The constant is emitted only when it is exported, or (presumably) when the defining package instantiates
the type itself. File-private **functions** used the same way are emitted fine, so only constants are
affected.

**Repro.** A library `glib` and an executable that path-depends on it:

```kama
// glib/src/glib.kama
export { Box };

comptime int32 LIMIT = 7;

type resource Box<T> {
    T v;
    public ctor make(T v) { this.v = give v; }
    public fn int32 limit() { return LIMIT; }
}
```

```kama
// app/src/main.kama
import { glib::Box };
fn int32 main() { Box<int32> b = Box::<int32>.make(v: 1); return b.limit(); }
```

```
$ kama check app/kama.json
kama: app/src/main.kama OK (2 units analyzed)
$ kama build app/kama.json -o app/a
app/.kama/deps/glib/src/glib.kama:8:18: error: use of undeclared identifier 'glib__k_Fglib__LIMIT'
```

With `export { Box, LIMIT };` the same program builds and exits 7.

**Impact.** `TlsStream<S>` is generic over its transport, so every constant its methods use (the engine's
result codes, the record-sized chunk) hit this as soon as the tests instantiated it.

**Workaround here.** `src/stream.kama` spells those constants as file-private functions (`wantRead()`,
`chunk()`, …) rather than `comptime` values. Exporting them would also work, but it would put engine
internals on the package's public surface.

**Suggested fix.** When a generic body is instantiated in another package, emit (or reference) the
defining file's `comptime` constants it uses, as is already done for its file-private functions. A `check`
pass that walks the instantiation would also have caught this before clang.

---

### KTLS-2 · MED · Indexing a view that a call returns passes `check` and fails in clang

**Status:** open. Reproduces on 0.9.486.

**Repro:**

```kama
// Indexing a view returned by a call, without binding it first.
import { std::collections::ConstView };

fn uint8 second(const ref string s) { return s.bytes()[1]; }

fn int32 main() {
    string s = "abc";
    return cast<int32>(second(s: s));
}
```

```
$ kama check viewindex.kama
kama: viewindex.kama OK (4 units analyzed)
$ kama build viewindex.kama -o viewindex
viewindex.kama:4:64: error: cannot take the address of an rvalue of type 'std__collections__ConstView_uint8'
```

The emitted C passes `&(kama_string__bytes(...))` to `ConstView_uint8__op_index`. This is the same family as
`@kama/sodium`'s gap #3 (`addr(of: f.view()[0])`, fixed in 0.9.229 as a kama diagnostic), but for a plain
index rather than `addr(of:)`.

**Workaround here.** Bind the view first, or take it as a by-value `ConstView` parameter; the tests do the
latter. **Hit again in `@kama/postgres`** (its unit tests index `RowValues.value(column:)` directly), with the
same workaround there. Every accessor that hands back a view invites this spelling, so it will keep coming
up. Note that `.length()` on the same call result compiles fine (it is emitted through a compound literal),
which makes the indexing failure more surprising.

**Suggested fix.** Materialise the call result into a temporary before indexing it, or reject the
expression in `check` with a "bind it to a local first" message, as was done for `addr(of:)`.

---

### KTLS-3 · LOW · Without `ConstView` imported, `s.bytes()` reports "`kama_string` has no method `bytes`"

**Status:** open. Reproduces on 0.9.486.

```kama
fn int32 main() {
    string s = "abc";
    uint8 b = s.bytes()[1];
    return cast<int32>(b);
}
```

```
viewindex.kama:4:0: error: `kama_string` has no method `bytes`
```

The method exists. What is missing is the import of its return type, `std::collections::ConstView`. The
message names the type by its C spelling (`kama_string`), not `string`, and points at the wrong cause.

**Suggested fix.** Say that `string.bytes()` returns `std::collections::ConstView<uint8>`, which this file
does not import, and name the type `string`.

---

## FIXED — kept for the record

Nothing yet.

---

## Checked and NOT a gap

Nothing yet.
