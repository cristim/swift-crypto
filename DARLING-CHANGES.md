# Darling fork of swift-crypto

Upstream: https://github.com/apple/swift-crypto, Apache-2.0. Licence, `LICENSE.txt`, `NOTICE.txt`
and all upstream copyright headers are unchanged and carry with this fork.

Forked at upstream `a9d1d5ab8951ada40cafff8c8e2b551dfde4f390`
("Merge the 5.x branch for the Swift Crypto 5.0 release (#470)").

## Why this fork exists

Darling (macOS emulation on Linux) has no `CryptoKit.framework`, so arm64 macOS apps that link it
abort at dyld. swift-crypto deliberately mirrors CryptoKit's public API, and Swift mangling is a
function of the declared API plus the module name — so building this package **as module
`CryptoKit`** produces a framework that satisfies those bindings exactly.

Two things stop stock swift-crypto from being built that way, and this fork fixes both.

## The changes, sorted

### Darling-specific (would not make sense upstream)

1. **`#if canImport(CryptoKit)` guards, 91 files.** Every source begins with

   ```swift
   #if canImport(CryptoKit)
   @_exported import CryptoKit
   #else
   ... the real implementation ...
   #endif
   ```

   `canImport(CryptoKit)` is **true when the module being compiled is itself named CryptoKit**, so
   building as `-module-name CryptoKit` collapses the whole package into an empty module that
   re-exports itself. Each guard is now
   `#if canImport(CryptoKit) && !DARLING_CRYPTOKIT_MODULE`, so `-D DARLING_CRYPTOKIT_MODULE`
   selects the real implementation. Mechanical and uniform, so it survives a rebase: a whole-tree
   `sed` reapplies it.

2. **Module self-qualification, 2 sites.** `HashFunctions.swift` and `MACFunctions.swift` qualify
   as `Crypto.Digest` / `Crypto.MessageAuthenticationCode` to disambiguate from an associated type
   of the same name. Under `-module-name CryptoKit` there is no `Crypto` module, so both are now
   `#if DARLING_CRYPTOKIT_MODULE` / `#else` pairs naming `CryptoKit.` instead.

3. **`Sources/Crypto/Digests/Darling/Digest_darling.swift` (new).** Darling cannot link BoringSSL
   into this framework, so this supplies what `Digest_boring.swift` would otherwise provide —
   `HashFunctionImplementationDetails` and `DigestImpl` — backed by a **pure-Swift SHA-256**
   (FIPS 180-4) instead of `CCryptoBoringSSL`. `DigestImpl` mirrors `OpenSSLDigestImpl`'s
   copy-on-write context so a half-fed hash function keeps value semantics.

4. **SHA-384, SHA-512 and their `SHA2_*` typealiases compiled out** under
   `DARLING_CRYPTOKIT_MODULE` (`HashFunctions_SHA2.swift`). See the scope boundary below.

### Upstreamable (general, not Darling-specific)

Nothing yet. The pure-Swift SHA-256 in change 3 is a plausible starting point for a
BoringSSL-free backend, but it covers only SHA-256 and has not been reviewed or benchmarked
against that goal, so it is not offered as one.

## Scope boundary

Implemented: **SHA-256 and HMAC-SHA-256**, plus `SymmetricKey`, `Digest`/`SHA256Digest`,
`HashFunction`, `HashedAuthenticationCode` and `MessageAuthenticationCode`.

That is what Darling's corpus binds. The app that motivated this work binds 13 CryptoKit symbols,
all within that surface. Five macOS 26 apps (Weather, FindMy, Maps, Freeform, Music) also link
CryptoKit; their per-symbol demand was **not** re-derived, because the macOS system volume was not
mounted, so the boundary may need widening later.

Not implemented: SHA-384/512, SHA-3, MD5/SHA-1, AES, ChaChaPoly, the key-agreement and signature
suites, HKDF, and everything else in the package. Those files are untouched and still build
normally against BoringSSL for non-Darling consumers.

## Verification

`Darling/run-vectors.sh` builds the compiled subset natively for the host and runs published test
vectors against it:

- **NIST FIPS 180-4 / CAVP SHA-256** — empty string, `"abc"`, the 448-bit and 896-bit messages, and
  one million `'a'`.
- **Streaming** — the one-million-`'a'` digest recomputed in 1, 7, 63, 64, 65, 127 and 1000-byte
  chunks, which is what exercises the block buffer across the 64-byte boundary.
- **Value semantics** — copying a half-fed `SHA256` and diverging must not alias state; `finalize()`
  twice must be stable.
- **RFC 4231 HMAC-SHA-256** — cases 1, 2, 3, 4, 6 and 7, including both over-block-size-key cases.

21/21 pass. Run it with `SWIFTC=/path/to/swiftc ./Darling/run-vectors.sh`.

`Darling/Vectors/support.swift` carries a Linux-only `memset_s` shim so the identical sources can
be exercised on a Linux host; Darwin (and therefore Darling) has `memset_s` natively and does not
use it. The shim is test scaffolding and is not compiled into the framework.
