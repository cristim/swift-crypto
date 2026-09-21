#!/bin/sh
# Run the NIST SHA-256 and RFC 4231 HMAC-SHA-256 vectors against this fork's pure-Swift backend.
#
# Builds the Darling CryptoKit subset natively for the host and runs it, so the crypto can be
# checked without a macOS or Darling environment. The sources compiled here are exactly the ones
# the Darling build compiles; only the target differs.
#
#   SWIFTC  path to swiftc (default: whatever is on PATH)
set -eu
SWIFTC=${SWIFTC:-swiftc}
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=${TMPDIR:-/tmp}/darling-cryptokit-vectors

cd "$root"
"$SWIFTC" -module-name CryptoKit -swift-version 5 \
  -D DARLING_CRYPTOKIT_MODULE -enable-experimental-feature Lifetimes -O \
  Sources/Crypto/Digests/Digest.swift \
  Sources/Crypto/Digests/Digests.swift \
  Sources/Crypto/Digests/HashFunctions.swift \
  Sources/Crypto/Digests/HashFunctions_SHA2.swift \
  Sources/Crypto/Digests/Darling/Digest_darling.swift \
  Sources/Crypto/Keys/Symmetric/SymmetricKeys.swift \
  Sources/Crypto/Insecure/Insecure.swift \
  Sources/Crypto/Util/ArraySpanHelpers.swift \
  Sources/Crypto/Util/Data+ArraySpan.swift \
  Sources/Crypto/Util/PrettyBytes.swift \
  Sources/Crypto/Util/SafeCompare.swift \
  Sources/Crypto/Util/SecureBytes.swift \
  Sources/Crypto/Util/Zeroization.swift \
  Sources/Crypto/Util/BoringSSL/SafeCompare_boring.swift \
  Sources/Crypto/Util/BoringSSL/RNG_boring.swift \
  Sources/Crypto/Util/BoringSSL/InlineArray+withBytes_boring.swift \
  Sources/Crypto/Util/BoringSSL/Optional+withUnsafeBytes_boring.swift \
  "Sources/Crypto/Message Authentication Codes/HMAC/HMAC.swift" \
  "Sources/Crypto/Message Authentication Codes/MessageAuthenticationCode.swift" \
  "Sources/Crypto/Message Authentication Codes/MACFunctions.swift" \
  "$here/Vectors/support.swift" "$here/Vectors/main.swift" \
  -o "$out"
exec "$out"
