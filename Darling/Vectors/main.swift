import Foundation

// Compiled into module CryptoKit itself by Darling/run-vectors.sh (no import possible), and
// as a separate test module when the built framework is exercised under Darling.
#if !DARLING_CRYPTOKIT_MODULE
import CryptoKit
#endif

func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

var failures = 0
var checks = 0
func check(_ name: String, _ got: String, _ want: String) {
    checks += 1
    if got == want { print("  PASS  \(name)") }
    else { failures += 1; print("  FAIL  \(name)\n        got  \(got)\n        want \(want)") }
}

print("NIST FIPS 180-4 / CAVP SHA-256 vectors")
check("empty string", hex(Array(SHA256.hash(data: Data()))),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
check("\"abc\"", hex(Array(SHA256.hash(data: Data("abc".utf8)))),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("448-bit message", hex(Array(SHA256.hash(data: Data("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".utf8)))),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
check("896-bit message", hex(Array(SHA256.hash(data: Data("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".utf8)))),
      "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
check("one million 'a'", hex(Array(SHA256.hash(data: Data(repeating: UInt8(ascii: "a"), count: 1_000_000)))),
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")

print("\nStreaming / block-boundary behaviour (exercises the update buffer)")
// Same 1M 'a' message, fed in awkward chunk sizes that straddle the 64-byte block boundary.
for chunk in [1, 7, 63, 64, 65, 127, 1000] {
    var h = SHA256()
    let total = 1_000_000
    var sent = 0
    let block = [UInt8](repeating: UInt8(ascii: "a"), count: chunk)
    while sent < total {
        let n = min(chunk, total - sent)
        h.update(data: block[0..<n])
        sent += n
    }
    check("1M 'a' in \(chunk)-byte chunks", hex(Array(h.finalize())),
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
}
// Copying a half-fed hash must not alias state (value semantics / CoW).
var base = SHA256()
base.update(data: Data("ab".utf8))
var copy = base
copy.update(data: Data("c".utf8))
base.update(data: Data("c".utf8))
check("value semantics: copy then diverge", hex(Array(copy.finalize())),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("value semantics: original unaffected", hex(Array(base.finalize())),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
// finalize() is non-mutating: calling it twice must give the same answer.
let twice = SHA256Wrapper()
check("finalize twice is stable", twice.a, twice.b)

print("\nRFC 4231 HMAC-SHA-256 vectors")
func mac(_ key: [UInt8], _ data: [UInt8]) -> String {
    hex(Array(HMAC<SHA256>.authenticationCode(for: Data(data), using: SymmetricKey(data: Data(key)))))
}
check("RFC 4231 case 1", mac([UInt8](repeating: 0x0b, count: 20), Array("Hi There".utf8)),
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
check("RFC 4231 case 2", mac(Array("Jefe".utf8), Array("what do ya want for nothing?".utf8)),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
check("RFC 4231 case 3", mac([UInt8](repeating: 0xaa, count: 20), [UInt8](repeating: 0xdd, count: 50)),
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
check("RFC 4231 case 4", mac(Array(1...25).map { UInt8($0) }, [UInt8](repeating: 0xcd, count: 50)),
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
check("RFC 4231 case 6 (key > block size)", mac([UInt8](repeating: 0xaa, count: 131),
      Array("Test Using Larger Than Block-Size Key - Hash Key First".utf8)),
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
check("RFC 4231 case 7 (key and data > block size)", mac([UInt8](repeating: 0xaa, count: 131),
      Array("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".utf8)),
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")

print("\n\(checks - failures)/\(checks) vectors passed")
if failures > 0 { exit(1) }
