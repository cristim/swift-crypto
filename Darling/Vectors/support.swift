import Foundation

// Compiled into module CryptoKit itself by Darling/run-vectors.sh (no import possible), and
// as a separate test module when the built framework is exercised under Darling.
#if !DARLING_CRYPTOKIT_MODULE
import CryptoKit
#endif

// Test scaffolding ONLY, not part of the fork. Darwin (and therefore Darling) has memset_s;
// Linux does not, and on Linux swift-crypto normally gets zeroization from BoringSSL. This shim
// exists purely so the identical sources can be exercised natively on this host.
#if os(Linux)
@discardableResult
func memset_s(_ s: UnsafeMutableRawPointer?, _ smax: Int, _ c: Int32, _ n: Int) -> Int32 {
    guard let s = s else { return 0 }
    memset(s, c, min(smax, n))
    return 0
}
#endif
struct SHA256Wrapper {
    let a: String
    let b: String
    init() {
        var h = SHA256()
        h.update(data: Array("abc".utf8))
        let d1 = h.finalize()
        let d2 = h.finalize()
        func hx(_ d: SHA256Digest) -> String { d.map { String(format: "%02x", $0) }.joined() }
        a = hx(d1); b = hx(d2)
    }
}
