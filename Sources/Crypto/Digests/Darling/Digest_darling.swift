//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
//
// Darling addition. See DARLING-CHANGES.md.
//
// Darling builds this package as module `CryptoKit` to stand in for Apple's closed-source framework,
// and cannot link BoringSSL into it. This file supplies the pieces Digest_boring.swift would
// otherwise provide -- HashFunctionImplementationDetails and DigestImpl -- backed by a pure-Swift
// SHA-256 rather than CCryptoBoringSSL.
//
// SHA-256 only: that is what Darling's corpus binds. SHA-384, SHA-512 and SHA-3 are compiled out.

#if DARLING_CRYPTOKIT_MODULE

protocol HashFunctionImplementationDetails: HashFunction where Digest: DigestPrivate {}

/// A hash function whose compression is implemented in Swift.
protocol DarlingBackedHashFunction: HashFunctionImplementationDetails {
    associatedtype Context
    static var digestSize: Int { get }
    static func initialize() -> Context
    static func update(_ context: inout Context, data: UnsafeRawBufferPointer)
    static func finalize(_ context: inout Context, digest: UnsafeMutableRawBufferPointer)
}

// MARK: - SHA-256 (FIPS 180-4)

/// Streaming SHA-256 state: the eight chaining words, a 64-byte block buffer, and the message length.
struct DarlingSHA256Context {
    fileprivate var h: (UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32) = (
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19
    )
    fileprivate var buffer = [UInt8](repeating: 0, count: 64)
    fileprivate var bufferCount = 0
    fileprivate var messageLength: UInt64 = 0
}

private let sha256K: [UInt32] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
]

extension DarlingSHA256Context {
    /// Compresses exactly one 64-byte block into the chaining state.
    fileprivate mutating func compress(_ block: UnsafeRawBufferPointer) {
        precondition(block.count == 64)

        var w = [UInt32](repeating: 0, count: 64)
        for i in 0..<16 {
            // FIPS 180-4 treats the message as big-endian.
            w[i] = (UInt32(block[i * 4]) << 24) | (UInt32(block[i * 4 + 1]) << 16)
                | (UInt32(block[i * 4 + 2]) << 8) | UInt32(block[i * 4 + 3])
        }
        for i in 16..<64 {
            let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = w[i - 16] &+ s0 &+ w[i - 7] &+ s1
        }

        var (a, b, c, d, e, f, g, hh) = self.h
        for i in 0..<64 {
            let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            let ch = (e & f) ^ (~e & g)
            let temp1 = hh &+ s1 &+ ch &+ sha256K[i] &+ w[i]
            let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj

            hh = g; g = f; f = e
            e = d &+ temp1
            d = c; c = b; b = a
            a = temp1 &+ temp2
        }

        self.h = (self.h.0 &+ a, self.h.1 &+ b, self.h.2 &+ c, self.h.3 &+ d,
                  self.h.4 &+ e, self.h.5 &+ f, self.h.6 &+ g, self.h.7 &+ hh)
    }
}

@inline(__always)
private func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
    (x >> n) | (x << (32 - n))
}

extension SHA256: DarlingBackedHashFunction {
    static var digestSize: Int { 32 }

    static func initialize() -> DarlingSHA256Context { DarlingSHA256Context() }

    static func update(_ context: inout DarlingSHA256Context, data: UnsafeRawBufferPointer) {
        context.messageLength &+= UInt64(data.count)
        var offset = 0

        // Top up a partially filled block first.
        if context.bufferCount > 0 {
            let take = min(64 - context.bufferCount, data.count)
            for i in 0..<take { context.buffer[context.bufferCount + i] = data[i] }
            context.bufferCount += take
            offset = take
            if context.bufferCount == 64 {
                context.buffer.withUnsafeBytes { context.compress($0) }
                context.bufferCount = 0
            }
        }

        // Then consume whole blocks straight from the input.
        while data.count - offset >= 64 {
            context.compress(UnsafeRawBufferPointer(rebasing: data[offset..<(offset + 64)]))
            offset += 64
        }

        // Whatever is left is a partial block.
        let remaining = data.count - offset
        if remaining > 0 {
            for i in 0..<remaining { context.buffer[i] = data[offset + i] }
            context.bufferCount = remaining
        }
    }

    static func finalize(_ context: inout DarlingSHA256Context, digest: UnsafeMutableRawBufferPointer) {
        precondition(digest.count == Self.digestSize)

        // Padding: 0x80, then zeroes, then the 64-bit big-endian bit length.
        let bitLength = context.messageLength &* 8
        context.buffer[context.bufferCount] = 0x80
        context.bufferCount += 1
        if context.bufferCount > 56 {
            for i in context.bufferCount..<64 { context.buffer[i] = 0 }
            context.buffer.withUnsafeBytes { context.compress($0) }
            context.bufferCount = 0
        }
        for i in context.bufferCount..<56 { context.buffer[i] = 0 }
        for i in 0..<8 {
            context.buffer[56 + i] = UInt8(truncatingIfNeeded: bitLength >> (56 - 8 * UInt64(i)))
        }
        context.buffer.withUnsafeBytes { context.compress($0) }
        context.bufferCount = 0

        let words = [context.h.0, context.h.1, context.h.2, context.h.3,
                     context.h.4, context.h.5, context.h.6, context.h.7]
        for (i, word) in words.enumerated() {
            digest[i * 4] = UInt8(truncatingIfNeeded: word >> 24)
            digest[i * 4 + 1] = UInt8(truncatingIfNeeded: word >> 16)
            digest[i * 4 + 2] = UInt8(truncatingIfNeeded: word >> 8)
            digest[i * 4 + 3] = UInt8(truncatingIfNeeded: word)
        }
    }
}

// MARK: - DigestImpl

/// Mirrors OpenSSLDigestImpl: value semantics over a reference-counted context, copied on write so
/// that copying a half-fed hash function does not alias its state.
struct DarlingDigestImpl<H: DarlingBackedHashFunction>: @unchecked Sendable {
    private var context: DarlingDigestContext<H>

    init() {
        self.context = DarlingDigestContext()
    }

    internal mutating func update(data: UnsafeRawBufferPointer) {
        if !isKnownUniquelyReferenced(&self.context) {
            self.context = DarlingDigestContext(copying: self.context)
        }
        self.context.update(data: data)
    }

    internal func finalize() -> H.Digest {
        self.context.finalize()
    }
}

private final class DarlingDigestContext<H: DarlingBackedHashFunction> {
    private var context: H.Context

    init() {
        self.context = H.initialize()
    }

    init(copying original: DarlingDigestContext) {
        self.context = original.context
    }

    func update(data: UnsafeRawBufferPointer) {
        H.update(&self.context, data: data)
    }

    func finalize() -> H.Digest {
        // finalize() is non-mutating on the hash function, so pad a copy and leave the stream intact.
        var copyContext = self.context
        return withUnsafeTemporaryAllocation(byteCount: H.digestSize, alignment: 1) { digestPointer in
            defer { digestPointer.zeroize() }
            H.finalize(&copyContext, digest: digestPointer)
            // Force-unwrapped because a wrong digest size here is an internal error.
            return H.Digest(copying: digestPointer.bytes)!
        }
    }
}

#endif  // DARLING_CRYPTOKIT_MODULE
