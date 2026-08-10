import CryptoKit
import Foundation

/// Digest construction for the armel-authority-v1 family.
///
///     SHA-256(domain || 0x00 || canonical_cbor(object))
///
/// The NUL separator cannot appear in a domain string, so no combination of
/// domain and payload can be reinterpreted as a different domain with a
/// different payload. That injectivity is the whole point: without it, a
/// carefully chosen domain suffix could be shifted into the payload and two
/// different (domain, object) pairs would produce one digest.
///
/// The separator guard below is not decoration. If a domain ever contained a
/// NUL, the construction would stop being injective, so this refuses rather
/// than producing a digest that looks fine and is not.
public enum AuthorityDigest {
    public enum DomainError: Error, Sendable, Hashable {
        case separatorInDomain(String)
        case emptyDomain
    }

    public static func preimage(domain: String, canonicalBytes: [UInt8]) throws -> [UInt8] {
        guard !domain.isEmpty else { throw DomainError.emptyDomain }
        let domainBytes = Array(domain.utf8)
        guard !domainBytes.contains(0x00) else { throw DomainError.separatorInDomain(domain) }
        return domainBytes + [0x00] + canonicalBytes
    }

    public static func digestHex(domain: String, object: CanonicalValue) throws -> String {
        let canonical = try CanonicalCBOR.encode(object)
        return try digestHex(domain: domain, canonicalBytes: canonical)
    }

    public static func digestHex(domain: String, canonicalBytes: [UInt8]) throws -> String {
        let preimage = try preimage(domain: domain, canonicalBytes: canonicalBytes)
        let digest = SHA256.hash(data: Data(preimage))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
