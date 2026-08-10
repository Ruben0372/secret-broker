import Foundation
import SecretBrokerContracts
import Testing

/// Independent reproduction of the armel-authority-v1 canonical encoding and
/// digest construction.
///
/// Reproduced from the contract document, not from the upstream implementation,
/// which was deliberately never read. The published vectors are used strictly
/// as black-box known answers: if this encoder and theirs disagree on a single
/// byte, the canonical hex will not match and the digest will not match.
///
/// The rules come from `contracts/authority/v1/README.md`: deterministic CBOR
/// per RFC 8949 section 4.2.1, restricted to unsigned integer, text string,
/// array, map and boolean; shortest-form heads; definite lengths only; map keys
/// text, sorted bytewise by encoded form; duplicate keys rejected; strict UTF-8;
/// no trailing bytes; at most 32 nested containers. The digest is
/// SHA-256(domain || 0x00 || canonical_cbor(object)).
@Suite("Authority canonical encoding and digests")
struct AuthorityCanonicalTests {
    static var corpus: [String: Any] {
        get throws {
            try ContractVectorFixtures.json(
                at: ContractVectorFixtures.authorityRoot
                    .appendingPathComponent("authority-v1-vectors.json")
            )
        }
    }

    /// Converts the vector's JSON field map into the canonical value model.
    /// Fails rather than coercing: a vector containing a type the family
    /// excludes is a finding, not something to quietly map onto a neighbour.
    static func canonicalValue(from json: Any) throws -> CanonicalValue {
        switch json {
        case let text as String:
            return .text(text)
        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                return .boolean(number.boolValue)
            }
            let value = number.int64Value
            guard value >= 0 else {
                throw VectorShapeError.excludedType("negative integer \(value)")
            }
            return .unsigned(UInt64(value))
        case let array as [Any]:
            return .array(try array.map { try canonicalValue(from: $0) })
        case let object as [String: Any]:
            var map: [String: CanonicalValue] = [:]
            for (key, value) in object {
                map[key] = try canonicalValue(from: value)
            }
            return .map(map)
        default:
            throw VectorShapeError.excludedType(String(describing: type(of: json)))
        }
    }

    enum VectorShapeError: Error { case excludedType(String) }

    @Test("Every positive vector reproduces its canonical bytes and its digest")
    func positiveVectorsReproduce() throws {
        let positives = try #require(try Self.corpus["positive"] as? [[String: Any]])
        #expect(positives.count == 5, "expected exactly 5 positive vectors, found \(positives.count)")

        var reproduced = 0
        for vector in positives {
            let name = vector["name"] as? String ?? "unnamed"
            let fields = try #require(vector["fields"], "\(name) carries no fields")
            let expectedHex = try #require(vector["canonical_hex"] as? String)
            let expectedDigest = try #require(vector["digest"] as? String)
            let domain = try #require(vector["digest_domain"] as? String)

            let value = try Self.canonicalValue(from: fields)
            let encoded = try CanonicalCBOR.encode(value)
            let encodedHex = encoded.map { String(format: "%02x", $0) }.joined()
            #expect(
                encodedHex == expectedHex,
                "\(name): canonical bytes diverge from the published encoding"
            )

            let digest = try AuthorityDigest.digestHex(domain: domain, object: value)
            #expect(digest == expectedDigest, "\(name): digest diverges under domain \(domain)")
            reproduced += 1
        }
        // Non-vacuity: every published positive must actually have been driven.
        #expect(reproduced == 5, "reproduced \(reproduced) of 5 positive vectors")
    }

    @Test("A decoder round-trips every positive vector back to the same bytes")
    func positiveVectorsRoundTrip() throws {
        let positives = try #require(try Self.corpus["positive"] as? [[String: Any]])
        var roundTripped = 0
        for vector in positives {
            let name = vector["name"] as? String ?? "unnamed"
            let hex = try #require(vector["canonical_hex"] as? String)
            let bytes = try #require(CanonicalCBOR.bytes(fromHex: hex), "\(name): bad hex in vector")

            let decoded = try CanonicalCBOR.decode(bytes)
            let reEncoded = try CanonicalCBOR.encode(decoded)
            #expect(
                reEncoded == bytes,
                "\(name): decode then encode did not return the input bytes, so the encoding is not canonical-on-input"
            )
            roundTripped += 1
        }
        #expect(roundTripped == 5, "round-tripped \(roundTripped) of 5")
    }

    @Test("Encoding-level negative vectors are refused with the published reason")
    func encodingNegativesAreRefused() throws {
        let negatives = try #require(try Self.corpus["negative"] as? [[String: Any]])
        #expect(negatives.count == 11, "expected exactly 11 negative vectors, found \(negatives.count)")

        // The categories this suite decides at the encoding layer. The rest are
        // semantic and are driven by the claim-validation suite.
        // list_ordering is deliberately NOT here: an unsorted or duplicated
        // selector list is well-formed CBOR that decodes fine and is refused
        // one layer up. Asserting the decoder rejects it would be asserting
        // the wrong layer, and would pass only by accident.
        let encodingCategories: Set<String> = ["alternate_encoding", "duplicate_field"]

        var exercised = 0
        for vector in negatives {
            let category = vector["category"] as? String ?? ""
            guard encodingCategories.contains(category) else { continue }
            let name = vector["name"] as? String ?? "unnamed"
            let expectedReason = try #require(vector["expected_reason"] as? String)
            let hex = try #require(vector["encoded_hex"] as? String, "\(name) carries no encoded_hex")
            let bytes = try #require(CanonicalCBOR.bytes(fromHex: hex))

            do {
                _ = try CanonicalCBOR.decode(bytes)
                Issue.record("\(name): accepted bytes that must be refused with \(expectedReason)")
            } catch let error as CanonicalCBORError {
                #expect(
                    error.reasonCode == expectedReason,
                    "\(name): refused with \(error.reasonCode), published reason is \(expectedReason)"
                )
            }
            exercised += 1
        }
        #expect(exercised == 2, "exercised \(exercised) encoding negatives, expected exactly 2")
    }

    @Test("The known-answer suite is wired to real vectors")
    func suiteIsWiredCorrectly() throws {
        let corpus = try Self.corpus
        #expect(corpus["family"] as? String == "armel-authority-v1")
        #expect(
            corpus["digest_construction"] as? String == "SHA-256(domain || 0x00 || canonical_cbor(object))",
            "the corpus no longer states the digest construction this suite implements"
        )
        let positives = try #require(corpus["positive"] as? [[String: Any]])
        #expect(
            Set(positives.compactMap { $0["digest_domain"] as? String }).count == 4,
            "expected four distinct digest domains across the positive corpus"
        )
    }
}
