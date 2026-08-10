import Foundation
import SecretBrokerContracts
import Testing

/// Canonical JSON reproduction against the ARM-47 oracle.
///
/// These vectors closed the coverage gap this repository reported: before them,
/// the only escape appearing anywhere in the corpus was the escaped double
/// quote and no canonical string carried a non-ASCII character, so an encoder
/// could differ on every other branch and no test would notice.
@Suite("Canonical JSON, ARM-47 oracle")
struct CanonicalJSONTests {
    static func vector(_ name: String) throws -> [String: Any] {
        try ContractVectorFixtures.json(
            at: ContractVectorFixtures.approvalRoot.appendingPathComponent("\(name).json")
        )
    }

    static func cases(in name: String) throws -> [[String: Any]] {
        try #require(try vector(name)["cases"] as? [[String: Any]])
    }

    /// Builds the object the vector describes: a single key "k" whose value is
    /// the string formed from the given UTF-8 bytes.
    static func subject(fromInputHex hex: String) -> [String: Any]? {
        guard let bytes = CanonicalCBOR.bytes(fromHex: hex),
              let text = String(bytes: bytes, encoding: .utf8)
        else { return nil }
        return ["k": text]
    }

    @Test("Every escaping case reproduces its pinned canonical bytes")
    func escapingCasesReproduce() throws {
        let cases = try Self.cases(in: "canonical_json_escaping_v1")
        #expect(cases.count == 38, "expected 38 escaping cases, found \(cases.count)")

        var reproduced = 0
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            let inputHex = try #require(testCase["input_utf8_hex"] as? String)
            let expectedHex = try #require(testCase["expected_canonical_hex"] as? String)
            let subject = try #require(Self.subject(fromInputHex: inputHex), "\(name): bad input hex")

            let encoded = try CanonicalJSON.encode(subject)
            #expect(
                CanonicalCBOR.hex(fromBytes: encoded) == expectedHex,
                "\(name): encoded \(CanonicalCBOR.hex(fromBytes: encoded)), pinned \(expectedHex)"
            )
            reproduced += 1
        }
        #expect(reproduced == 38, "reproduced \(reproduced) of 38")
    }

    /// The upstream coverage contract, asserted here rather than assumed: every
    /// C0 point exactly once, plus both boundaries. A corpus that quietly lost
    /// a code point would narrow the oracle without failing anything.
    @Test("The escaping corpus covers every C0 point and both boundaries")
    func escapingCoverageIsComplete() throws {
        let cases = try Self.cases(in: "canonical_json_escaping_v1")
        let inputs = cases.compactMap { $0["input_utf8_hex"] as? String }
        for point in 0x00...0x1f {
            let hex = String(format: "%02x", point)
            #expect(
                inputs.filter { $0 == hex }.count == 1,
                "C0 point \(hex) appears \(inputs.filter { $0 == hex }.count) times, expected exactly once"
            )
        }
        #expect(inputs.contains("20"), "the space boundary is missing")
        #expect(inputs.contains("7f"), "the DEL boundary is missing")
        #expect(inputs.contains("22") && inputs.contains("5c") && inputs.contains("2f"))
    }

    @Test("Every unicode case reproduces, with non-ASCII emitted raw")
    func unicodeCasesReproduce() throws {
        let cases = try Self.cases(in: "canonical_json_unicode_v1")
        #expect(cases.count == 7, "expected 7 unicode cases, found \(cases.count)")

        var reproduced = 0
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            let inputHex = try #require(testCase["input_utf8_hex"] as? String)
            let expectedHex = try #require(testCase["expected_canonical_hex"] as? String)
            let subject = try #require(Self.subject(fromInputHex: inputHex), "\(name): bad input hex")

            let encoded = try CanonicalJSON.encode(subject)
            #expect(
                CanonicalCBOR.hex(fromBytes: encoded) == expectedHex,
                "\(name): encoded \(CanonicalCBOR.hex(fromBytes: encoded)), pinned \(expectedHex)"
            )
            // The rule stated positively: no backslash-u escape survives for a
            // non-ASCII scalar.
            let text = String(decoding: encoded, as: UTF8.self)
            if inputHex.count > 2 {
                #expect(!text.contains("\\u"), "\(name): a non-ASCII scalar was escaped rather than emitted raw")
            }
            reproduced += 1
        }
        #expect(reproduced == 7, "reproduced \(reproduced) of 7")
    }

    @Test("Every structure case reproduces its pinned canonical bytes")
    func structureCasesReproduce() throws {
        let cases = try Self.cases(in: "canonical_json_structure_v1")
        #expect(cases.count == 7, "expected 7 structure cases, found \(cases.count)")

        var reproduced = 0
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            let expectedText = try #require(testCase["expected_canonical"] as? String)
            let expectedHex = try #require(testCase["expected_canonical_hex"] as? String)

            // Round-trip the pinned bytes: parse the canonical form and require
            // re-encoding to return exactly the same bytes. That is
            // canonical-on-input stated directly.
            let pinned = try #require(CanonicalCBOR.bytes(fromHex: expectedHex))
            #expect(Array(expectedText.utf8) == pinned, "\(name): the vector's text and hex disagree")
            #expect(
                CanonicalJSON.isCanonical(pinned),
                "\(name): the pinned canonical form did not survive a parse and re-encode"
            )
            reproduced += 1
        }
        #expect(reproduced == 7, "reproduced \(reproduced) of 7")
    }

    @Test("Canonical-on-input refuses non-canonical spellings")
    func nonCanonicalSpellingsRefused() throws {
        // Each of these parses to the same value as a canonical form but is
        // spelled differently, so accepting it would let two byte strings both
        // verify while the digest covers only one.
        let notCanonical = [
            #"{"b":"1","a":"2"}"#,      // keys out of byte order
            #"{"a": "1"}"#,             // insignificant whitespace
            #"{ }"#,                    // whitespace inside an empty object
            ##"{"a":"\u0041"}"##,      // an ASCII letter escaped unnecessarily
            #"{"a":"\/"}"#,             // solidus escaped, which this form does not do
        ]
        for spelling in notCanonical {
            #expect(
                !CanonicalJSON.isCanonical(Array(spelling.utf8)),
                "accepted a non-canonical spelling: \(spelling)"
            )
        }

        // Positive control: the canonical spellings of the same values ARE
        // accepted, so this is not a checker that refuses everything.
        let canonical = [#"{"a":"1","b":"2"}"#, #"{}"#, #"{"a":"A"}"#, #"{"a":"/"}"#]
        for spelling in canonical {
            #expect(
                CanonicalJSON.isCanonical(Array(spelling.utf8)),
                "refused a canonical spelling: \(spelling)"
            )
        }
    }

    @Test("Every published approval object is already canonical")
    func publishedObjectsAreCanonical() throws {
        // The corpus should be self-consistent: each vector's canonical_json is
        // canonical by this encoder's own rule.
        var checked = 0
        for name in VendoredVectorIntegrityTests.expectedApprovalVectors {
            let file = try Self.vector(name)
            guard let canonical = file["canonical_json"] as? String else { continue }
            #expect(
                CanonicalJSON.isCanonical(Array(canonical.utf8)),
                "\(name): its own pinned canonical_json is not canonical by this encoder"
            )
            checked += 1
        }
        #expect(checked >= 6, "checked only \(checked) pinned canonical payloads")
    }
}
