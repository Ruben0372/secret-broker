import Foundation
@testable import SecretBrokerContracts
import Testing

/// Claim validation against the published semantic negatives: audience,
/// freshness, digest binding, generation, and list ordering.
///
/// Each negative is decoded from its published bytes and refused with the
/// published reason code. Every one is paired with the positive control that
/// the same validator ACCEPTS the genuine capability, so a validator that
/// refused everything would fail here rather than look rigorous.
@Suite("Authority claim validation")
struct AuthorityClaimTests {
    static var corpus: [String: Any] {
        get throws {
            try ContractVectorFixtures.json(
                at: ContractVectorFixtures.authorityRoot
                    .appendingPathComponent("authority-v1-vectors.json")
            )
        }
    }

    static func context(from vector: [String: Any]) throws -> AuthorityValidationContext {
        let ctx = try #require(vector["context"] as? [String: Any])
        let audience = try #require(ctx["expected_audience"] as? String)
        let now = try #require(ctx["now_ms"] as? Int64 ?? (ctx["now_ms"] as? NSNumber)?.int64Value)
        var activeGeneration: UInt64?
        if let lease = ctx["lease_fields"] as? [String: Any],
           let generation = (lease["lease_generation"] as? NSNumber)?.uint64Value {
            activeGeneration = generation
        }
        return AuthorityValidationContext(
            expectedAudience: audience,
            nowMilliseconds: now,
            activeLeaseGeneration: activeGeneration
        )
    }

    @Test("Every semantic negative is refused with its published reason")
    func semanticNegativesRefused() throws {
        let negatives = try #require(try Self.corpus["negative"] as? [[String: Any]])
        let encodingCategories: Set<String> = ["alternate_encoding", "duplicate_field"]

        var driven = 0
        var mismatched: [String] = []
        for vector in negatives {
            let category = vector["category"] as? String ?? ""
            let name = vector["name"] as? String ?? "unnamed"
            // The two pure-encoding negatives are decided by the decoder suite.
            if encodingCategories.contains(category), name != "context_selectors_duplicate" { continue }

            let expected = try #require(vector["expected_reason"] as? String)
            let hex = try #require(vector["encoded_hex"] as? String)
            let bytes = try #require(CanonicalCBOR.bytes(fromHex: hex))
            let context = try Self.context(from: vector)

            // Decoder-level refusals count too: a duplicate map key never
            // reaches claim validation, and refusing earlier is not a weaker
            // refusal.
            let rejection: String?
            do {
                let value = try CanonicalCBOR.decode(bytes)
                rejection = AuthorityClaimValidator.validateCapability(value, in: context)?.rawValue
            } catch let error as CanonicalCBORError {
                rejection = error.reasonCode
            }

            if rejection != expected {
                mismatched.append("\(name): got \(rejection ?? "ACCEPTED"), expected \(expected)")
            }
            driven += 1
        }
        #expect(mismatched.isEmpty, "\(mismatched.count) semantic negatives disagreed: \(mismatched)")
        #expect(driven == 9, "drove \(driven) semantic negatives, expected 9")
    }

    @Test("The genuine capabilities are ACCEPTED, so refusal is not blanket")
    func positiveControlsAccepted() throws {
        let positives = try #require(try Self.corpus["positive"] as? [[String: Any]])
        var accepted = 0
        for vector in positives {
            let name = vector["name"] as? String ?? "unnamed"
            guard name.hasPrefix("execution_capability") else { continue }
            let hex = try #require(vector["canonical_hex"] as? String)
            let bytes = try #require(CanonicalCBOR.bytes(fromHex: hex))
            let value = try CanonicalCBOR.decode(bytes)

            guard case .map(let fields) = value,
                  case .text(let audience)? = fields["audience"],
                  case .text(let issuedAt)? = fields["issued_at"],
                  let issued = AuthorityClaimValidator.milliseconds(fromTimestamp: issuedAt)
            else {
                Issue.record("\(name): could not read audience and issue time")
                continue
            }

            // Evaluated at its own issue instant, which is inside its window.
            let context = AuthorityValidationContext(
                expectedAudience: audience,
                nowMilliseconds: issued,
                activeLeaseGeneration: 1
            )
            let rejection = AuthorityClaimValidator.validateCapability(value, in: context)
            #expect(rejection == nil, "\(name): genuine capability refused with \(rejection?.rawValue ?? "-")")
            accepted += 1
        }
        #expect(accepted == 2, "expected 2 capability positives, drove \(accepted)")
    }

    @Test("Timestamp arithmetic matches the published instants")
    func timestampParsing() throws {
        // Known answers rather than self-consistency: these are epoch
        // milliseconds for the instants the corpus uses.
        #expect(AuthorityClaimValidator.milliseconds(fromTimestamp: "1970-01-01T00:00:00.000Z") == 0)
        #expect(AuthorityClaimValidator.milliseconds(fromTimestamp: "2026-08-09T12:00:00.000Z") == 1_786_276_800_000)
        #expect(AuthorityClaimValidator.milliseconds(fromTimestamp: "2026-08-09T12:01:00.000Z") == 1_786_276_860_000)
        // Malformed shapes are refused rather than coerced.
        #expect(AuthorityClaimValidator.milliseconds(fromTimestamp: "2026-08-09T12:00:00Z") == nil)
        #expect(AuthorityClaimValidator.milliseconds(fromTimestamp: "2026-13-09T12:00:00.000Z") == nil)
    }

    @Test("Freshness uses the supplied instant and never a clock")
    func freshnessUsesSuppliedInstant() throws {
        let positives = try #require(try Self.corpus["positive"] as? [[String: Any]])
        let capability = try #require(
            positives.first { ($0["name"] as? String)?.hasPrefix("execution_capability") == true }
        )
        let hex = try #require(capability["canonical_hex"] as? String)
        let bytes = try #require(CanonicalCBOR.bytes(fromHex: hex))
        let value = try CanonicalCBOR.decode(bytes)
        guard case .map(let fields) = value,
              case .text(let audience)? = fields["audience"],
              case .text(let expiresAt)? = fields["expires_at"],
              let expiry = AuthorityClaimValidator.milliseconds(fromTimestamp: expiresAt)
        else {
            Issue.record("could not read the capability window")
            return
        }

        // At the expiry instant it is still fresh; one millisecond past, it is
        // not. The boundary is inclusive, which I had assumed the other way
        // until the published vectors evaluated a capability at exactly its
        // expiry and expected a structural refusal rather than expiry.
        let fresh = AuthorityValidationContext(
            expectedAudience: audience, nowMilliseconds: expiry, activeLeaseGeneration: 1
        )
        let stale = AuthorityValidationContext(
            expectedAudience: audience, nowMilliseconds: expiry + 1, activeLeaseGeneration: 1
        )
        #expect(AuthorityClaimValidator.validateCapability(value, in: fresh) == nil)
        #expect(AuthorityClaimValidator.validateCapability(value, in: stale) == .expired)
    }
}
