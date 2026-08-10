import Foundation

/// Refusal reasons for claim validation, carrying the published reason codes.
public enum AuthorityClaimRejection: String, Sendable, Hashable, CaseIterable {
    case unknownAudience = "unknown_audience"
    case audienceMismatch = "audience_mismatch"
    case expired
    case digestMismatch = "digest_mismatch"
    case generationDrift = "generation_drift"
    case unsupportedVersion = "unsupported_version"
    case unsortedList = "unsorted_list"
    case duplicateField = "duplicate_field"
    case malformed
}

/// Everything the validator needs that it must not read for itself.
///
/// `now` is supplied by the caller. No validator here reads a clock: a
/// validator that decides using ambient time is a step toward deciding
/// authority, and it also cannot be tested deterministically.
public struct AuthorityValidationContext: Sendable, Hashable {
    public let expectedAudience: String
    public let nowMilliseconds: Int64
    public let activeLeaseGeneration: UInt64?

    public init(expectedAudience: String, nowMilliseconds: Int64, activeLeaseGeneration: UInt64? = nil) {
        self.expectedAudience = expectedAudience
        self.nowMilliseconds = nowMilliseconds
        self.activeLeaseGeneration = activeLeaseGeneration
    }
}

/// Claim validation for armel-authority-v1 capabilities.
///
/// Form validation and binding only. Nothing here signs, verifies a signature,
/// or authorises: a validated capability is a well-formed, currently-fresh,
/// correctly-bound claim, never a permission.
public enum AuthorityClaimValidator {
    /// The audiences this family defines. An audience outside the set is
    /// refused as unknown rather than merely mismatched, because the two are
    /// different failures: one is a typo or a forgery, the other is evidence
    /// pointed at the wrong service.
    public static let knownAudiences: Set<String> = [
        "effect-gateway", "cadence-context", "sandbox-admission",
    ]

    public static let audienceClaimsDomain = "armel/capability/audience-claims/v1"
    public static let selectorSetDomain = "armel/capability/context-selector-set/v1"

    public static func validateCapability(
        _ value: CanonicalValue,
        in context: AuthorityValidationContext
    ) -> AuthorityClaimRejection? {
        guard case .map(let fields) = value else { return .malformed }

        // A version carried as a boolean is a type confusion, not a version.
        // The family spells this field `version`; a boolean true there is the
        // published type-confusion case.
        for key in ["version", "schema_version"] {
            guard let carried = fields[key] else { continue }
            guard case .unsigned(let number) = carried, number == 1 else {
                return .unsupportedVersion
            }
        }

        guard case .text(let audience)? = fields["audience"] else { return .malformed }
        guard knownAudiences.contains(audience) else { return .unknownAudience }
        guard audience == context.expectedAudience else { return .audienceMismatch }

        // Freshness against the supplied instant.
        if case .text(let expires)? = fields["expires_at"] {
            guard let expiresAt = milliseconds(fromTimestamp: expires) else { return .malformed }
            // The window is inclusive of its final instant: expired means past
            // expires_at, not at it. Derived from the published vectors, which
            // evaluate the cadence-context capability at exactly its expiry and
            // still expect a structural refusal rather than expiry. An
            // exclusive boundary here would refuse a capability that the issuer
            // considers live, one millisecond early, at an authority boundary.
            guard context.nowMilliseconds <= expiresAt else { return .expired }
        }

        // Generation binding: a capability may not claim a generation above the
        // lease that is actually active, or a superseded lease would keep
        // authorising work after rotation.
        if let active = context.activeLeaseGeneration,
           case .unsigned(let claimed)? = fields["lease_generation"] {
            guard claimed <= active else { return .generationDrift }
        }

        guard case .map(let claims)? = fields["audience_claims"] else { return .malformed }

        // The claims digest must cover the claims actually presented.
        if case .text(let boundDigest)? = fields["audience_claims_digest"] {
            guard let recomputed = try? AuthorityDigest.digestHex(
                domain: audienceClaimsDomain,
                object: .map(claims)
            ) else { return .malformed }
            guard recomputed == boundDigest else { return .digestMismatch }
        }

        return validateSelectors(in: claims)
    }

    /// Selector sets are ordered and unique, and the set digest must cover the
    /// selectors presented. Order matters because the digest is over the
    /// encoded sequence: an unsorted list is a different preimage.
    private static func validateSelectors(in claims: [String: CanonicalValue]) -> AuthorityClaimRejection? {
        guard case .array(let selectors)? = claims["selectors"] else { return nil }

        var previousID: String?
        var seen = Set<String>()
        for selector in selectors {
            guard case .map(let entry) = selector, case .text(let id)? = entry["id"] else {
                return .malformed
            }
            if seen.contains(id) { return .duplicateField }
            if let previous = previousID, id < previous { return .unsortedList }
            seen.insert(id)
            previousID = id
        }

        if case .text(let boundDigest)? = claims["selector_set_digest"] {
            guard let recomputed = try? AuthorityDigest.digestHex(
                domain: selectorSetDomain,
                object: .array(selectors)
            ) else { return .malformed }
            guard recomputed == boundDigest else { return .digestMismatch }
        }
        return nil
    }

    /// Parses the family's fixed-width UTC timestamp without a date library.
    ///
    /// The grammar is fixed width, zero padded and always UTC, so this is
    /// arithmetic rather than locale-sensitive parsing. A library date parser
    /// would introduce exactly the cross-implementation divergence the fixed
    /// grammar exists to prevent.
    static func milliseconds(fromTimestamp text: String) -> Int64? {
        let scalars = Array(text.utf8)
        guard scalars.count == 24, text.hasSuffix("Z") else { return nil }

        func number(_ range: Range<Int>) -> Int64? {
            var value: Int64 = 0
            for index in range {
                let digit = Int64(scalars[index]) - 48
                guard (0...9).contains(digit) else { return nil }
                value = value * 10 + digit
            }
            return value
        }

        guard let year = number(0..<4), let month = number(5..<7), let day = number(8..<10),
              let hour = number(11..<13), let minute = number(14..<16), let second = number(17..<19),
              let milli = number(20..<23)
        else { return nil }
        guard (1...12).contains(month), (1...31).contains(day),
              hour < 24, minute < 60, second < 61
        else { return nil }

        // Days from the civil epoch, Howard Hinnant's algorithm.
        let shiftedYear = year - (month <= 2 ? 1 : 0)
        let era = (shiftedYear >= 0 ? shiftedYear : shiftedYear - 399) / 400
        let yearOfEra = shiftedYear - era * 400
        let dayOfYear = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear
        let days = era * 146_097 + dayOfEra - 719_468

        return ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + milli
    }
}
