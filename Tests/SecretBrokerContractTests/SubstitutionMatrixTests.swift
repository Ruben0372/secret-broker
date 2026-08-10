import Foundation
import SecretBrokerContracts
import Testing

/// The acceptance bar: task authority must never satisfy owner-control
/// authority, and owner-control authority must never satisfy a task effect.
///
/// This is proven directly rather than inferred from the presence of a domain
/// field. Every published substitution case is driven through the validator for
/// the type it was presented AS, and must be refused.
///
/// And every refusal is paired with a positive control (DISC-031). A verifier
/// that refuses everything would pass a suite made only of must-fail cases
/// while providing no separation at all, because it also refuses the genuine
/// article. Separation means refusing the wrong thing AND accepting the right
/// one, so both halves are asserted.
@Suite("Substitution matrix, task authority versus owner control")
struct SubstitutionMatrixTests {
    static func vector(_ name: String) throws -> [String: Any] {
        try ContractVectorFixtures.json(
            at: ContractVectorFixtures.approvalRoot.appendingPathComponent("\(name).json")
        )
    }

    /// Maps the published validator name onto the object type it stands for.
    static let validatorTypes: [String: ApprovalObjectType] = [
        "task_manifest": .taskManifest,
        "task_decision": .taskDecision,
        "gateway_receipt": .gatewayReceipt,
        "enrollment_record": .enrollmentRecord,
        "owner_control_manifest": .ownerControlManifest,
        "owner_control_decision": .ownerControlDecision,
        "owner_control_continuity": .ownerControlContinuity,
    ]

    /// The genuine article for each type, from its own published vector. These
    /// are the positive controls.
    static let genuineObjects: [ApprovalObjectType: String] = [
        .taskManifest: "task_manifest_v1",
        .taskDecision: "task_decision_v1",
        .gatewayReceipt: "gateway_receipt_v1",
        .enrollmentRecord: "enrollment_record_v1",
        .ownerControlManifest: "owner_control_manifest_v1",
        .ownerControlDecision: "owner_control_decision_v1",
        .ownerControlContinuity: "owner_control_continuity_v1",
    ]

    static func genuineObject(for type: ApprovalObjectType) throws -> [String: Any] {
        let name = try #require(genuineObjects[type])
        let file = try vector(name)
        let object = file["object"] ?? file["owner_control_object"]
        return try #require(object as? [String: Any], "\(name) carries no object")
    }

    // MARK: The positive control half

    @Test("Every genuine object is ACCEPTED as its own type", arguments: ApprovalObjectType.allCases)
    func genuineObjectsAreAccepted(type: ApprovalObjectType) throws {
        let object = try Self.genuineObject(for: type)
        let rejection = ApprovalObjectValidator.validate(object, as: type)
        #expect(
            rejection == nil,
            "\(type.schema) refused its own genuine object with \(rejection?.rawValue ?? "-"). A verifier that refuses everything provides no separation."
        )
    }

    // MARK: The substitution half

    @Test("Published owner-control cross-domain cases are all refused")
    func ownerControlCrossDomainCasesRefused() throws {
        let cases = try #require(try Self.vector("owner_control_cross_domain_v1")["cases"] as? [[String: Any]])
        #expect(cases.count == 31, "expected exactly 31 published cases, found \(cases.count)")

        var driven = 0
        var skipped: [String] = []
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            guard let validatorName = testCase["expected_validator"] as? String,
                  let type = Self.validatorTypes[validatorName],
                  let object = testCase["object"] as? [String: Any]
            else {
                skipped.append(name)
                continue
            }
            let rejection = ApprovalObjectValidator.validate(object, as: type)
            #expect(rejection != nil, "\(name): ACCEPTED by \(validatorName); substitution is possible")
            driven += 1
        }
        // Exact, not a tolerance. A tolerance is what let two published cases
        // sit undriven while the suite still read as green, which is how the
        // duplicate-key bypass survived: the count absorbed the gap instead of
        // naming it.
        #expect(
            driven == cases.count,
            "drove \(driven) of \(cases.count) published cases; UNDRIVEN: \(skipped)"
        )
    }

    @Test("Published task-domain cross-domain rejections are all refused")
    func taskCrossDomainCasesRefused() throws {
        let cases = try #require(try Self.vector("cross_domain_rejection_v1")["cases"] as? [[String: Any]])
        #expect(cases.count == 14, "expected exactly 14 published cases, found \(cases.count)")

        var driven = 0
        var skipped: [String] = []
        for testCase in cases {
            let name = testCase["case"] as? String ?? "unnamed"
            guard let validatorName = testCase["expected_validator"] as? String,
                  let type = Self.validatorTypes[validatorName]
            else {
                skipped.append(name)
                continue
            }
            // Cases carrying raw_json are byte-level by construction: a
            // duplicate key cannot survive a parse, so they are driven through
            // the byte entry rather than skipped for lacking a parsed object.
            let rejection: ApprovalRejection?
            if let raw = testCase["raw_json"] as? String {
                rejection = ApprovalObjectValidator.validate(bytes: Array(raw.utf8), as: type)
            } else if let object = testCase["object"] as? [String: Any] {
                rejection = ApprovalObjectValidator.validate(object, as: type)
            } else {
                skipped.append(name)
                continue
            }
            #expect(rejection != nil, "\(name): ACCEPTED by \(validatorName); substitution is possible")
            driven += 1
        }
        #expect(
            driven == cases.count,
            "drove \(driven) of \(cases.count) published cases; UNDRIVEN: \(skipped)"
        )
    }

    /// The bar stated directly, independent of any published case list: take
    /// the genuine article from one family and present it as every type in the
    /// other. None may be accepted.
    @Test("No genuine object of either family satisfies any type of the other")
    func neitherFamilySatisfiesTheOther() throws {
        var checked = 0
        for sourceType in ApprovalObjectType.allCases {
            let genuine = try Self.genuineObject(for: sourceType)
            for targetType in ApprovalObjectType.allCases
            where targetType.family != sourceType.family {
                let rejection = ApprovalObjectValidator.validate(genuine, as: targetType)
                #expect(
                    rejection != nil,
                    "a genuine \(sourceType.schema) was ACCEPTED as \(targetType.schema), crossing the family boundary"
                )
                checked += 1
            }
        }
        // 4 task types times 3 owner-control types, both directions.
        #expect(checked == 24, "checked \(checked) cross-family pairings, expected 24")
    }

    @Test("Within a family, a genuine object still does not satisfy a sibling type")
    func siblingTypesAreNotInterchangeable() throws {
        var checked = 0
        for sourceType in ApprovalObjectType.allCases {
            let genuine = try Self.genuineObject(for: sourceType)
            for targetType in ApprovalObjectType.allCases
            where targetType != sourceType && targetType.family == sourceType.family {
                #expect(
                    ApprovalObjectValidator.validate(genuine, as: targetType) != nil,
                    "a genuine \(sourceType.schema) was ACCEPTED as its sibling \(targetType.schema)"
                )
                checked += 1
            }
        }
        #expect(checked == 18, "checked \(checked) sibling pairings, expected 18")
    }

    @Test("Recording is not deciding: the two owner-control roles are not interchangeable")
    func continuityAndDecisionRolesDoNotSwap() throws {
        var decision = try Self.genuineObject(for: .ownerControlDecision)
        decision["key_role"] = ApprovalObjectType.ownerControlContinuity.requiredKeyRole
        #expect(
            ApprovalObjectValidator.validate(decision, as: .ownerControlDecision) == .keyRoleMismatch,
            "a decision carrying the continuity recorder role was accepted"
        )

        var continuity = try Self.genuineObject(for: .ownerControlContinuity)
        continuity["key_role"] = ApprovalObjectType.ownerControlDecision.requiredKeyRole
        #expect(
            ApprovalObjectValidator.validate(continuity, as: .ownerControlContinuity) == .keyRoleMismatch,
            "a continuity record carrying the decision signer role was accepted"
        )
    }

    @Test("Widening is never implicit: an unenumerated control action is refused")
    func unenumeratedControlActionRefused() throws {
        var manifest = try Self.genuineObject(for: .ownerControlManifest)
        var action = try #require(manifest["control_action"] as? [String: Any])
        action["kind"] = "policy.change.but.more"
        manifest["control_action"] = action
        #expect(
            ApprovalObjectValidator.validate(manifest, as: .ownerControlManifest) == .unenumeratedControlAction,
            "an unenumerated control action kind was accepted"
        )
    }
}
