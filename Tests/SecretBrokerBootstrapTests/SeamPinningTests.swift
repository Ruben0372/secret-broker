import Foundation
import Testing

/// Pins the shape of the caller-facing surface.
///
/// The dependency allowlist and the token scan cannot catch an operation that
/// is added in the right module with ordinary Swift: a reveal operation on the
/// seam, a matching request case, and a daemon method returning the value would
/// pass both. These tests pin the exact seam methods, the exact request cases,
/// and the exact public daemon API, so widening the surface fails here first.
@Suite("Seam and API pinning")
struct SeamPinningTests {
    // MARK: Source parsing

    static func sourceText(_ components: String...) throws -> String {
        var url = BootstrapTestSupport.packageRoot
        for component in components {
            url = url.appendingPathComponent(component)
        }
        return try String(contentsOf: url, encoding: .utf8)
    }

    /// Returns the declaration text from `marker` through its matching brace.
    static func block(in text: String, startingWith marker: String) -> String? {
        guard let start = text.range(of: marker) else { return nil }
        var depth = 0
        var opened = false
        var result = ""
        for character in text[start.lowerBound...] {
            result.append(character)
            if character == "{" {
                depth += 1
                opened = true
            } else if character == "}" {
                depth -= 1
                if opened, depth == 0 { break }
            }
        }
        return opened ? result : nil
    }

    /// Declarations beginning with `prefix`, joined across continuation lines.
    ///
    /// A declaration split over several lines used to be invisible to the
    /// return-type parser: the first line carries the name but no `->`, so the
    /// pin collected the name and silently dropped the type. That is the
    /// failure mode where a check fires but reports the wrong thing, so the
    /// scan now accumulates until the signature closes.
    static func lines(in block: String, withPrefix prefix: String) -> [String] {
        var declarations: [String] = []
        var pending: String?

        for rawLine in block.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if var accumulating = pending {
                accumulating += " " + line
                if line.contains("{") || line.hasSuffix(")") && accumulating.contains("->") {
                    declarations.append(accumulating)
                    pending = nil
                } else {
                    pending = accumulating
                }
                continue
            }
            guard line.hasPrefix(prefix) else { continue }
            // Complete on one line when it opens a body or is a protocol
            // requirement with no body.
            if line.contains("{") || (line.contains(")") && !line.hasSuffix(",")) {
                declarations.append(line)
            } else {
                pending = line
            }
        }
        if let leftover = pending {
            declarations.append(leftover)
        }
        return declarations
    }

    static func name(ofDeclaration line: String, keyword: String) -> String {
        guard let range = line.range(of: keyword) else { return "" }
        let rest = line[range.upperBound...]
        let terminators = CharacterSet(charactersIn: "( :{<")
        guard let end = rest.rangeOfCharacter(from: terminators) else {
            return rest.trimmingCharacters(in: .whitespaces)
        }
        return String(rest[..<end.lowerBound]).trimmingCharacters(in: .whitespaces)
    }

    static func returnType(ofDeclaration line: String) -> String? {
        guard let arrow = line.range(of: "->") else { return nil }
        return line[arrow.upperBound...]
            .replacingOccurrences(of: "{", with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    // MARK: Pins

    @Test("Custody seam exposes exactly one availability method")
    func custodySeamMethodSet() throws {
        let text = try Self.sourceText("Sources", "SecretBrokerContracts", "BrokeredOperations.swift")
        let seam = try #require(
            Self.block(in: text, startingWith: "public protocol SecretCustodian"),
            "SecretCustodian protocol not found"
        )
        let declarations = Self.lines(in: seam, withPrefix: "func ")
        let names = declarations.map { Self.name(ofDeclaration: $0, keyword: "func ") }
        #expect(
            names == ["availability"],
            "custody seam method set changed: \(names). A new seam method needs security review."
        )
        for declaration in declarations {
            let returned = Self.returnType(ofDeclaration: declaration)
            #expect(
                returned == "SecretAvailability",
                "seam method returns \(returned ?? "nothing"); only SecretAvailability is allowed"
            )
        }
    }

    @Test("Request enum exposes exactly the availability case")
    func requestCaseList() throws {
        let text = try Self.sourceText("Sources", "SecretBrokerContracts", "BrokeredOperations.swift")
        let request = try #require(
            Self.block(in: text, startingWith: "public enum BrokeredRequest"),
            "BrokeredRequest enum not found"
        )
        let cases = Self.lines(in: request, withPrefix: "case ")
            .map { Self.name(ofDeclaration: $0, keyword: "case ") }
        #expect(
            cases == ["availability"],
            "request case list changed: \(cases). A new operation needs security review."
        )
    }

    @Test("Public daemon API is exactly the bootstrap and caller-bound dispatch")
    func publicDaemonAPISurface() throws {
        var names: [String] = []
        var returnTypes: [String] = []
        for file in BootstrapTestSupport.swiftFiles(
            under: BootstrapTestSupport.packageRoot
                .appendingPathComponent("Sources")
                .appendingPathComponent("SecretBrokerDaemon")
        ) {
            let text = try String(contentsOf: file, encoding: .utf8)
            for declaration in Self.lines(in: text, withPrefix: "public func ") {
                names.append(Self.name(ofDeclaration: declaration, keyword: "func "))
                if let returned = Self.returnType(ofDeclaration: declaration) {
                    returnTypes.append(returned)
                }
            }
        }
        // ARM-24: the unverified handle(_:) is gone. Every public entry is
        // caller bound, so there is no path to an operation without an
        // identity to verify.
        #expect(
            names.sorted() == ["dispatch", "start"],
            "public daemon API changed: \(names.sorted()). Widening it needs security review."
        )
        #expect(Set(returnTypes) == ["BootstrapReport", "DaemonOutcome"])
    }

    @Test("No public daemon method returns secret-capable material")
    func daemonReturnsNoSecretCapableMaterial() throws {
        let forbiddenReturns = ["String", "Data", "[UInt8]", "SymmetricKey"]
        for file in BootstrapTestSupport.swiftFiles(
            under: BootstrapTestSupport.packageRoot
                .appendingPathComponent("Sources")
                .appendingPathComponent("SecretBrokerDaemon")
        ) {
            let text = try String(contentsOf: file, encoding: .utf8)
            for declaration in Self.lines(in: text, withPrefix: "public func ") {
                guard let returned = Self.returnType(ofDeclaration: declaration) else { continue }
                #expect(
                    !forbiddenReturns.contains(returned),
                    "\(file.lastPathComponent) returns \(returned) from a public method: \(declaration)"
                )
            }
        }
    }

    @Test("Custody seam returns nothing secret-capable")
    func seamReturnsNoSecretCapableMaterial() throws {
        let text = try Self.sourceText("Sources", "SecretBrokerContracts", "BrokeredOperations.swift")
        let seam = try #require(Self.block(in: text, startingWith: "public protocol SecretCustodian"))
        let forbiddenReturns = ["String", "Data", "[UInt8]"]
        for declaration in Self.lines(in: seam, withPrefix: "func ") {
            guard let returned = Self.returnType(ofDeclaration: declaration) else { continue }
            #expect(
                !forbiddenReturns.contains(returned),
                "custody seam returns \(returned): \(declaration)"
            )
        }
    }
}
