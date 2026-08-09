import Foundation

/// Typed handle to a brokered secret. Carries naming only, never material.
public struct SecretReference: Sendable, Hashable, Codable {
    public let namespace: String
    public let name: String

    public init(namespace: String, name: String) throws {
        self.namespace = try Self.validated(namespace, field: "namespace")
        self.name = try Self.validated(name, field: "name")
    }

    /// References are caller input and cross an IPC boundary later, so both
    /// parts are validated here rather than trusted downstream.
    private static func validated(_ value: String, field: String) throws -> String {
        guard !value.isEmpty else {
            throw BrokerContractError.invalidReference("\(field) is empty")
        }
        let banned = CharacterSet.whitespacesAndNewlines
            .union(.controlCharacters)
            .union(CharacterSet(charactersIn: "/\\"))
        guard value.unicodeScalars.allSatisfy({ !banned.contains($0) }) else {
            throw BrokerContractError.invalidReference("\(field) contains banned characters")
        }
        return value
    }
}

public enum BrokerContractError: Error, Sendable, Equatable {
    case invalidReference(String)
}
