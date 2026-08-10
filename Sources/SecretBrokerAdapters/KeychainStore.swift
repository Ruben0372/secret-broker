import Foundation

/// Opaque reference to a stored secret.
///
/// This type structurally cannot carry secret bytes: it has no field that
/// could hold one, and it is the only thing custody ever hands back. A handle
/// names an item, scopes it to a namespace and an access group, and records
/// which generation it refers to. It is not a bearer token, because resolving
/// it requires the store that minted it.
public struct SecretHandle: Sendable, Hashable, CustomStringConvertible {
    public let namespace: String
    public let name: String
    public let generation: UInt64
    /// Identifies the store instance lineage that minted this handle, so a
    /// handle restored from elsewhere does not resolve here.
    public let originID: UUID

    public var description: String {
        // Deliberately names the item and never its contents.
        "SecretHandle(\(namespace)/\(name)#\(generation))"
    }
}

/// Why custody refused. Typed, so a caller branches on a reason rather than
/// parsing a string, and so a refusal can be logged without improvising text.
public struct CustodyRefusal: Error, Sendable, Hashable, CustomStringConvertible {
    public enum Reason: String, Sendable, Hashable, CaseIterable {
        case accessGroupMismatch
        case namespaceMismatch
        case foreignOrigin
        case supersededGeneration
        case notFound
        case invalidName
        case productionActivationDisabled
    }

    public let reason: Reason
    /// Names the item, never its value. Every construction site below goes
    /// through here, so there is one place that could ever leak and it does not.
    public let message: String

    public var description: String { "CustodyRefusal(\(reason.rawValue): \(message))" }

    init(_ reason: Reason, item: String? = nil, detail: String? = nil) {
        self.reason = reason
        var text = reason.rawValue
        if let item { text += " for \(item)" }
        if let detail { text += ", \(detail)" }
        self.message = text
    }
}

/// Collects custody log lines so a test can scan them.
///
/// Custody never writes to a global logger: it appends here, so what was
/// emitted is exactly what a test can inspect. A logger that wrote somewhere
/// unobservable would make the leak proof unfalsifiable.
public struct CustodyLogRecorder: Sendable {
    public private(set) var lines: [String] = []

    public init() {}

    public mutating func record(_ line: String) {
        lines.append(line)
    }
}

/// The storage seam. Custody logic is written against this, so the whole
/// boundary is testable without entitlements and without touching a real
/// Keychain.
public protocol KeychainBacking: AnyObject, Sendable {
    func write(key: String, secret: [UInt8], nonExportable: Bool)
    func contains(key: String) -> Bool
    func remove(key: String)
    func removeAll(withPrefix prefix: String)
    func isNonExportable(key: String) -> Bool
    /// Generation lives with the item, not in a store instance. Holding it in
    /// memory would mean a restarted store could not resolve its own live
    /// handles, and two stores over one backing would disagree about which
    /// generation is current, which is a supersession check that depends on
    /// process lifetime rather than on stored state.
    func currentGeneration(key: String) -> UInt64?
    func setGeneration(key: String, to generation: UInt64)
}

/// In-memory backing for the disposable namespace.
///
/// Secret bytes live here and nowhere else, and the caller-visible surface
/// below deliberately exposes counts and key names only, so a test can prove
/// absence of residue without the fixture itself becoming the leak.
public final class InMemoryKeychainBacking: KeychainBacking, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: [UInt8]] = [:]
    private var nonExportable: Set<String> = []
    private var generations: [String: UInt64] = [:]

    public init() {}

    public func write(key: String, secret: [UInt8], nonExportable flag: Bool) {
        lock.lock(); defer { lock.unlock() }
        items[key] = secret
        if flag { nonExportable.insert(key) }
    }

    public func contains(key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return items[key] != nil
    }

    public func remove(key: String) {
        lock.lock(); defer { lock.unlock() }
        items.removeValue(forKey: key)
        nonExportable.remove(key)
        generations.removeValue(forKey: key)
    }

    public func removeAll(withPrefix prefix: String) {
        lock.lock(); defer { lock.unlock() }
        for key in items.keys where key.hasPrefix(prefix) {
            items.removeValue(forKey: key)
            nonExportable.remove(key)
            generations.removeValue(forKey: key)
        }
    }

    public func isNonExportable(key: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return nonExportable.contains(key)
    }

    public func currentGeneration(key: String) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        return generations[key]
    }

    public func setGeneration(key: String, to generation: UInt64) {
        lock.lock(); defer { lock.unlock() }
        generations[key] = generation
    }

    // MARK: Inspection for tests, deliberately value-free

    public var rawItemCount: Int {
        lock.lock(); defer { lock.unlock() }
        return items.count
    }

    /// Key names only. If this returned values it would be the leak it is
    /// meant to detect.
    public var callerVisibleDescription: String {
        lock.lock(); defer { lock.unlock() }
        return "InMemoryKeychainBacking(keys: \(items.keys.sorted()))"
    }

    /// Everything still recoverable from the backing, values included, so a
    /// residue check can prove a deleted value is genuinely gone rather than
    /// merely unreferenced.
    public var residueDescription: String {
        lock.lock(); defer { lock.unlock() }
        return items.values.map { String(decoding: $0, as: UTF8.self) }.joined(separator: "|")
    }
}

/// Isolated custody for secrets.
///
/// The rule this whole type exists to enforce: Armel-facing code receives
/// opaque handles and never secret bytes. There is deliberately no read, no
/// value accessor, and no export. `resolve` proves a handle is live and returns
/// nothing, which is the only question a caller is entitled to ask here.
///
/// Production access-group activation is held OFF behind release signing,
/// exactly like the caller verifier: an approximate custody boundary is worse
/// than a closed door, because it looks like a boundary.
public final class KeychainStore: @unchecked Sendable {
    /// Never a real access group. Naming it disposable makes an accidental
    /// production use visible in the value itself.
    public static let disposableTestAccessGroup = "arm26.disposable.test.access-group"

    /// Flipped only when a release signing identity and a reviewed entitlement
    /// exist. Until then every production path refuses.
    public static let isProductionAccessGroupEnabled = false

    public static let productionActivationGate = """
    Production access-group activation stays disabled until a release signing \
    identity and a reviewed Keychain entitlement exist. A real access group \
    binds items to a signed application identity, and claiming that binding \
    without the identity would assert a boundary that is not there. While it is \
    disabled every production entry refuses, and the disposable namespace is \
    the only path that works.
    """

    private let namespace: String
    private let backing: KeychainBacking
    private let accessGroup: String
    private let originID: UUID
    private let lock = NSLock()

    public init(namespace: String, backing: KeychainBacking, accessGroup: String) {
        self.namespace = namespace
        self.backing = backing
        self.accessGroup = accessGroup
        self.originID = KeychainStore.originID(forNamespace: namespace)
    }

    /// Lineage is derived from the namespace, so a restarted store over the
    /// same namespace resolves its own handles while a different namespace,
    /// or a restored foreign backup, does not.
    private static func originID(forNamespace namespace: String) -> UUID {
        var bytes = Array(namespace.utf8)
        while bytes.count < 16 { bytes.append(0) }
        var uuidBytes = uuid_t(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        withUnsafeMutableBytes(of: &uuidBytes) { raw in
            for index in 0..<16 { raw[index] = bytes[index] }
        }
        return UUID(uuid: uuidBytes)
    }

    /// The production entry point, which refuses while activation is disabled.
    public static func productionStore(namespace: String) throws -> KeychainStore {
        guard isProductionAccessGroupEnabled else {
            throw CustodyRefusal(
                .productionActivationDisabled,
                item: namespace,
                detail: "production access-group activation is disabled pending release signing"
            )
        }
        // Unreachable while the flag is false, and deliberately not written as
        // a real Keychain path: activating it is a reviewed change, not a
        // matter of flipping a Boolean over code that already exists.
        throw CustodyRefusal(.productionActivationDisabled, item: namespace)
    }

    private func key(for name: String) -> String {
        "\(namespace)::\(accessGroup)::\(name)"
    }

    private var namespacePrefix: String { "\(namespace)::" }

    /// Stores a secret and returns a handle. The bytes go to the backing and
    /// are not retained, logged, or returned.
    @discardableResult
    public func store(
        secret: [UInt8],
        named name: String,
        log: inout CustodyLogRecorder
    ) throws -> SecretHandle {
        guard !name.isEmpty, !name.contains("::") else {
            // Names the parameter, never the secret.
            throw CustodyRefusal(.invalidName, item: "<empty or malformed name>")
        }

        let itemKey = key(for: name)
        let generation = (backing.currentGeneration(key: itemKey) ?? 0) + 1
        backing.setGeneration(key: itemKey, to: generation)

        // Overwrite replaces in place, so no superseded copy survives.
        backing.write(key: key(for: name), secret: secret, nonExportable: true)

        // Logs the item and the generation. Never the value, and never a
        // length either, since a length is a hint about the value.
        log.record("custody: stored \(namespace)/\(name) generation \(generation)")

        return SecretHandle(
            namespace: namespace,
            name: name,
            generation: generation,
            originID: originID
        )
    }

    /// Proves a handle is live. Returns nothing, because there is nothing a
    /// caller here is entitled to receive.
    public func resolve(_ handle: SecretHandle) throws {
        guard handle.namespace == namespace else {
            throw CustodyRefusal(.namespaceMismatch, item: handle.name)
        }
        guard handle.originID == originID else {
            throw CustodyRefusal(.foreignOrigin, item: handle.name)
        }
        let current = backing.currentGeneration(key: key(for: handle.name))

        guard backing.contains(key: key(for: handle.name)) else {
            throw CustodyRefusal(.notFound, item: handle.name, detail: "not found")
        }
        guard let current, current == handle.generation else {
            throw CustodyRefusal(
                .supersededGeneration,
                item: handle.name,
                detail: "handle refers to a superseded generation"
            )
        }
        guard backing.isNonExportable(key: key(for: handle.name)) else {
            throw CustodyRefusal(.accessGroupMismatch, item: handle.name)
        }
    }

    public func exists(_ handle: SecretHandle) -> Bool {
        (try? resolve(handle)) != nil
    }

    public func isNonExportable(_ handle: SecretHandle) -> Bool {
        backing.isNonExportable(key: key(for: handle.name))
    }

    public func delete(_ handle: SecretHandle) throws {
        guard handle.namespace == namespace, handle.originID == originID else {
            throw CustodyRefusal(.foreignOrigin, item: handle.name)
        }
        backing.remove(key: key(for: handle.name))
    }

    /// Receipt for an operation. Carries the handle's identity and nothing
    /// else, so it can be recorded anywhere without becoming a disclosure.
    public func receipt(for handle: SecretHandle) -> CustodyReceipt {
        CustodyReceipt(
            namespace: handle.namespace,
            name: handle.name,
            generation: handle.generation,
            outcome: exists(handle) ? .stored : .absent
        )
    }

    /// Removes everything in this disposable namespace.
    public func destroyDisposableNamespace() throws {
        guard accessGroup == Self.disposableTestAccessGroup else {
            throw CustodyRefusal(
                .accessGroupMismatch,
                item: namespace,
                detail: "refusing to bulk destroy outside the disposable access group"
            )
        }
        backing.removeAll(withPrefix: namespacePrefix)
    }
}

/// Evidence that an operation happened. Structurally value-free.
public struct CustodyReceipt: Sendable, Hashable, CustomStringConvertible {
    public enum Outcome: String, Sendable, Hashable {
        case stored
        case absent
    }

    public let namespace: String
    public let name: String
    public let generation: UInt64
    public let outcome: Outcome

    public var description: String {
        "CustodyReceipt(\(namespace)/\(name)#\(generation) \(outcome.rawValue))"
    }
}
