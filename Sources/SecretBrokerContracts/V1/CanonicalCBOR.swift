/// Deterministic CBOR for the armel-authority-v1 family.
///
/// Implemented from the family's contract document (RFC 8949 section 4.2.1,
/// restricted to five types), not from any peer's implementation. The point of
/// a second implementation is to disagree when one of us has misread the
/// specification, which it cannot do if it was derived from the other's code.
///
/// The decoder refuses a non-canonical spelling instead of normalising it.
/// Normalising would mean two different byte strings both verify while the
/// digest, and therefore the signature, covers only one of them.
///
/// KNOWN RESIDUAL, ARM-48-pending. Duplicate map keys are rejected by byte
/// equality. Two keys that differ in bytes but are canonically equivalent, for
/// example under a Unicode normalisation, are not currently treated as
/// duplicates here. The owner decision is reject-as-duplicate on both sides,
/// extending ARM-32 F1, and lands as ARM-48. Until it does, this is named
/// rather than silently carried: a consumer must not read the duplicate-key
/// rule as covering canonical equivalence.
public enum CanonicalCBOR {
    static let maximumNesting = 32

    // MARK: Encoding

    public static func encode(_ value: CanonicalValue) throws -> [UInt8] {
        var output: [UInt8] = []
        try encode(value, into: &output, depth: 0)
        return output
    }

    private static func encode(_ value: CanonicalValue, into output: inout [UInt8], depth: Int) throws {
        guard depth <= maximumNesting else { throw CanonicalCBORError.nestingTooDeep }

        switch value {
        case .unsigned(let number):
            appendHead(major: 0, argument: number, to: &output)

        case .text(let text):
            guard let utf8 = strictUTF8(text) else { throw CanonicalCBORError.invalidUTF8 }
            appendHead(major: 3, argument: UInt64(utf8.count), to: &output)
            output.append(contentsOf: utf8)

        case .boolean(let flag):
            // Major 7, simple value 20 for false and 21 for true.
            output.append(flag ? 0xf5 : 0xf4)

        case .array(let elements):
            appendHead(major: 4, argument: UInt64(elements.count), to: &output)
            for element in elements {
                try encode(element, into: &output, depth: depth + 1)
            }

        case .map(let entries):
            // Keys sort bytewise by their ENCODED form, so the length prefix is
            // part of the key: "b" sorts before "aa". Sorting the strings alone
            // would order them the other way and silently produce bytes no peer
            // reproduces.
            var encodedKeys: [(key: [UInt8], name: String)] = []
            encodedKeys.reserveCapacity(entries.count)
            for name in entries.keys {
                guard let utf8 = strictUTF8(name) else { throw CanonicalCBORError.invalidUTF8 }
                var head: [UInt8] = []
                appendHead(major: 3, argument: UInt64(utf8.count), to: &head)
                encodedKeys.append((key: head + utf8, name: name))
            }
            encodedKeys.sort { lexicographicallyPrecedes($0.key, $1.key) }

            appendHead(major: 5, argument: UInt64(entries.count), to: &output)
            for entry in encodedKeys {
                output.append(contentsOf: entry.key)
                try encode(entries[entry.name]!, into: &output, depth: depth + 1)
            }
        }
    }

    /// Shortest form that carries the argument, which is what makes the
    /// encoding deterministic.
    private static func appendHead(major: UInt8, argument: UInt64, to output: inout [UInt8]) {
        let prefix = major << 5
        switch argument {
        case ..<24:
            output.append(prefix | UInt8(argument))
        case ..<0x1_00:
            output.append(prefix | 24)
            output.append(UInt8(argument))
        case ..<0x1_0000:
            output.append(prefix | 25)
            output.append(contentsOf: bigEndianBytes(argument, width: 2))
        case ..<0x1_0000_0000:
            output.append(prefix | 26)
            output.append(contentsOf: bigEndianBytes(argument, width: 4))
        default:
            output.append(prefix | 27)
            output.append(contentsOf: bigEndianBytes(argument, width: 8))
        }
    }

    private static func bigEndianBytes(_ value: UInt64, width: Int) -> [UInt8] {
        (0..<width).reversed().map { UInt8(truncatingIfNeeded: value >> (8 * UInt64($0))) }
    }

    private static func lexicographicallyPrecedes(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for (a, b) in zip(lhs, rhs) where a != b { return a < b }
        return lhs.count < rhs.count
    }

    /// Strict UTF-8: rejects any string carrying an unpaired surrogate, which
    /// Swift represents as a replacement-producing scalar sequence.
    private static func strictUTF8(_ text: String) -> [UInt8]? {
        for scalar in text.unicodeScalars where (0xD800...0xDFFF).contains(scalar.value) {
            return nil
        }
        return Array(text.utf8)
    }

    // MARK: Decoding

    public static func decode(_ bytes: [UInt8]) throws -> CanonicalValue {
        var cursor = 0
        let value = try decodeItem(bytes, &cursor, depth: 0)
        guard cursor == bytes.count else { throw CanonicalCBORError.trailingBytes }
        return value
    }

    private static func decodeItem(_ bytes: [UInt8], _ cursor: inout Int, depth: Int) throws -> CanonicalValue {
        guard depth <= maximumNesting else { throw CanonicalCBORError.nestingTooDeep }
        guard cursor < bytes.count else { throw CanonicalCBORError.truncated }

        let initial = bytes[cursor]
        let major = initial >> 5
        let additional = initial & 0x1f
        cursor += 1

        switch major {
        case 0:
            return .unsigned(try readArgument(bytes, &cursor, additional))

        case 3:
            let length = Int(try readArgument(bytes, &cursor, additional))
            guard cursor + length <= bytes.count else { throw CanonicalCBORError.truncated }
            let slice = Array(bytes[cursor..<(cursor + length)])
            cursor += length
            guard let text = String(bytes: slice, encoding: .utf8), strictUTF8(text) != nil else {
                throw CanonicalCBORError.invalidUTF8
            }
            return .text(text)

        case 4:
            let count = Int(try readArgument(bytes, &cursor, additional))
            var elements: [CanonicalValue] = []
            elements.reserveCapacity(count)
            for _ in 0..<count {
                elements.append(try decodeItem(bytes, &cursor, depth: depth + 1))
            }
            return .array(elements)

        case 5:
            let count = Int(try readArgument(bytes, &cursor, additional))
            var entries: [String: CanonicalValue] = [:]
            var previousKey: [UInt8]?
            for _ in 0..<count {
                let keyStart = cursor
                let key = try decodeItem(bytes, &cursor, depth: depth + 1)
                guard case .text(let name) = key else {
                    throw CanonicalCBORError.unsupportedType("map key is not a text string")
                }
                let encodedKey = Array(bytes[keyStart..<cursor])
                if let previous = previousKey {
                    if encodedKey == previous {
                        throw CanonicalCBORError.duplicateField(name)
                    }
                    guard lexicographicallyPrecedes(previous, encodedKey) else {
                        throw CanonicalCBORError.noncanonicalEncoding(
                            "map keys are not sorted bytewise by encoded form at key \(name)"
                        )
                    }
                }
                if entries[name] != nil { throw CanonicalCBORError.duplicateField(name) }
                previousKey = encodedKey
                entries[name] = try decodeItem(bytes, &cursor, depth: depth + 1)
            }
            return .map(entries)

        case 7:
            switch additional {
            case 20: return .boolean(false)
            case 21: return .boolean(true)
            default:
                throw CanonicalCBORError.unsupportedType("simple or float value \(additional)")
            }

        case 1:
            throw CanonicalCBORError.unsupportedType("negative integer")
        case 2:
            throw CanonicalCBORError.unsupportedType("byte string")
        case 6:
            throw CanonicalCBORError.unsupportedType("tag")
        default:
            throw CanonicalCBORError.unsupportedType("major type \(major)")
        }
    }

    /// Reads a head argument, refusing indefinite lengths and any head that is
    /// not the shortest form carrying its value.
    private static func readArgument(_ bytes: [UInt8], _ cursor: inout Int, _ additional: UInt8) throws -> UInt64 {
        switch additional {
        case ..<24:
            return UInt64(additional)
        case 24, 25, 26, 27:
            let width = 1 << Int(additional - 24)
            guard cursor + width <= bytes.count else { throw CanonicalCBORError.truncated }
            var value: UInt64 = 0
            for offset in 0..<width {
                value = (value << 8) | UInt64(bytes[cursor + offset])
            }
            cursor += width
            let minimum: UInt64
            switch additional {
            case 24: minimum = 24
            case 25: minimum = 0x1_00
            case 26: minimum = 0x1_0000
            default: minimum = 0x1_0000_0000
            }
            guard value >= minimum else {
                throw CanonicalCBORError.noncanonicalEncoding(
                    "argument \(value) is not written in its shortest head"
                )
            }
            return value
        case 31:
            throw CanonicalCBORError.noncanonicalEncoding("indefinite length")
        default:
            throw CanonicalCBORError.noncanonicalEncoding("reserved additional information \(additional)")
        }
    }

    // MARK: Hex helpers

    public static func bytes(fromHex hex: String) -> [UInt8]? {
        guard hex.count % 2 == 0 else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        return result
    }

    public static func hex(fromBytes bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
