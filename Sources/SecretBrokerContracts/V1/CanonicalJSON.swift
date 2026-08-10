import Foundation

/// Canonical JSON for the armel-approval families.
///
/// Implemented from the published vectors and the contract documents, never
/// from a peer encoder. The rules, in the order they bite:
///
/// 1. Object keys are sorted by UTF-8 byte value. Not by Unicode collation and
///    not by insertion order, so `"A"` precedes `"a"` and every ASCII key
///    precedes every non-ASCII one.
/// 2. No insignificant whitespace anywhere.
/// 3. Integers are plain decimal: no exponent, no fraction, no leading plus.
/// 4. C0 control points are escaped, never emitted raw. Five have short forms
///    (`\b \t \n \f \r`); the rest take `\u00xx`. Quote and backslash take
///    their short forms. Solidus is NOT escaped.
/// 5. Non-ASCII is emitted as raw UTF-8. The encoder never emits a `\u` escape
///    for a non-ASCII character and never normalises, so two strings that
///    render identically but differ in bytes encode differently.
///
/// DELIBERATELY NOT CLAIMED: lone surrogates. They cannot appear in a UTF-8
/// vector file, and upstream measured that the two JSON readers diverge on the
/// escaped form. This encoder therefore takes no position, and no test here
/// asserts one. A behaviour nobody has pinned is not a behaviour to guess.
///
/// KNOWN RESIDUAL, ARM-48-pending, upstream DISC-052: two keys that are
/// distinct byte sequences but Unicode-canonically-equivalent are not treated
/// as duplicates. Upstream pins no case blessing either behaviour. The owner
/// decision is reject-as-duplicate on both sides; until it lands, this is named
/// rather than assumed.
public enum CanonicalJSON {
    public enum EncodingError: Error, Sendable, Hashable {
        case unsupportedValue(String)
        case invalidUTF8
    }

    /// Encodes a JSON value in canonical form, returning the exact bytes a
    /// signer covers.
    public static func encode(_ value: Any) throws -> [UInt8] {
        var output: [UInt8] = []
        try encode(value, into: &output)
        return output
    }

    public static func encodeToString(_ value: Any) throws -> String {
        String(decoding: try encode(value), as: UTF8.self)
    }

    private static func encode(_ value: Any, into output: inout [UInt8]) throws {
        switch value {
        case let text as String:
            try encode(string: text, into: &output)

        case let number as NSNumber:
            if CFGetTypeID(number) == CFBooleanGetTypeID() {
                output.append(contentsOf: Array((number.boolValue ? "true" : "false").utf8))
                return
            }
            // Integers only: an exponent or fraction would give two spellings
            // of one value, and a canonical encoding cannot have two.
            guard CFNumberIsFloatType(number as CFNumber) == false else {
                throw EncodingError.unsupportedValue("floating point")
            }
            output.append(contentsOf: Array(String(number.int64Value).utf8))

        case let array as [Any]:
            output.append(UInt8(ascii: "["))
            for (index, element) in array.enumerated() {
                if index > 0 { output.append(UInt8(ascii: ",")) }
                try encode(element, into: &output)
            }
            output.append(UInt8(ascii: "]"))

        case let object as [String: Any]:
            // Sorted by UTF-8 byte value of the key itself.
            let keys = object.keys.sorted { lhs, rhs in
                bytesPrecede(Array(lhs.utf8), Array(rhs.utf8))
            }
            output.append(UInt8(ascii: "{"))
            for (index, key) in keys.enumerated() {
                if index > 0 { output.append(UInt8(ascii: ",")) }
                try encode(string: key, into: &output)
                output.append(UInt8(ascii: ":"))
                try encode(object[key]!, into: &output)
            }
            output.append(UInt8(ascii: "}"))

        case is NSNull:
            throw EncodingError.unsupportedValue("null")

        default:
            throw EncodingError.unsupportedValue(String(describing: type(of: value)))
        }
    }

    private static func encode(string: String, into output: inout [UInt8]) throws {
        output.append(UInt8(ascii: "\""))
        for scalar in string.unicodeScalars {
            switch scalar {
            case "\"": output.append(contentsOf: Array("\\\"".utf8))
            case "\\": output.append(contentsOf: Array("\\\\".utf8))
            case "\u{08}": output.append(contentsOf: Array("\\b".utf8))
            case "\u{09}": output.append(contentsOf: Array("\\t".utf8))
            case "\u{0a}": output.append(contentsOf: Array("\\n".utf8))
            case "\u{0c}": output.append(contentsOf: Array("\\f".utf8))
            case "\u{0d}": output.append(contentsOf: Array("\\r".utf8))
            default:
                if scalar.value < 0x20 {
                    // Every other C0 point takes the six-character form.
                    output.append(contentsOf: Array(String(format: "\\u%04x", scalar.value).utf8))
                } else {
                    // Everything else, including solidus, DEL, and all
                    // non-ASCII, is emitted as raw UTF-8.
                    output.append(contentsOf: Array(String(scalar).utf8))
                }
            }
        }
        output.append(UInt8(ascii: "\""))
    }

    private static func bytesPrecede(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        for (a, b) in zip(lhs, rhs) where a != b { return a < b }
        return lhs.count < rhs.count
    }

    /// Canonical-on-input: parse, re-encode, and require the bytes to match.
    ///
    /// A verifier that accepted a non-canonical spelling would let two byte
    /// strings both verify while the digest covers only one of them.
    public static func isCanonical(_ bytes: [UInt8]) -> Bool {
        guard let parsed = try? JSONSerialization.jsonObject(
            with: Data(bytes),
            options: [.fragmentsAllowed]
        ) else {
            return false
        }
        guard let reEncoded = try? encode(parsed) else { return false }
        return reEncoded == bytes
    }
}
