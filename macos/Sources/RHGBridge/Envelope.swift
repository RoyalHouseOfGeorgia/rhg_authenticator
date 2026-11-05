import Foundation

/// The contract's canonical JSON encoding: compact, keys sorted by byte order,
/// non-ASCII and "/" unescaped. Params are sent in this form, and it
/// reproduces each contract params file (minus its trailing newline).
public enum CanonicalJSON {
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
}

/// Decodes response envelopes, `{"ok":true,"result":…}` or
/// `{"ok":false,"error":{…}}`.
public enum RPCEnvelope {
    /// Returns the result of a success envelope, or throws the RPCError of an
    /// error envelope. A response that does not decode (including a result
    /// that does not match `R`) throws `RPCError.badResponse`.
    public static func decode<R: Decodable>(_ data: Data, as _: R.Type = R.self) throws(RPCError) -> R {
        let outcome: Outcome<R>
        do {
            outcome = try JSONDecoder().decode(Outcome<R>.self, from: data)
        } catch {
            throw .badResponse
        }
        switch outcome {
        case .success(let result): return result
        case .failure(let error): throw error
        }
    }

    private enum Outcome<R: Decodable>: Decodable {
        case success(R)
        case failure(RPCError)

        private enum CodingKeys: String, CodingKey {
            case ok, result, error
        }

        init(from decoder: any Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            if try c.decode(Bool.self, forKey: .ok) {
                self = .success(try c.decode(R.self, forKey: .result))
            } else {
                self = .failure(try c.decode(RPCError.self, forKey: .error))
            }
        }
    }
}
