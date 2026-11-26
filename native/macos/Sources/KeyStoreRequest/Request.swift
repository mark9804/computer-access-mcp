import Foundation

public enum KeyStoreRequestError: Error {
    case invalidArguments
    case invalidInput
    case tooLarge
}

/// Parses bounded JSON stdin requests before touching Keychain APIs.
public struct KeyStoreRequest: Decodable, Equatable {
    public let version: Int
    public let command: String
    public let service: String
    public let account: String

    public static func read(arguments: [String], from input: FileHandle) throws -> KeyStoreRequest {
        guard arguments.count == 3, arguments[1] == "--command", ["get", "create", "delete"].contains(arguments[2]) else {
            throw KeyStoreRequestError.invalidArguments
        }
        var bytes = Data()
        while true {
            guard let part = try input.read(upToCount: 2049 - bytes.count), !part.isEmpty else { break }
            bytes.append(part)
            guard bytes.count <= 2048 else { throw KeyStoreRequestError.tooLarge }
        }
        guard let dictionary = try JSONSerialization.jsonObject(with: bytes) as? [String: Any],
              Set(dictionary.keys) == Set(["version", "command", "service", "account"]) else {
            throw KeyStoreRequestError.invalidInput
        }
        let request = try JSONDecoder().decode(KeyStoreRequest.self, from: bytes)
        guard request.version == 1, request.command == arguments[2],
              request.service.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil,
              request.account.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil else {
            throw KeyStoreRequestError.invalidInput
        }
        return request
    }
}
