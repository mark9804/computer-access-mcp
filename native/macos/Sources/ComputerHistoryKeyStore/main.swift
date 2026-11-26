import Foundation
import Security
import LocalAuthentication
import Darwin
import KeyStoreRequest

private struct KeyStoreResponse: Encodable {
    let version = 1
    let status: String
    let key: String?
    let phase: String?
    let osStatus: Int32?
}

private enum KeyStoreCLI {
    private static func wipe(_ data: inout Data) {
        data.withUnsafeMutableBytes { buffer in
            if let address = buffer.baseAddress, buffer.count > 0 {
                _ = memset_s(address, buffer.count, 0, buffer.count)
            }
        }
        data.removeAll(keepingCapacity: false)
    }

    @discardableResult
    private static func reply(_ status: String, _ key: Data? = nil, phase: String? = nil, osStatus: OSStatus? = nil) -> Int32 {
        let response = KeyStoreResponse(status: status, key: key?.base64EncodedString(), phase: phase, osStatus: osStatus)
        guard var bytes = try? JSONEncoder().encode(response) else { return 1 }
        defer { wipe(&bytes) }
        bytes.append(0x0a)
        do {
            try FileHandle.standardOutput.write(contentsOf: bytes)
            return 0
        } catch {
            return 74
        }
    }

    private enum LegacyUIResult<T> {
        case ok(T)
        case failed(OSStatus)
    }

    /// Unsigned local development binaries use the legacy file-based login keychain where
    /// `LAContext.interactionNotAllowed` alone does not suppress modal access prompts.
    /// Isolate the deprecated non-interactive toggle in one scoped helper so `defer` always runs.
    @available(macOS, deprecated: 10.10, message: "Required for unsigned login keychain compatibility")
    private static func withLegacyKeychainInteractionDisabled<T>(_ body: () -> T) -> LegacyUIResult<T> {
        let status = SecKeychainSetUserInteractionAllowed(false)
        guard status == errSecSuccess else { return .failed(status) }
        defer { _ = SecKeychainSetUserInteractionAllowed(true) }
        return .ok(body())
    }

    private static func baseQuery(for request: KeyStoreRequest) -> [String: Any] {
        let authContext = LAContext()
        authContext.interactionNotAllowed = true
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: request.service,
            kSecAttrAccount as String: request.account,
            kSecAttrSynchronizable as String: false,
            kSecUseAuthenticationContext as String: authContext,
        ]
    }

    private static func load(base: [String: Any]) -> (OSStatus, Data?) {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &value)
        return (status, value as? Data)
    }

    private static func respond(_ status: OSStatus, _ value: inout Data?, phase: String) -> Int32 {
        defer {
            if var secret = value {
                wipe(&secret)
                value = nil
            }
        }
        if status == errSecSuccess, let value, value.count == 32 {
            return reply("ok", value)
        } else if status == errSecSuccess {
            return reply("error", phase: "response-validation", osStatus: status)
        } else if status == errSecItemNotFound {
            return reply("missing", phase: phase, osStatus: status)
        } else if status == errSecInteractionNotAllowed || status == errSecAuthFailed || status == errSecUserCanceled {
            return reply("denied", phase: phase, osStatus: status)
        } else {
            return reply("error", phase: phase, osStatus: status)
        }
    }

    static func run() -> Int32 {
        signal(SIGPIPE, SIG_IGN)
        let request: KeyStoreRequest
        do {
            request = try KeyStoreRequest.read(arguments: CommandLine.arguments, from: FileHandle.standardInput)
        } catch {
            _ = reply("error")
            return 64
        }

        let outcome = withLegacyKeychainInteractionDisabled { () -> Int32 in
            let base = baseQuery(for: request)
            if request.command == "delete" {
                let deleted = SecItemDelete(base as CFDictionary)
                if deleted == errSecSuccess || deleted == errSecItemNotFound {
                    return reply("ok")
                } else if deleted == errSecInteractionNotAllowed || deleted == errSecAuthFailed || deleted == errSecUserCanceled {
                    return reply("denied", phase: "delete", osStatus: deleted)
                } else {
                    return reply("error", phase: "delete", osStatus: deleted)
                }
            }

            var (status, existing) = load(base: base)
            if request.command == "get" || status != errSecItemNotFound {
                return respond(status, &existing, phase: "lookup")
            }

            // Create generates a 32-byte key only when no item exists; concurrent duplicate adds reload the winner.
            var bytes = [UInt8](repeating: 0, count: 32)
            let randomStatus = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            guard randomStatus == errSecSuccess else {
                return reply("error", phase: "random", osStatus: randomStatus)
            }
            var generated = Data(bytes)
            bytes.withUnsafeMutableBytes { buffer in
                if let address = buffer.baseAddress, buffer.count > 0 {
                    _ = memset_s(address, buffer.count, 0, buffer.count)
                }
            }
            defer { wipe(&generated) }

            var attributes = base
            attributes[kSecValueData as String] = generated
            let added = SecItemAdd(attributes as CFDictionary, nil)
            if added == errSecSuccess {
                return reply("ok", generated)
            } else if added == errSecDuplicateItem {
                var (winnerStatus, winner) = load(base: base)
                return respond(winnerStatus, &winner, phase: "race-reload")
            } else {
                var empty: Data? = nil
                return respond(added, &empty, phase: "add")
            }
        }

        switch outcome {
        case .ok(let exitCode):
            return exitCode
        case .failed(let uiStatus):
            return reply("error", phase: "ui-policy", osStatus: uiStatus)
        }
    }
}

exit(KeyStoreCLI.run())
