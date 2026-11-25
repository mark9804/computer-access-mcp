import Foundation
import Security
import Darwin
import KeyStoreRequest

private struct Response: Encodable {
    let version = 1
    let status: String
    let key: String?
    let phase: String?
    let osStatus: Int32?
}

private func reply(_ status: String, _ key: Data? = nil, phase: String? = nil, osStatus: OSStatus? = nil) {
    let response = Response(status: status, key: key?.base64EncodedString(), phase: phase, osStatus: osStatus)
    guard let bytes = try? JSONEncoder().encode(response) else { exit(1) }
    FileHandle.standardOutput.write(bytes)
    FileHandle.standardOutput.write(Data([10]))
}

private func failBeforeKeychain() -> Never {
    reply("error")
    exit(64)
}

let request: KeyStoreRequest
do {
    request = try KeyStoreRequest.read(arguments: CommandLine.arguments, from: FileHandle.standardInput)
} catch {
    failBeforeKeychain()
}

// Suppress interactive Keychain prompts in this helper process.
let uiStatus = SecKeychainSetUserInteractionAllowed(false)
guard uiStatus == errSecSuccess else {
    reply("error", phase: "ui-policy", osStatus: uiStatus)
    exit(0)
}
defer { _ = SecKeychainSetUserInteractionAllowed(true) }

let base: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: request.service,
    kSecAttrAccount as String: request.account,
    kSecAttrSynchronizable as String: false,
    kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
]

func load() -> (OSStatus, Data?) {
    var query = base
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var value: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &value)
    return (status, value as? Data)
}

func respond(_ status: OSStatus, _ value: Data?, phase: String) {
    if status == errSecSuccess, let value, value.count == 32 {
        reply("ok", value)
    } else if status == errSecSuccess {
        reply("error", phase: "response-validation", osStatus: status)
    } else if status == errSecItemNotFound {
        reply("missing", phase: phase, osStatus: status)
    } else if status == errSecInteractionNotAllowed || status == errSecAuthFailed || status == errSecUserCanceled {
        reply("denied", phase: phase, osStatus: status)
    } else {
        reply("error", phase: phase, osStatus: status)
    }
}

if request.command == "delete" {
    let deleted = SecItemDelete(base as CFDictionary)
    if deleted == errSecSuccess || deleted == errSecItemNotFound {
        reply("ok")
    } else if deleted == errSecInteractionNotAllowed || deleted == errSecAuthFailed || deleted == errSecUserCanceled {
        reply("denied", phase: "delete", osStatus: deleted)
    } else {
        reply("error", phase: "delete", osStatus: deleted)
    }
    exit(0)
}

let (status, existing) = load()
if request.command == "get" || status != errSecItemNotFound {
    respond(status, existing, phase: "lookup")
    exit(0)
}

// Create generates a 32-byte key only when no item exists; concurrent duplicate adds reload the winner.
var bytes = [UInt8](repeating: 0, count: 32)
let randomStatus = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard randomStatus == errSecSuccess else {
    reply("error", phase: "random", osStatus: randomStatus)
    exit(0)
}
let generated = Data(bytes)
bytes.withUnsafeMutableBytes { buffer in
    if let address = buffer.baseAddress {
        memset_s(address, buffer.count, 0, buffer.count)
    }
}

var attributes = base
attributes[kSecValueData as String] = generated
let added = SecItemAdd(attributes as CFDictionary, nil)
if added == errSecSuccess {
    reply("ok", generated)
} else if added == errSecDuplicateItem {
    let (winnerStatus, winner) = load()
    respond(winnerStatus, winner, phase: "race-reload")
} else {
    respond(added, nil, phase: "add")
}
