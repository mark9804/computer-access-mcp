import Foundation
import AppKit
import ApplicationServices
import CollectorCore

/// One public AX request for a fixed metadata set without `AXValue`. The caller
/// owns the fresh gate, receiver timeout and budget accounting (charged as one
/// IPC request); this helper neither retries nor caches.
/// Sensitive nodes (`AXSecureTextField`, sensitive subrole, or protected content)
/// always suppress `safeTitle`, `safeDescription`, `safeURL`, `safeRect`, and `safeIdentifier`.
enum AXMetadataBatch {
    typealias Copy = (AXUIElement, CFArray, AXCopyMultipleAttributeOptions, UnsafeMutablePointer<CFArray?>) -> AXError

    static let requestCost = 1
    static let attributeCount = 10
    static let attributeNames: [String] = [
        kAXRoleAttribute,
        kAXSubroleAttribute,
        NSAccessibility.Attribute.containsProtectedContent.rawValue,
        kAXEnabledAttribute,
        kAXTitleAttribute,
        kAXDescriptionAttribute,
        kAXURLAttribute,
        kAXPositionAttribute,
        kAXSizeAttribute,
        kAXIdentifierAttribute,
    ]
    static var attributes: [CFString] {
        attributeNames.map { $0 as CFString }
    }

    enum BatchStatus: Equatable {
        /// The request and array shape succeeded, not necessarily any attribute.
        case success, notPermitted, malformed
        case apiFailure(AXError)

        var axError: AXError? {
            if case .apiFailure(let error) = self { return error }
            return nil
        }
    }

    enum AttributeRead<Value: Equatable>: Equatable {
        case value(Value), noValue, attributeUnsupported, null, malformed, notRead
        case apiFailure(AXError)

        /// Closed shape only; a typed value never exports its strings or boolean.
        var debugStatus: Int64 {
            switch self {
            case .value: return 1
            case .noValue: return 2
            case .attributeUnsupported: return 3
            case .null: return 4
            case .malformed: return 5
            case .notRead: return 6
            case .apiFailure: return 7
            }
        }
        /// Exact SDK status for diagnostics; null/malformed are not AX errors.
        var axError: AXError? {
            switch self {
            case .noValue: return .noValue
            case .attributeUnsupported: return .attributeUnsupported
            case .apiFailure(let error): return error
            case .value, .null, .malformed, .notRead: return nil
            }
        }
    }

    struct Snapshot: Equatable {
        let status: BatchStatus
        let roleStatus: AttributeRead<String>
        let subroleStatus: AttributeRead<String>
        let protectedStatus: AttributeRead<Bool>
        let enabledStatus: AttributeRead<Bool>
        private let titleStatus: AttributeRead<String>
        private let descriptionStatus: AttributeRead<String>
        private let urlStatus: AttributeRead<String>
        private let positionStatus: AttributeRead<CGPoint>
        private let sizeStatus: AttributeRead<CGSize>
        private let identifierStatus: AttributeRead<String>

        init(
            status: BatchStatus,
            roleStatus: AttributeRead<String>,
            subroleStatus: AttributeRead<String>,
            protectedStatus: AttributeRead<Bool>,
            enabledStatus: AttributeRead<Bool> = .notRead,
            titleStatus: AttributeRead<String> = .notRead,
            descriptionStatus: AttributeRead<String> = .notRead,
            urlStatus: AttributeRead<String> = .notRead,
            positionStatus: AttributeRead<CGPoint> = .notRead,
            sizeStatus: AttributeRead<CGSize> = .notRead,
            identifierStatus: AttributeRead<String> = .notRead
        ) {
            self.status = status
            self.roleStatus = roleStatus
            self.subroleStatus = subroleStatus
            self.protectedStatus = protectedStatus
            self.enabledStatus = enabledStatus
            self.titleStatus = titleStatus
            self.descriptionStatus = descriptionStatus
            self.urlStatus = urlStatus
            self.positionStatus = positionStatus
            self.sizeStatus = sizeStatus
            self.identifierStatus = identifierStatus
        }

        var debugNumbers: [String: Int64] {
            let batch: Int64
            switch status { case .success: batch = 1; case .malformed: batch = 5; case .notPermitted: batch = 6; case .apiFailure: batch = 7 }
            var result = ["batchStatus": batch, "roleStatus": roleStatus.debugStatus,
                "subroleStatus": subroleStatus.debugStatus, "protectedStatus": protectedStatus.debugStatus]
            if let error = status.axError { result["batchAXError"] = Int64(error.rawValue) }
            if let error = roleStatus.axError { result["roleAXError"] = Int64(error.rawValue) }
            if let error = subroleStatus.axError { result["subroleAXError"] = Int64(error.rawValue) }
            if let error = protectedStatus.axError { result["protectedAXError"] = Int64(error.rawValue) }
            return result
        }
        var role: String? {
            if case .value(let value) = roleStatus { return value }
            return nil
        }
        var isEnabled: Bool? {
            if case .value(let value) = enabledStatus { return value }
            return nil
        }
        var subroleRead: TextSecurityGate.SubroleRead {
            switch subroleStatus {
            case .value(let value): return .value(value)
            case .noValue: return .noValue
            case .attributeUnsupported: return .attributeUnsupported
            case .null, .malformed: return .malformed
            case .apiFailure, .notRead: return .failure
            }
        }
        var protectedRead: TextSecurityGate.ProtectedContentRead {
            switch protectedStatus {
            case .value(let value): return .value(value)
            case .noValue: return .noValue
            case .attributeUnsupported: return .attributeUnsupported
            case .null, .malformed: return .malformed
            case .apiFailure, .notRead: return .failure
            }
        }
        /// Positive evidence survives an unrelated malformed/failed attribute.
        /// Callers must inspect this before rejecting an absent or wrong role.
        var hasSensitiveEvidence: Bool {
            if role == "AXSecureTextField" || protectedStatus == .value(true) { return true }
            if case .value(let value) = subroleStatus { return TextSecurityGate.isSensitiveSubrole(value) }
            return false
        }
        private var canExposeDisplayMetadata: Bool {
            status == .success && role != nil && !hasSensitiveEvidence &&
                TextSecurityGate.mayTraverse(subrole: subroleRead, protectedContent: protectedRead)
        }
        var safeTitle: String? {
            guard canExposeDisplayMetadata, case .value(let value) = titleStatus else { return nil }
            return value
        }
        var safeDescription: String? {
            guard canExposeDisplayMetadata, case .value(let value) = descriptionStatus else { return nil }
            return value
        }
        var safeURL: String? {
            guard canExposeDisplayMetadata, case .value(let value) = urlStatus else { return nil }
            return value
        }
        var safeRect: SurfaceAbsoluteRect? {
            guard canExposeDisplayMetadata,
                  case .value(let point) = positionStatus,
                  case .value(let size) = sizeStatus else { return nil }
            return SurfaceAbsoluteRect(
                x: Double(point.x),
                y: Double(point.y),
                width: Double(size.width),
                height: Double(size.height)
            )
        }
        var safeIdentifier: String? {
            guard canExposeDisplayMetadata, case .value(let value) = identifierStatus, !value.isEmpty else { return nil }
            return value
        }
    }

    static func read(element: AXUIElement, permit: () -> Bool,
                     copy: Copy = { AXUIElementCopyMultipleAttributeValues($0, $1, $2, $3) }) -> Snapshot {
        guard permit() else {
            return Snapshot(status: .notPermitted, roleStatus: .notRead, subroleStatus: .notRead, protectedStatus: .notRead)
        }
        var values: CFArray?
        let status = WorkerProgress.withCall(api: 6, attribute: 20) {
            copy(element, attributes as CFArray, AXCopyMultipleAttributeOptions(rawValue: 0), &values)
        }
        guard status == .success else {
            // A failed request is not per-attribute absence. Do not trust a
            // partially returned array or retry through a different API.
            return Snapshot(status: .apiFailure(status), roleStatus: .notRead, subroleStatus: .notRead, protectedStatus: .notRead)
        }
        guard let values, CFArrayGetCount(values) == attributeCount else {
            // No positional evidence is trusted when the fixed shape is wrong.
            return Snapshot(
                status: .malformed,
                roleStatus: .malformed,
                subroleStatus: .malformed,
                protectedStatus: .malformed,
                enabledStatus: .malformed,
                titleStatus: .malformed,
                descriptionStatus: .malformed,
                urlStatus: .malformed,
                positionStatus: .malformed,
                sizeStatus: .malformed,
                identifierStatus: .malformed
            )
        }
        return Snapshot(
            status: .success,
            roleStatus: decode(values, index: 0, typed: string),
            subroleStatus: decode(values, index: 1, typed: string),
            protectedStatus: decode(values, index: 2, typed: boolean),
            enabledStatus: decode(values, index: 3, typed: boolean),
            titleStatus: decode(values, index: 4, typed: string),
            descriptionStatus: decode(values, index: 5, typed: string),
            urlStatus: decode(values, index: 6, typed: urlString),
            positionStatus: decode(values, index: 7, typed: cgPoint),
            sizeStatus: decode(values, index: 8, typed: cgSize),
            identifierStatus: decode(values, index: 9, typed: string)
        )
    }

    private static func decode<Value: Equatable>(_ values: CFArray, index: Int,
                                                 typed: (CFTypeRef) -> Value?) -> AttributeRead<Value> {
        guard let pointer = CFArrayGetValueAtIndex(values, index) else { return .malformed }
        let value = Unmanaged<AnyObject>.fromOpaque(pointer).takeUnretainedValue()
        if CFGetTypeID(value) == CFNullGetTypeID() { return .null }
        if CFGetTypeID(value) == AXValueGetTypeID() {
            let wrapped = value as! AXValue
            if AXValueGetType(wrapped) == .axError {
                var error = AXError.failure
                guard AXValueGetValue(wrapped, .axError, &error) else { return .malformed }
                switch error {
                case .noValue: return .noValue
                case .attributeUnsupported: return .attributeUnsupported
                case .success: return .malformed // No typed value accompanies it.
                default: return .apiFailure(error)
                }
            }
            return typed(value).map(AttributeRead.value) ?? .malformed
        }
        return typed(value).map(AttributeRead.value) ?? .malformed
    }

    private static func string(_ value: CFTypeRef) -> String? {
        guard CFGetTypeID(value) == CFStringGetTypeID() else { return nil }
        return value as? String
    }
    private static func boolean(_ value: CFTypeRef) -> Bool? {
        guard CFGetTypeID(value) == CFBooleanGetTypeID() else { return nil }
        return CFBooleanGetValue((value as! CFBoolean))
    }
    private static func urlString(_ value: CFTypeRef) -> String? {
        if CFGetTypeID(value) == CFURLGetTypeID() {
            return (value as? URL)?.absoluteString
        }
        if CFGetTypeID(value) == CFStringGetTypeID() {
            return value as? String
        }
        return nil
    }
    private static func cgPoint(_ value: CFTypeRef) -> CGPoint? {
        guard CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
        let wrapped = value as! AXValue
        guard AXValueGetType(wrapped) == .cgPoint else { return nil }
        var point = CGPoint.zero
        guard AXValueGetValue(wrapped, .cgPoint, &point),
              point.x.isFinite, point.y.isFinite else { return nil }
        return point
    }
    private static func cgSize(_ value: CFTypeRef) -> CGSize? {
        guard CFGetTypeID(value) == AXValueGetTypeID() else { return nil }
        let wrapped = value as! AXValue
        guard AXValueGetType(wrapped) == .cgSize else { return nil }
        var size = CGSize.zero
        guard AXValueGetValue(wrapped, .cgSize, &size),
              size.width.isFinite, size.height.isFinite else { return nil }
        return size
    }
}
