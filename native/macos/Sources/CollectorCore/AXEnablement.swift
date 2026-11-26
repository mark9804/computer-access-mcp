import Foundation

/// Metadata describing per-application accessibility tree activation.
public struct AXEnablementResult: Codable, Equatable {
    public enum Status: String, Codable {
        case disabled
        case denied
        case alreadyEnabled = "already-enabled"
        case enabled
        case unsupported
        case originalUnknown = "original-unknown"
        case notSettable = "not-settable"
        case writeFailed = "write-failed"
    }
    public enum Attribute: String, Codable {
        case manual
        case enhanced
        case none
    }
    public var status: Status
    public var attribute: Attribute
    public var changed: Bool

    public init(status: Status, attribute: Attribute = .none, changed: Bool = false) {
        self.status = status
        self.attribute = attribute
        self.changed = changed
    }
}

public protocol AXEnablementProvider: AnyObject {
    var isAvailable: Bool { get }
    var writeReportedSuccess: Bool { get }
    func supports(_ attribute: AXEnablementResult.Attribute) -> Bool
    func current(_ attribute: AXEnablementResult.Attribute) -> Bool?
    func settable(_ attribute: AXEnablementResult.Attribute) -> Bool?
    func enable(_ attribute: AXEnablementResult.Attribute) -> Bool
}

public extension AXEnablementProvider {
    var isAvailable: Bool { true }
    var writeReportedSuccess: Bool { false }
}

public final class AXEnablementLease {
    public private(set) var result = AXEnablementResult(status: .disabled)
    private var acquired = false

    public init() {}

    public func acquire(
        applicationId: String,
        policy: CapturePolicy,
        activation: AXActivationMode = .manualAccessibility,
        provider: AXEnablementProvider,
        allowWrite: Bool = true
    ) -> AXEnablementResult {
        guard !acquired else { return result }
        acquired = true
        guard policy.axCompatibility == true, activation != .none else { return result }
        guard ApplicationPolicy.allows(applicationId, policy: policy),
              BrowserGate.allows(applicationId, policy: policy) else {
            result = .init(status: .denied)
            return result
        }
        guard provider.isAvailable else {
            result = .init(status: .originalUnknown)
            return result
        }

        let attribute: AXEnablementResult.Attribute
        switch activation {
        case .none:
            return result
        case .enhancedUI:
            let enhanced = provider.supports(.enhanced)
            guard provider.isAvailable else { result = .init(status: .originalUnknown); return result }
            guard enhanced else { result = .init(status: .unsupported); return result }
            attribute = .enhanced
        case .manualAccessibility:
            let manual = provider.supports(.manual)
            guard provider.isAvailable else { result = .init(status: .originalUnknown); return result }
            if manual {
                attribute = .manual
            } else {
                let enhanced = provider.supports(.enhanced)
                guard provider.isAvailable else { result = .init(status: .originalUnknown); return result }
                guard enhanced else { result = .init(status: .unsupported); return result }
                attribute = .enhanced
            }
        }

        guard let previous = provider.current(attribute), provider.isAvailable else {
            result = .init(status: .originalUnknown, attribute: attribute)
            return result
        }
        if previous {
            result = .init(status: .alreadyEnabled, attribute: attribute)
            return result
        }
        guard allowWrite else {
            result = .init(status: .denied, attribute: attribute)
            return result
        }
        guard provider.settable(attribute) == true, provider.isAvailable else {
            result = .init(status: .notSettable, attribute: attribute)
            return result
        }
        guard provider.enable(attribute), provider.isAvailable else {
            result = .init(status: .writeFailed, attribute: attribute, changed: provider.writeReportedSuccess)
            return result
        }
        guard provider.current(attribute) == true, provider.isAvailable else {
            result = .init(status: .writeFailed, attribute: attribute, changed: true)
            return result
        }
        result = .init(status: .enabled, attribute: attribute, changed: true)
        return result
    }

    public func release() {
        acquired = false
    }
}
