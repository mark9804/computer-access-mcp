import Foundation
import HistoryContract

/// Raw event categories, not successful actions or interpreted gestures.
public enum InputActivityCategory: CaseIterable {
    case pointerRelease, dragSample, scrollSample, shortcutPress
}

/// CGEvent timestamps use nanoseconds. Missing, future and delayed events are dropped.
public enum InputActivityFreshness {
    public static func accepts(timestampNanoseconds: UInt64, nowNanoseconds: UInt64, afterNanoseconds: UInt64 = 0) -> Bool {
        timestampNanoseconds > afterNanoseconds && timestampNanoseconds <= nowNanoseconds &&
            nowNanoseconds - timestampNanoseconds <= 200_000_000
    }
}

/// The native boundary never retains or transfers a CGEvent, key identity or location.
public struct InputActivitySample {
    public let application: ApplicationIdentity
    public let category: InputActivityCategory
    public let callbackTimeMs: Int64
    public init(application: ApplicationIdentity, category: InputActivityCategory, callbackTimeMs: Int64) {
        self.application = application; self.category = category; self.callbackTimeMs = callbackTimeMs
    }
}

public struct InputActivityStamp: Equatable {
    public let captureEpoch: Int64
    public let foregroundGeneration: Int64
    public let focusGeneration: Int64
    public let policyRevision: Int64
    public init(captureEpoch: Int64, foregroundGeneration: Int64, focusGeneration: Int64, policyRevision: Int64) {
        self.captureEpoch = captureEpoch; self.foregroundGeneration = foregroundGeneration
        self.focusGeneration = focusGeneration; self.policyRevision = policyRevision
    }
    public var json: JSONValue { .object([
        "captureEpoch": j(captureEpoch), "foregroundGeneration": j(foregroundGeneration),
        "focusGeneration": j(focusGeneration), "policyRevision": j(policyRevision),
    ]) }
}

public struct InputActivityBucket {
    public let application: ApplicationIdentity
    public let stamp: InputActivityStamp
    public let intervalStartMs: Int64
    public var intervalEndMs: Int64 { intervalStartMs + 1_000 }
    public private(set) var pointerReleases = 0
    public private(set) var dragSamples = 0
    public private(set) var scrollSamples = 0
    public private(set) var shortcutPresses = 0
    public private(set) var capped = false
    public var total: Int { pointerReleases + dragSamples + scrollSamples + shortcutPresses }
    fileprivate init(sample: InputActivitySample, stamp: InputActivityStamp) {
        application = sample.application; self.stamp = stamp
        intervalStartMs = sample.callbackTimeMs / 1_000 * 1_000
    }
    fileprivate mutating func add(_ category: InputActivityCategory) {
        guard total < 256 else { capped = true; return }
        switch category {
        case .pointerRelease: pointerReleases += 1
        case .dragSample: dragSamples += 1
        case .scrollSample: scrollSamples += 1
        case .shortcutPress: shortcutPresses += 1
        }
    }
    public func payload(fixture: Bool) -> JSONValue {
        var reasons = ["input-events-partial", "application-only", "effect-unverified"]
        if capped { reasons.append("input-events-capped") }
        return .object([
            "kind": .string("input.activity"), "source": .string(fixture ? "fixture" : "cg.listen-only"), "scope": .string("application"),
            "intervalStartMs": j(intervalStartMs), "intervalEndMs": j(intervalEndMs),
            "counts": .object(["pointerReleases": j(pointerReleases), "dragSamples": j(dragSamples),
                               "scrollSamples": j(scrollSamples), "shortcutPresses": j(shortcutPresses)]),
            "gate": .object(["policyRevision": j(stamp.policyRevision), "secureInput": .string("inactive"),
                             "targetAttribution": .string("event-target-pid"), "detail": .string("coarse-counts")]),
            "coverage": .object(["status": .string("partial"), "truncated": .bool(capped),
                                 "missingReasons": .array(reasons.map(JSONValue.string))]),
        ])
    }
}

/// One in-memory bucket only. No raw events, sub-second timestamps or per-key counters.
public struct InputActivityAccumulator {
    public private(set) var pending: InputActivityBucket?
    public init() {}
    public mutating func clear() { pending = nil }
    public mutating func add(_ sample: InputActivitySample, stamp: InputActivityStamp) {
        guard sample.callbackTimeMs >= 0, sample.callbackTimeMs <= 9_007_199_254_739_000,
              sample.application.processId > 1, !sample.application.applicationId.isEmpty,
              !sample.application.processStartTime.isEmpty else { clear(); return }
        let start = sample.callbackTimeMs / 1_000 * 1_000
        // A caller must flush completed buckets explicitly after its fresh gate.
        // Identity/epoch/time discontinuities discard, never merge or reattribute.
        if let current = pending,
           current.application != sample.application || current.stamp.captureEpoch != stamp.captureEpoch ||
           current.stamp.policyRevision != stamp.policyRevision || current.intervalStartMs != start {
            clear()
        }
        if pending == nil { pending = InputActivityBucket(sample: sample, stamp: stamp) }
        pending?.add(sample.category)
    }
    public mutating func takeCompleted(nowMs: Int64) -> InputActivityBucket? {
        guard let current = pending else { return nil }
        guard nowMs >= current.intervalStartMs else { clear(); return nil }
        guard nowMs >= current.intervalEndMs else { return nil }
        clear()
        // Scheduling gaps and wall-clock jumps cannot publish stale activity later.
        guard nowMs - current.intervalEndMs <= 1_000 else { return nil }
        return current
    }
}
