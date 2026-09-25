//
//  SecurityShield.swift
//  NexilisSecurityShield
//
//  Created by Qindi on 31/10/24. Split out of NexilisLite into a package of its own.
//
//  The server-configured SecurityShield policy (get_feature_access_new): which device, network and
//  behaviour checks run, and what a finding does - "continue" (warn and go on) or "exit". It sits
//  between NexilisZTA and the NexilisLite connection:
//
//      APISZTA / SentinelSecurityGate  ->  SecurityShield.run  ->  Nexilis.connect
//
//  so a device the ZTA layer let through is still held to the institution's own policy before the
//  messaging session opens, and NexilisLite refuses to connect until `hasPassed`.
//
//  What changed against the copy that lived in NexilisLite:
//    - One linear chain with a single completion, instead of a step counter every check had to set
//      by hand. The counter was off by one in most places: a "continue" answer, the clone check and
//      the behaviour check all resumed at a step the counter did not expect and ended in exit(172),
//      so no policy could ever say "warn and continue".
//    - Findings go to the ZTA layer (revocation at modes 1 and 2) through NexilisZTA directly.
//    - No policy yet (first launch offline) is fail-closed at modes 1 and 2: the device-integrity
//      checks run with "exit" instead of not at all.
//    - Jailbreak, hook and debugger checks also consult the NexilisZTA native engine.
//    - The policy is parsed defensively; a malformed answer no longer crashes the app.
//    - Device attributes are never collected on the main thread (it waited on itself for 10 s).
//    - Every connection is HTTPS to the policy service, pinned the NexilisZTA way; reports go to
//      security_shield_logging (the endpoint the Android SDK's HTTPS path uses) instead of over
//      the nuSDKService socket, so they no longer wait for - or depend on - the messaging session.
//      A report that cannot be delivered is kept and retried.
//    - No private UIKit keys; URLSessions are invalidated after use.
//

import Foundation
import UIKit
import CoreTelephony
import CryptoKit
import MachO
import NexilisZTA
import OSLog
import SystemConfiguration.CaptiveNetwork
import CoreLocation
import Network
import CoreMotion

public final class SecurityShield: NSObject {

    // MARK: - Public API

    /// True once the chain has finished for this launch - every check passed, or the policy said
    /// "continue" for what it found. NexilisLite does not open its session before this.
    public static var hasPassed: Bool {
        lock.lock(); defer { lock.unlock() }
        return passed
    }

    /// Runs the policy once per launch and reports the outcome on the main thread. A later call
    /// while it runs waits for the same outcome; a call after it finished gets it at once. A
    /// finding whose policy action is "exit" ends the process from its alert and never completes.
    public static func run(appName: String, apiKey: String, completion: @escaping (Bool) -> Void) {
        if !appName.isEmpty { Preference.setAppId(value: appName) }
        if !apiKey.isEmpty { Preference.setAccount(value: apiKey) }
        lock.lock()
        if passed {
            lock.unlock()
            DispatchQueue.main.async { completion(true) }
            return
        }
        waiters.append(completion)
        let alreadyRunning = running
        running = true
        lock.unlock()
        guard !alreadyRunning else { return }
        // Used on its own, without NexilisZTA having been configured, the policy service's pins
        // are not in place yet and every pinned request would be refused. The compiled-in set.
        if !RASPGuard.shared().pinningConfigured {
            APISZTA.applyConfiguration(APISZTA.configuration)
            log("pin NexilisZTA belum dipasang - memakai set terkompilasi")
        }
        log("mulai - menarik kebijakan")
        pullPolicy { Chain.start() }
    }

    /// Kept for hosts that started the checks themselves and did not wait on them.
    @available(*, deprecated, message: "Use run(appName:apiKey:completion:) and connect from its completion.")
    public static func check(appName: String, apiKey: String) {
        run(appName: appName, apiKey: apiKey) { _ in }
    }

    /// The signed-in user's pin, attached to every report from here on. NexilisLite sets it once
    /// its session is up.
    public static func setUserPin(_ pin: String) {
        guard !pin.isEmpty else { return }
        SecureUserDefaultsSS.shared.set(pin, forKey: "me")
    }

    /// Retries the reports that could not be delivered (no network at the time). NexilisLite calls
    /// this once it is connected; it is safe to call at any time.
    public static func flushPendingReports() {
        Reports.flush()
    }

    // MARK: - Completion

    private static let lock = NSLock()
    private static var passed = false
    private static var running = false
    private static var waiters: [(Bool) -> Void] = []

    fileprivate static func finish(_ ok: Bool) {
        lock.lock()
        passed = ok
        running = false
        let pending = waiters
        waiters = []
        lock.unlock()
        log(ok ? "selesai - lolos" : "selesai - tidak lolos")
        DispatchQueue.main.async { pending.forEach { $0(ok) } }
    }

    fileprivate static func log(_ text: String) {
        NXLogger.general.publicInfo("[SecurityShield] \(text)")
        #if DEBUG
        print("[SecurityShield] \(text)")
        #endif
    }

    // MARK: - Policy

    private static func pullPolicy(then next: @escaping () -> Void) {
        guard let url = URL(string: Preference.getDomainOpr() + "get_feature_access_new") else {
            next(); return
        }
        post(to: url) { data, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            if status == 200, error == nil, let data, Policy.apply(data) {
                log("kebijakan diterima")
            } else {
                // The checks still run, against the rules last received - and at modes 1 and 2
                // against the integrity baseline when none was ever received.
                log("kebijakan tidak tersedia (HTTP \(status)) - memakai kebijakan tersimpan")
            }
            next()
        }
    }

    /// POSTs to the policy service over a session pinned the NexilisZTA way. HTTPS only: anything
    /// else is refused before a byte leaves the device.
    fileprivate static func post(to url: URL, body: Any? = nil,
                                 completion: @escaping (Data?, URLResponse?, Error?) -> Void) {
        guard url.scheme?.lowercased() == "https" else {
            log("menolak koneksi non-HTTPS: \(url.scheme ?? "?")://\(url.host ?? "")")
            completion(nil, nil, NSError(domain: "io.nexilis.securityshield", code: -1,
                                         userInfo: [NSLocalizedDescriptionKey: "HTTPS required"]))
            return
        }
        var payload: Any = [["app_id": Preference.getAppId(), "apikey": Preference.getAccount()]
                                .merging(pin().map { ["f_pin": $0] } ?? [:]) { a, _ in a }]
        if let body { payload = body }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60
        let session = URLSession(configuration: config, delegate: PinnedURLSessionSSDelegate(), delegateQueue: nil)
        session.dataTask(with: request, completionHandler: completion).resume()
        // The session holds its delegate until invalidated; this lets it go after the one task.
        session.finishTasksAndInvalidate()
    }

    fileprivate static func pin() -> String? {
        let me: String? = SecureUserDefaultsSS.shared.value(forKey: "me")
        return (me?.isEmpty ?? true) ? nil : me
    }

    // MARK: - Alerts

    /// Puts a security alert on a window of its own, whatever else is on screen.
    static func present(_ alert: UIAlertController) {
        let show = {
            let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            guard let scene = scenes.first(where: { $0.activationState == .foregroundActive })
                    ?? scenes.first(where: { $0.activationState == .foregroundInactive })
                    ?? scenes.first else {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { present(alert) }
                return
            }
            let window = UIWindow(windowScene: scene)
            window.windowLevel = .alert + 2
            window.backgroundColor = .clear
            let host = UIViewController()
            host.view.backgroundColor = .clear
            window.rootViewController = host
            window.makeKeyAndVisible()
            alertWindows.append(window)
            (alert as? SSLibAlertController)?.hostWindow = window
            host.present(alert, animated: true)
        }
        if Thread.isMainThread { show() } else { DispatchQueue.main.async(execute: show) }
    }

    fileprivate static func alert(title: String, message: String) -> SSLibAlertController {
        let title = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let message = message.replacingOccurrences(of: "<br>", with: "\n")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        if title.isEmpty && message.isEmpty {
            return SSLibAlertController(title: "Keamanan",
                                        message: "Perangkat/jaringan/OS/aplikasi tidak memenuhi syarat keamanan.",
                                        preferredStyle: .alert)
        }
        return SSLibAlertController(title: title, message: message, preferredStyle: .alert)
    }

    fileprivate static var alertWindows: [UIWindow] = []

    fileprivate static func releaseAlertWindow(_ window: UIWindow) {
        window.isHidden = true
        window.rootViewController = nil
        alertWindows.removeAll { $0 === window }
    }
}

// MARK: - The chain

/*
 * Report codes (server side, shared with Android):
 *  1 multiple login · 2 call redirection · 3 SIM swap · 4 rooted · 5 emulator · 6 debugger
 *  7 screen capture/sharing · 12 outdated OS · 14 cloned · 15 overlay · 17 behavioural anomaly
 *  21/28 geovelocity · 22 hook/Frida
 */
private enum Chain {

    struct Finding {
        let title: String
        let message: String
        let action: String      // PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE or _EXIT
        let exitCode: Int32
        let reportCode: Int?
        let revokeReason: String?
    }

    enum Verdict { case clear, found(Finding) }

    typealias Step = (_ done: @escaping (Verdict) -> Void) -> Void

    /// The order is fixed here and only here; nothing outside this enum advances it.
    static let steps: [(name: String, run: Step)] = [
        ("emulator", sync(Checks.emulator)),
        ("rooted", sync(Checks.rooted)),
        ("outdated_os", sync(Checks.outdatedOS)),
        ("cloned", Checks.cloned),
        ("hooked", sync(Checks.hooked)),
        ("debugging", sync(Checks.debugging)),
        ("screen_casting", sync(Checks.screenCasting)),
        ("screen_overlay", sync(Checks.screenOverlay)),
        ("call_forward", sync(Checks.callForward)),
        ("multiple_login", sync(Checks.multipleLogin)),
        ("sim_swap", sync(Checks.simSwap)),
        ("geovelocity", Checks.geovelocity),
        ("behaviour", Checks.behaviour),
    ]

    private static func sync(_ check: @escaping () -> Verdict) -> Step {
        { done in done(check()) }
    }

    static func start() {
        Checks.installCaptureProtectionIfNeeded()
        DispatchQueue.global(qos: .userInitiated).async { advance(0) }
    }

    private static func advance(_ index: Int) {
        guard index < steps.count else {
            SecurityShield.finish(true)
            return
        }
        let step = steps[index]
        var answered = false
        let answerLock = NSLock()
        let answer: (Verdict) -> Void = { verdict in
            answerLock.lock()
            guard !answered else { answerLock.unlock(); return }
            answered = true
            answerLock.unlock()
            handle(verdict, step: step.name, next: index + 1)
        }
        // An asynchronous check that never answers (a location prompt left open, a request that
        // hangs past its own timeouts) must not park the whole app: past this, it counts as clear.
        DispatchQueue.global().asyncAfter(deadline: .now() + 45) {
            answerLock.lock()
            let pending = !answered
            answerLock.unlock()
            if pending { SecurityShield.log("\(step.name): tidak menjawab dalam 45 dtk - dianggap bersih") }
            answer(.clear)
        }
        step.run(answer)
    }

    private static func handle(_ verdict: Verdict, step: String, next: Int) {
        guard case .found(let finding) = verdict else {
            DispatchQueue.global(qos: .userInitiated).async { advance(next) }
            return
        }
        SecurityShield.log("\(step): terdeteksi (aksi \(finding.action == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE ? "lanjut" : "keluar"))")
        if let code = finding.reportCode { Reports.send(code: code) }
        if let reason = finding.revokeReason, NXSecurityPolicy.revokesOnRuntimeThreat() {
            APISZTA.revokeLocalAuthorization(reason: reason)
        }
        DispatchQueue.main.async {
            let alert = SecurityShield.alert(title: finding.title, message: finding.message)
            if finding.action == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE {
                alert.addAction(UIAlertAction(title: "OK", style: .default) { _ in
                    DispatchQueue.global(qos: .userInitiated).async { advance(next) }
                })
            } else {
                alert.addAction(UIAlertAction(title: "Exit", style: .default) { _ in
                    exit(finding.exitCode)
                })
            }
            SecurityShield.present(alert)
        }
    }
}

// MARK: - Checks

private enum Checks {

    private static func finding(_ title: String, _ message: String, _ action: String,
                                exit: Int32 = -141, report: Int?, revoke: String? = nil) -> Chain.Verdict {
        .found(.init(title: title, message: message, action: action, exitCode: exit,
                     reportCode: report, revokeReason: revoke))
    }

    // The native engine's findings, taken fresh.
    private static func nativeMask() -> UInt32 { UInt32(RASPGuard.shared().runChecksNow()) }
    private static func native(_ bits: Int32...) -> Bool {
        let mask = nativeMask()
        return bits.contains { mask & UInt32(bitPattern: $0) != 0 }
    }

    static func emulator() -> Chain.Verdict {
        guard Preference.getCheckEmulator(), isEmulator() else { return .clear }
        return finding(Preference.getCheckEmulatorAlertTitle(), Preference.getCheckEmulatorAlertMessage(),
                       Preference.getCheckEmulatorAction(), exit: -101, report: 5,
                       revoke: "SecurityShield emulator detection")
    }

    static func rooted() -> Chain.Verdict {
        guard Preference.getCheckRooted(), isRooted() || native(RASP_THREAT_JAILBREAK) else { return .clear }
        return finding(Preference.getCheckRootedAlertTitle(), Preference.getCheckRootedAlertMessage(),
                       Preference.getCheckRootedAction(), report: 4,
                       revoke: "SecurityShield jailbreak detection")
    }

    static func outdatedOS() -> Chain.Verdict {
        guard Preference.getCheckOutdatedOs() else { return .clear }
        let required = Preference.getMinimumOsVersion().trimmingCharacters(in: .whitespaces)
        // Numeric comparison: "15.10" is newer than "15.9", which a Double comparison got wrong.
        guard !required.isEmpty,
              UIDevice.current.systemVersion.compare(required, options: .numeric) == .orderedAscending else {
            return .clear
        }
        return finding(Preference.getCheckOutdatedOsAlertTitle(), Preference.getCheckOutdatedOsAlertMessage(),
                       Preference.getCheckOutdatedOsAction(), exit: -103, report: 12)
    }

    static func hooked() -> Chain.Verdict {
        guard Preference.getCheckHooked(),
              isHooked() || native(RASP_THREAT_FRIDA, RASP_THREAT_HOOK_DETECTED, RASP_THREAT_INLINE_HOOK,
                                   RASP_THREAT_GOT_HOOK, RASP_THREAT_INJECTION) else { return .clear }
        return finding(Preference.getCheckHookedAlertTitle(), Preference.getCheckHookedAlertMessage(),
                       Preference.getCheckHookedAction(), report: 22,
                       revoke: "SecurityShield hook detection")
    }

    static func debugging() -> Chain.Verdict {
        guard Preference.getCheckDebugging(), isDebugging() || native(RASP_THREAT_DEBUGGER) else { return .clear }
        return finding(Preference.getCheckDebuggingAlertTitle(), Preference.getCheckDebuggingAlertMessage(),
                       Preference.getCheckDebuggingAction(), report: 6,
                       revoke: "SecurityShield debugger detection")
    }

    static func screenCasting() -> Chain.Verdict {
        guard Preference.getCheckScreenCasting(), UIScreen.screens.count > 1 || UIScreen.main.isCaptured else {
            return .clear
        }
        return finding(Preference.getCheckScreenCastingAlertTitle(), Preference.getCheckScreenCastingAlertMessage(),
                       Preference.getCheckScreenCastingAction(), report: 7,
                       revoke: "SecurityShield screen-capture detection")
    }

    // iOS gives an app no way to see another app drawing over it, forwarding set on the carrier,
    // or a second login; these three answer from the server side or not at all.
    static func screenOverlay() -> Chain.Verdict { .clear }
    static func callForward() -> Chain.Verdict { .clear }
    static func multipleLogin() -> Chain.Verdict { .clear }

    static func simSwap() -> Chain.Verdict {
        guard Preference.getCheckSimSwap() else { return .clear }
        let current = simInfo()
        guard let saved: [String: [String: String]] = SecureUserDefaultsSS.shared.value(forKey: "SavedSIMInfo") else {
            SecureUserDefaultsSS.shared.set(current, forKey: "SavedSIMInfo")
            return .clear
        }
        guard saved != current else { return .clear }
        return finding(Preference.getCheckSimSwapAlertTitle(), Preference.getCheckSimSwapAlertMessage(),
                       Preference.getCheckSimSwapAction(), report: 3)
    }

    static func cloned(_ done: @escaping (Chain.Verdict) -> Void) {
        guard Preference.getCheckCloned() else { done(.clear); return }
        guard let team = teamIdentifier(),
              let url = URL(string: Preference.getDomainOpr() + "get_app_list") else {
            SecurityShield.log("cloned: Team ID tidak terbaca - dilewati")
            done(.clear); return
        }
        let body: [String: Any] = ["api_key": Preference.getAccount(), "app_id": Bundle.main.bundleIdentifier ?? "",
                                   "app_name": Preference.getAppId(), "team_id": team]
        SecurityShield.post(to: url, body: body) { data, response, error in
            guard (response as? HTTPURLResponse)?.statusCode == 200, error == nil, let data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  (json["error_code"] as? NSNumber)?.intValue == 1 else {
                done(.clear); return
            }
            done(finding(Preference.getCheckClonedAlertTitle(), Preference.getCheckClonedAlertMessage(),
                         Preference.getCheckClonedAction(), report: 14))
        }
    }

    static func geovelocity(_ done: @escaping (Chain.Verdict) -> Void) {
        guard Preference.getCheckGeoVelocity() else { done(.clear); return }
        LocationFetcher.shared.getCurrentLocation { _, score in
            guard score > 0 else { done(.clear); return }
            Reports.send(code: 28)
            done(finding(Preference.getCheckGeoVelocityAlertTitle(), Preference.getCheckGeoVelocityAlertMessage(),
                         Preference.getCheckGeoVelocityAction(), report: 21))
        }
    }

    static func behaviour(_ done: @escaping (Chain.Verdict) -> Void) {
        guard Preference.getCheckBehaviourAnalysis(),
              let url = URL(string: Preference.getDomainOpr() + "data_capture") else { done(.clear); return }
        DispatchQueue.global(qos: .utility).async {
            SecurityShield.post(to: url, body: DeviceAttributes.collect()) { data, response, error in
                guard (response as? HTTPURLResponse)?.statusCode == 200, error == nil, let data,
                      String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) == "ANOMALY_DETECTED" else {
                    done(.clear); return
                }
                done(finding(Preference.getCheckBehaviourAnalysisAlertTitle(),
                             Preference.getCheckBehaviourAnalysisAlertMessage(),
                             Preference.getCheckBehaviourAnalysisAction(), report: 17))
            }
        }
    }

    // MARK: Detectors

    private static func isEmulator() -> Bool {
        #if targetEnvironment(simulator)
        return true
        #else
        return ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil
            || native(RASP_THREAT_SIMULATOR)
        #endif
    }

    private static func isRooted() -> Bool {
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
                     "/Library/MobileSubstrate/MobileSubstrate.dylib", "/usr/lib/libhooker.dylib",
                     "/usr/lib/libsubstitute.dylib", "/usr/lib/ellekit", "/bin/bash", "/usr/sbin/sshd",
                     "/etc/apt", "/private/var/lib/apt/", "/var/jb", "/private/preboot/jb",
                     "/Applications/FakeApp.app"]
        if paths.contains(where: { FileManager.default.fileExists(atPath: $0) }) { return true }
        let probe = "/private/" + UUID().uuidString
        if (try? "test".write(toFile: probe, atomically: true, encoding: .utf8)) != nil {
            try? FileManager.default.removeItem(atPath: probe)
            return true
        }
        return false
    }

    private static func isDebugging() -> Bool {
        var name: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        guard sysctl(&name, UInt32(name.count), &info, &size, nil, 0) == 0 else { return false }
        return (info.kp_proc.p_flag & P_TRACED) != 0
    }

    private static func isHooked() -> Bool {
        let needles = ["fridagadget", "frida", "libsubstrate", "libcycript", "cyinject", "mobilesubstrate",
                       "sslkillswitch", "cydiasubstrate", "tweakinject", "0shadow", "shadow.dylib",
                       "libhooker", "substitute", "ellekit"]
        for i in 0 ..< _dyld_image_count() {
            guard let c = _dyld_get_image_name(i) else { continue }
            let name = String(cString: c).lowercased()
            if needles.contains(where: { name.contains($0) }) { return true }
        }
        return false
    }

    private static func simInfo() -> [String: [String: String]] {
        var out: [String: [String: String]] = [:]
        for (key, carrier) in CTTelephonyNetworkInfo().serviceSubscriberCellularProviders ?? [:] {
            out[key] = ["carrierName": carrier.carrierName ?? "Unknown",
                        "mobileCountryCode": carrier.mobileCountryCode ?? "Unknown",
                        "mobileNetworkCode": carrier.mobileNetworkCode ?? "Unknown",
                        "isoCountryCode": carrier.isoCountryCode ?? "Unknown"]
        }
        return out
    }

    /// The Team ID the app is signed with. It is not in Info.plist (the old lookup read
    /// "com.apple.developer.team-identifier" from there, found nothing, and so the clone check
    /// never ran); the keychain reports the access group - "<TeamID>.<bundle id>" - of an item
    /// this app writes.
    private static func teamIdentifier() -> String? {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                   kSecAttrAccount as String: "io.nexilis.securityshield.team",
                                   kSecAttrService as String: "io.nexilis.securityshield"]
        var query = base
        query[kSecReturnAttributes as String] = true
        var item: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            var add = base
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            add[kSecReturnAttributes as String] = true
            status = SecItemAdd(add as CFDictionary, &item)
        }
        guard status == errSecSuccess, let attrs = item as? [String: Any],
              let group = attrs[kSecAttrAccessGroup as String] as? String,
              let team = group.split(separator: ".").first, team.count == 10 else { return nil }
        return String(team)
    }

    // MARK: Capture protection

    private static var captureObserver: NSObjectProtocol?
    private static var blur: UIView?

    static func installCaptureProtectionIfNeeded() {
        guard Preference.getPreventKeylogger() || Preference.getPreventScreenCapture() else { return }
        DispatchQueue.main.async {
            guard captureObserver == nil else { return }
            captureObserver = NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification,
                                                                     object: nil, queue: .main) { _ in updateBlur() }
            updateBlur()
            // Screenshots: the window's layer is re-hosted inside a secure text field's layer,
            // which the system renders black in captures. Once the host's window exists.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                if let window = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
                    .flatMap({ $0.windows }).first(where: { $0.windowLevel == .normal }) {
                    makeSecure(window: window)
                }
            }
        }
    }

    private static func makeSecure(window: UIWindow) {
        let field = UITextField()
        let cover = UIView(frame: CGRect(x: 0, y: 0, width: field.frame.width, height: field.frame.height))
        let image = UIImageView(image: UIImage.imageWithColorSS(color: .black, size: UIScreen.main.bounds.size))
        image.frame = UIScreen.main.bounds
        field.isSecureTextEntry = true
        window.addSubview(field)
        cover.addSubview(image)
        window.layer.superlayer?.addSublayer(field.layer)
        field.layer.sublayers?.last?.addSublayer(window.layer)
        field.leftView = cover
        field.leftViewMode = .always
    }

    private static func updateBlur() {
        blur?.removeFromSuperview()
        blur = nil
        guard UIScreen.main.isCaptured,
              let window = UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene })
                .flatMap({ $0.windows }).first(where: { $0.isKeyWindow }) else { return }
        let view = UIVisualEffectView(effect: UIBlurEffect(style: .regular))
        view.frame = window.bounds
        view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        window.addSubview(view)
        blur = view
    }
}

// MARK: - Policy parsing

private enum Policy {

    /// Stores what the service sent. Defensive: the old parser force-unwrapped every field, so one
    /// malformed or unexpected answer crashed the app. Returns false when nothing usable arrived.
    static func apply(_ data: Data) -> Bool {
        guard let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return false }
        func text(_ d: [String: Any], _ k: String) -> String? {
            if let s = d[k] as? String { return s }
            if let n = d[k] as? NSNumber { return n.stringValue }
            return nil
        }
        typealias Setter = (Bool, String, String, String) -> Void
        let rules: [(String, Setter)] = [
            ("check_keylogger", { on, a, t, m in Preference.setPreventKeylogger(value: on); Preference.setPreventKeyloggerAction(value: a); Preference.setKeyloggerAlertTitle(value: t); Preference.setKeyloggerAlertMessage(value: m) }),
            ("check_screen_capture", { on, a, t, m in Preference.setPreventScreenCapture(value: on); Preference.setPreventScreenCaptureAction(value: a); Preference.setCheckScreenCaptureAlertTitle(value: t); Preference.setScreenCaptureAlertMessage(value: m) }),
            ("check_emulator", { on, a, t, m in Preference.setCheckEmulator(value: on); Preference.setCheckEmulatorAction(value: a); Preference.setCheckEmulatorAlertTitle(value: t); Preference.setCheckEmulatorAlertMessage(value: m) }),
            ("check_rooted_device", { on, a, t, m in Preference.setCheckRooted(value: on); Preference.setCheckRootedAction(value: a); Preference.setCheckRootedAlertTitle(value: t); Preference.setCheckRootedAlertMessage(value: m) }),
            ("check_outdated_os", { on, a, t, m in Preference.setCheckOutdatedOs(value: on); Preference.setCheckOutdatedOsAction(value: a); Preference.setCheckOutdatedOsAlertTitle(value: t); Preference.setCheckOutdatedOsAlertMessage(value: m) }),
            ("check_cloned_app", { on, a, t, m in Preference.setCheckCloned(value: on); Preference.setCheckClonedAction(value: a); Preference.setCheckClonedAlertTitle(value: t); Preference.setCheckClonedAlertMessage(value: m) }),
            ("check_hook", { on, a, t, m in Preference.setCheckHooked(value: on); Preference.setCheckHookedAction(value: a); Preference.setCheckHookedAlertTitle(value: t); Preference.setCheckHookedAlertMessage(value: m) }),
            ("check_usb_debugging", { on, a, t, m in Preference.setCheckDebugging(value: on); Preference.setCheckDebuggingAction(value: a); Preference.setCheckDebuggingAlertTitle(value: t); Preference.setCheckDebuggingAlertMessage(value: m) }),
            ("check_screen_casting", { on, a, t, m in Preference.setCheckScreenCasting(value: on); Preference.setCheckScreenCastingAction(value: a); Preference.setCheckScreenCastingAlertTitle(value: t); Preference.setCheckScreenCastingAlertMessage(value: m) }),
            ("check_screen_overlay", { on, a, t, m in Preference.setCheckScreenOverlay(value: on); Preference.setCheckScreenOverlayAction(value: a); Preference.setCheckScreenOverlayAlertTitle(value: t); Preference.setCheckScreenOverlayAlertMessage(value: m) }),
            ("check_call_forwarding", { on, a, t, m in Preference.setCheckCallForward(value: on); Preference.setCheckCallForwardAction(value: a); Preference.setCheckCallForwardAlertTitle(value: t); Preference.setCheckCallForwardAlertMessage(value: m) }),
            ("multiple_login", { on, a, t, m in Preference.setCheckMultipleLogin(value: on); Preference.setCheckMultipleLoginAction(value: a); Preference.setCheckMultipleLoginAlertTitle(value: t); Preference.setCheckMultipleLoginAlertMessage(value: m) }),
            ("check_sim_swap", { on, a, t, m in Preference.setCheckSimSwap(value: on); Preference.setCheckSimSwapAction(value: a); Preference.setCheckSimSwapAlertTitle(value: t); Preference.setCheckSimSwapAlertMessage(value: m) }),
            ("check_geovelocity", { on, a, t, m in Preference.setCheckGeoVelocity(value: on); Preference.setCheckGeoVelocityAction(value: a); Preference.setCheckGeoVelocityAlertTitle(value: t); Preference.setCheckGeoVelocityAlertMessage(value: m) }),
            ("behavioral_analysis", { on, a, t, m in Preference.setCheckBehaviourAnalysis(value: on); Preference.setCheckBehaviourAnalysisAction(value: a); Preference.setCheckBehaviourAnalysisAlertTitle(value: t); Preference.setCheckBehaviourAnalysisAlertMessage(value: m) }),
        ]
        var applied = false
        for entry in array {
            for (key, set) in rules {
                guard let flag = text(entry, key) else { continue }
                // An unknown action is treated as "exit": the safe reading of a policy we do not understand.
                let action = text(entry, "action") == PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE
                    ? PreferencesKey.SECURITY_SHIELD_ALERT_CONTINUE : PreferencesKey.SECURITY_SHIELD_ALERT_EXIT
                set(flag == "1", action, text(entry, "alert_title") ?? "", text(entry, "alert_message") ?? "")
                applied = true
            }
            if let minimum = text(entry, "minimum_ios_version") {
                Preference.setMinimumOsVersion(value: minimum)
                applied = true
            }
        }
        if applied { Preference.setPolicyReceived(value: true) }
        return applied
    }
}

// MARK: - Reports

private enum Reports {
    private static let lock = NSLock()
    private static var pending: [[String: Any]] = []

    /// Sends the finding with the device attributes the service correlates it with, as a JSON
    /// object to security_shield_logging - what the Android SDK's HTTPS path posts. Collected off
    /// the main thread: collection waits on a location fix that is delivered on the main thread.
    static func send(code: Int) {
        DispatchQueue.global(qos: .utility).async {
            var data = DeviceAttributes.collect()
            data["security_shield"] = "\(code)"
            if let pin = SecurityShield.pin() { data["f_pin"] = pin }
            deliver(data)
        }
    }

    static func flush() {
        lock.lock()
        let queued = pending
        pending = []
        lock.unlock()
        queued.forEach(deliver)
    }

    private static func deliver(_ report: [String: Any]) {
        guard let url = URL(string: Preference.getDomainOpr() + "security_shield_logging") else { return }
        SecurityShield.post(to: url, body: report) { _, response, error in
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard status != 200 || error != nil else { return }
            SecurityShield.log("laporan \(report["security_shield"] ?? "?") belum terkirim (HTTP \(status)) - disimpan untuk dicoba lagi")
            lock.lock()
            pending.append(report)
            if pending.count > 20 { pending.removeFirst(pending.count - 20) }
            lock.unlock()
        }
    }
}

// MARK: - Device attributes

private enum DeviceAttributes {
    static let vers = "5.0.52"

    /// Meant for a background queue: there it waits up to 10 s for a location fix delivered on
    /// the main thread. Called on the main thread it leaves the location out instead of freezing.
    static func collect() -> [String: Any] {
        collectDeviceAttributes()
    }

    private static func collectDeviceAttributes() -> [String: Any] {
        var params: [String: Any] = [:]

        // User and session
        let me: String? = SecureUserDefaultsSS.shared.value(forKey: "me")
        let sesId: String? = Preference.getConnectionID()
        params["f_pin"] = me
        params["session_id"] = sesId

        // App info (replace with your preferences retrieval)
        params["api"] = Preference.getAccount()
        params["app_id"] = Preference.getAppId()
        params["lib_version"] = vers
        params["app_version"] = vers

        // Network Info
        let (netType, netTypeName) = getNetworkType()
        let (operatorCode, operatorName) = getCarrierInfo()
        let (wifiStatus, wifiIp, wifiSsid, wifiBssid) = getWifiInfo()
        params["network_type"] = netType
        params["network_type_name"] = netTypeName
        params["network_operator"] = operatorCode
        params["network_operator_name"] = operatorName
        params["wifi_ssid"] = wifiSsid
        params["wifi_bssid"] = wifiBssid
        params["wifi_adapter"] = wifiStatus
        params["wifi_ip"] = wifiIp
        

        // IP Address
        params["ip_addressv4"] = getIPAddress(useIPv4: true)
        params["ip_address"] = getIPAddress(useIPv4: false)

        // GPS / location - only off the main thread, where the fix (delivered on main) can arrive.
        let semaphore = DispatchSemaphore(value: 0)
        if !Thread.isMainThread {
        
        DispatchQueue.main.async {
            LocationFetcher.shared.getCurrentLocation { coordinate, score in
                var long = "0"
                var lat = "0"
                if let coord = coordinate {
                    long = "\(coord.longitude)"
                    lat = "\(coord.latitude)"
                }
//                print("Latitude: \(lat), Longitude: \(long)")
                params["latitude"] = lat
                params["longitude"] = long
                semaphore.signal()
            }
        }
        
        _ = semaphore.wait(timeout: .now() + 10.0)
        }

        // iOS doesn't have an Android ID; use identifierForVendor
        params["ios_identifier"] = UIDevice.current.identifierForVendor?.uuidString ?? ""

        // Device attributes
        let device = UIDevice.current
        params["device_NAME"] = device.name
        params["device_MODEL"] = device.model
        params["device_SYSTEM_NAME"] = device.systemName
        params["device_SYSTEM_VERSION"] = device.systemVersion
        params["device_IDENTIFIER_FOR_VENDOR"] = device.identifierForVendor?.uuidString ?? ""

        return getSimData(params: params)
    }
    
    private static func getSimData(params: [String: Any] = [:]) -> [String: Any] {
        var params = params
        var simArray: [[String: Any]] = []

        let networkInfo = CTTelephonyNetworkInfo()

        if #available(iOS 12.0, *) {
            if let carriers = networkInfo.serviceSubscriberCellularProviders {
                for (key, carrier) in carriers {
                    var simInfo: [String: Any] = [:]
                    simInfo["carrier_name"] = carrier.carrierName ?? ""
                    simInfo["mcc"] = carrier.mobileCountryCode ?? ""
                    simInfo["mnc"] = carrier.mobileNetworkCode ?? ""
                    simInfo["sim_slot"] = key // This is not a true "slot", but the key used internally
                    simArray.append(simInfo)
                }
            }
        } else {
            if let carrier = networkInfo.subscriberCellularProvider {
                var simInfo: [String: Any] = [:]
                simInfo["carrier_name"] = carrier.carrierName ?? ""
                simInfo["mcc"] = carrier.mobileCountryCode ?? ""
                simInfo["mnc"] = carrier.mobileNetworkCode ?? ""
                simInfo["sim_slot"] = "default"
                simArray.append(simInfo)
            }
        }
        params["sim_data"] = simArray

        return params
    }
    
    private static func getNetworkType() -> (type: String, name: String) {
        let monitor = NWPathMonitor()
        var networkType = ""
        var networkTypeName = ""
        
        let semaphore = DispatchSemaphore(value: 0)
        monitor.pathUpdateHandler = { path in
            if path.usesInterfaceType(.wifi) {
                networkType = "1" // Corresponds to TYPE_WIFI in Android
                networkTypeName = "WIFI"
            } else if path.usesInterfaceType(.cellular) {
                networkType = "0" // Corresponds to TYPE_MOBILE
                networkTypeName = "MOBILE"
            } else {
                networkType = "-1"
                networkTypeName = "UNKNOWN"
            }
            semaphore.signal()
            monitor.cancel()
        }
        let queue = DispatchQueue(label: "NetworkMonitor")
        monitor.start(queue: queue)
        _ = semaphore.wait(timeout: .now() + 2)
        
        return (networkType, networkTypeName)
    }
    
    private static func getCarrierInfo() -> (operatorCode: String, operatorName: String) {
        let networkInfo = CTTelephonyNetworkInfo()
        
        var carrierCode = ""
        var carrierName = ""
        
        if #available(iOS 12.0, *) {
            if let carriers = networkInfo.serviceSubscriberCellularProviders {
                for (_, carrier) in carriers {
                    carrierCode = (carrier.mobileCountryCode ?? "") + (carrier.mobileNetworkCode ?? "")
                    carrierName = carrier.carrierName ?? ""
                    break // Just use the first one
                }
            }
        } else {
            if let carrier = networkInfo.subscriberCellularProvider {
                carrierCode = (carrier.mobileCountryCode ?? "") + (carrier.mobileNetworkCode ?? "")
                carrierName = carrier.carrierName ?? ""
            }
        }
        
        return (carrierCode, carrierName)
    }
    
    private static func getWifiInfo() -> (adapter: String, ip: String, ssid: String, bssid: String) {
        var adapterStatus = "Off"
        var ipAddress = ""
        var ssid = ""
        var bssid = ""
        
        // Get IP Address
        if let interfaces = CNCopySupportedInterfaces() as NSArray? {
            for interfaceName in interfaces {
                if let unsafeInterfaceData = CNCopyCurrentNetworkInfo(interfaceName as! CFString) as NSDictionary? {
                    ssid = unsafeInterfaceData["SSID"] as? String ?? ""
                    bssid = unsafeInterfaceData["BSSID"] as? String ?? ""
                    adapterStatus = "Connected"
                    break
                }
            }
        }
        
        if ssid.isEmpty {
            adapterStatus = "Not Connected"
        }

        ipAddress = getWiFiIPAddress() ?? ""

        return (adapterStatus, ipAddress, ssid, bssid)
    }

    private static func getWiFiIPAddress() -> String? {
        var address: String?

        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return nil }

        for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
            let interface = ptr.pointee
            let addrFamily = interface.ifa_addr.pointee.sa_family

            if addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) {
                let name = String(cString: interface.ifa_name)
                if name == "en0" { // en0 is Wi-Fi
                    var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    getnameinfo(interface.ifa_addr, socklen_t(interface.ifa_addr.pointee.sa_len),
                                &hostname, socklen_t(hostname.count),
                                nil, socklen_t(0), NI_NUMERICHOST)
                    address = String(cString: hostname)
                    break
                }
            }
        }

        freeifaddrs(ifaddr)
        return address
    }
    
    private static func getIPAddress(useIPv4: Bool) -> String {
        var address: String = ""

        var ifaddr: UnsafeMutablePointer<ifaddrs>? = nil
        if getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr {
            for ptr in sequence(first: firstAddr, next: { $0.pointee.ifa_next }) {
                let interface = ptr.pointee
                let addrFamily = interface.ifa_addr.pointee.sa_family

                if addrFamily == UInt8(AF_INET) || addrFamily == UInt8(AF_INET6) {
                    let name = String(cString: interface.ifa_name)
                    if name == "en0" || name == "pdp_ip0" {
                        var hostname = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                        let result = getnameinfo(
                            interface.ifa_addr,
                            socklen_t(interface.ifa_addr.pointee.sa_len),
                            &hostname,
                            socklen_t(hostname.count),
                            nil,
                            socklen_t(0),
                            NI_NUMERICHOST
                        )

                        if result == 0 {
                            let ip = String(cString: hostname)
                            let isIPv4 = ip.contains(":") == false
                            if useIPv4 && isIPv4 {
                                address = ip
                                break
                            } else if !useIPv4 && !isIPv4 {
                                // Remove IPv6 scope if present
                                let cleanIPv6 = ip.split(separator: "%").first.map(String.init) ?? ip
                                address = cleanIPv6.uppercased()
                                break
                            }
                        }
                    }
                }
            }
            freeifaddrs(ifaddr)
        }

        return address
    }
}

private class LocationFetcher: NSObject, CLLocationManagerDelegate {
    static var shared = LocationFetcher()
    private var manager: CLLocationManager?
    private var completion: ((CLLocationCoordinate2D?, Int) -> Void)?
    let motionMgr = CMMotionActivityManager()
    
    func motionSnapshot(_ done: @escaping (CMMotionActivity?) -> Void) {
        guard CMMotionActivityManager.isActivityAvailable() else {
            done(nil)
            return
        }
        let now = Date()
        motionMgr.queryActivityStarting(from: now.addingTimeInterval(-120), to: now, to: .main) { acts, _ in
            done(acts?.last)
        }
    }
    
    /// Fix: this asked `CLLocationManager.locationServicesEnabled()` before requesting anything.
    /// That call reaches the location daemon and can sit there, which on the main thread is a
    /// frozen screen - the runtime issue "This method can cause UI unresponsiveness if invoked on
    /// the main thread". Both callers hand this work to the main queue, so it was being asked in
    /// exactly the place Apple warns about.
    ///
    /// Nothing needs to be asked up front. Setting the delegate makes the system report the
    /// current authorization through `locationManagerDidChangeAuthorization`, which is where the
    /// request starts from now; the services-off case that this used to catch arrives there as
    /// denied, or through `didFailWithError` if authorization is held but the services are not on.
    func getCurrentLocation(completion: @escaping (CLLocationCoordinate2D?, Int) -> Void) {
        let start = {
            self.completion = completion
            let manager = CLLocationManager()
            self.manager = manager
            manager.desiredAccuracy = kCLLocationAccuracyBest
            manager.delegate = self
            manager.requestWhenInUseAuthorization()
        }
        // A CLLocationManager wants a thread with a run loop, or its delegate is never called.
        if Thread.isMainThread {
            start()
        } else {
            DispatchQueue.main.async(execute: start)
        }
    }

    /// Hands the result over once and once only - the authorization callback and a failure can
    /// both land for the same request.
    private func finish(_ coordinate: CLLocationCoordinate2D?, _ score: Int) {
        guard let completion = self.completion else {
            return
        }
        self.completion = nil
        completion(coordinate, score)
    }

    // MARK: - CLLocationManagerDelegate
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        switch manager.authorizationStatus {
        case .authorizedWhenInUse, .authorizedAlways:
            manager.requestLocation()
        case .denied, .restricted:
            finish(nil, 0)
            cleanup()
        case .notDetermined:
            // The prompt is on screen; this is called again with whatever the user answers.
            break
        @unknown default:
            finish(nil, 0)
            cleanup()
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        motionSnapshot { snap in
            guard let last = locations.last else {
                self.finish(nil, 0)
                return
            }
            let (gpsScore, _) = FakeGps.movementAndAccuracy(prev: locations.first, curr: last, motion: snap)
            self.finish(last.coordinate, gpsScore)
        }
//        cleanup()
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        finish(nil, 0)
        cleanup()
    }
    
    private func cleanup() {
        manager?.stopUpdatingLocation()
        manager?.delegate = nil
        manager = nil
        completion = nil
    }
    
    enum FakeGps {
        static func movementAndAccuracy(prev: CLLocation?, curr: CLLocation, motion: CMMotionActivity?) -> (Int, [String]) {
            var score = 0
            var reasons: [String] = []
            
            // Accuracy check
            if curr.horizontalAccuracy > 200 {
                score += 10
                reasons.append("Low accuracy (>200m).")
            }
            
            // Movement checks
            if let p = prev {
                let dt = curr.timestamp.timeIntervalSince(p.timestamp)
                if dt >= 3 {
                    let d = curr.distance(from: p)
                    let v = d / dt
                    let vRep = curr.speed > 0 ? Double(curr.speed) : v
                    
                    if v > 150 && vRep < 10 {
                        score += 40
                        reasons.append("Unrealistic jump vs reported speed.")
                    }
                    
                    if v > 350 {
                        score += 60
                        reasons.append("Physically implausible speed (>350 m/s).")
                    }
                    
                    if curr.horizontalAccuracy <= 8 && d > 1000 {
                        score += 20
                        reasons.append("High accuracy but >1 km jump.")
                    }
                    
                    if p.courseAccuracy >= 0 && curr.courseAccuracy >= 0 {
                        let delta = abs(curr.course - p.course)
                        if delta < 1 && d > 3000 {
                            score += 10
                            reasons.append("Near-zero course jitter over long distance.")
                        }
                    }
                    
                    // NEW: unnatural smoothness
                    let speedDiff = abs(curr.speed - Double(v))
                    if speedDiff < 0.5 && d > 100 {
                        score += 10
                        reasons.append("Unnaturally smooth trajectory.")
                    }
                }
            }
            
            // Motion vs GPS mismatch
            if let m = motion {
                let moving = (m.walking || m.running || m.cycling || m.automotive)
                if !moving && curr.speed > 8 {
                    score += 20
                    reasons.append("High speed while motion reports stationary.")
                }
            }
            
            // Timezone mismatch check
            let deviceTZ = TimeZone.current
            let gpsTZ = TimeZone(secondsFromGMT: Int(curr.timestamp.timeIntervalSince1970)) // heuristic only
            if let gpsTZ = gpsTZ, gpsTZ.secondsFromGMT() != deviceTZ.secondsFromGMT() {
                score += 5
                reasons.append("Timezone mismatch with GPS region (heuristic).")
            }
            
            return (min(100, score), reasons)
        }
    }
}

private class Preference {
    /// Set once any policy was stored. Before that - a first launch with no route to the policy
    /// service - modes 1 and 2 run the device-integrity checks (emulator, jailbreak, hook,
    /// debugger) with "exit" rather than running nothing at all. Mode 3 keeps the old reading.
    static func setPolicyReceived(value: Bool) {
        SecureUserDefaultsSS.shared.set(value, forKey: "ss_policy_received")
    }

    static func getPolicyReceived() -> Bool {
        (SecureUserDefaultsSS.shared.value(forKey: "ss_policy_received") as Bool?) ?? false
    }

    static var integrityBaseline: Bool {
        !getPolicyReceived() && NXSecurityPolicy.requiresServerChain()
    }

    static func setConnectionID(value: String) {
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CONNECTION_ID)
    }

    static func getConnectionID() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CONNECTION_ID) {
            return value
        }
        return ""
    }
    static func getAppId() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_USER_APP_ID) {
            return value
        }
        return ""
    }
    
    static func setAppId(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_USER_APP_ID)
    }
    
    static func getAccount() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_USER_ACCOUNT) {
            return value
        }
        return ""
    }
    
    static func setAccount(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_USER_ACCOUNT)
    }
    
    static func setDomainOpr(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_DOMAIN_OPR)
    }
    
    static func getDomainOpr() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_DOMAIN_OPR) {
            return value
        }
        return "https://nexilis.io/"
    }
    
    static func setIpPortOpr(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_IP_PORT_OPR)
    }
    
    static func getIpOpr() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_IP_PORT_OPR) {
            return value
        }
        return "34.101.172.194:42823"
    }
    
    /**
     * Keylogger
     */
    static func setPreventKeylogger(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER)
    }
    
    static func getPreventKeylogger() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER) {
            return value
        }
        return false
    }
    static func setPreventKeyloggerAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ACTION)
    }
    
    static func getPreventKeyloggerAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ACTION) {
            return value
        }
        return "0"
    }
    static func setKeyloggerAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_TITLE)
    }
    
    static func getKeyloggerAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_title
            }
            return value
        }
        return PreferencesKey.ss_screenshare_title
    }
    static func setKeyloggerAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_MESSAGE)
    }
    
    static func getKeyloggerAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_KEYLOGGER_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_warning
            }
            return value
        }
        return PreferencesKey.ss_screenshare_warning
    }
    /**
     * Screen Capture
     */
    static func setPreventScreenCapture(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE)
    }
    
    static func getPreventScreenCapture() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE) {
            return value
        }
        return false
    }
    static func setPreventScreenCaptureAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ACTION)
    }
    
    static func getPreventScreenCaptureAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenCaptureAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE)
    }
    
    static func getCheckScreenCaptureAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_title
            }
            return value
        }
        return PreferencesKey.ss_screenshare_title
    }
    static func setScreenCaptureAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE)
    }
    
    static func getScreenCaptureAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenshare_warning
            }
            return value
        }
        return PreferencesKey.ss_screenshare_warning
    }
    /**
     * Emulator
     */
    static func setCheckEmulator(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR)
    }
    
    static func getCheckEmulator() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR) {
            return value
        }
        return integrityBaseline
    }
    static func setCheckEmulatorAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ACTION)
    }
    
    static func getCheckEmulatorAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckEmulatorAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_TITLE)
    }
    
    static func getCheckEmulatorAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_emulator_title
            }
            return value
        }
        return PreferencesKey.ss_emulator_title
    }
    static func setCheckEmulatorAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_MESSAGE)
    }
    
    static func getCheckEmulatorAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_EMULATOR_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_emulator_continue
            }
            return value
        }
        return PreferencesKey.ss_emulator_continue
    }
    
    /**
     * Root/Jailbreak Detection
     */
    static func setCheckRooted(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED)
    }
    
    static func getCheckRooted() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED) {
            return value
        }
        return integrityBaseline
    }
    static func setCheckRootedAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION)
    }
    
    static func getCheckRootedAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckRootedAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_TITLE)
    }
    
    static func getCheckRootedAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_rooted_title
            }
            return value
        }
        return PreferencesKey.ss_rooted_title
    }
    static func setCheckRootedAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_MESSAGE)
    }
    
    static func getCheckRootedAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_rooted_warning
            }
            return value
        }
        return PreferencesKey.ss_rooted_warning
    }
    
    /**
     * Outdated OS Detection
     */
    static func setCheckOutdatedOs(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS)
    }
    
    static func getCheckOutdatedOs() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS) {
            return value
        }
        return false
    }
    static func setCheckOutdatedOsAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION)
    }
    
    static func getCheckOutdatedOsAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_ROOTED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckOutdatedOsAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_TITLE)
    }
    
    static func getCheckOutdatedOsAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_os_not_supported_title
            }
            return value
        }
        return PreferencesKey.ss_os_not_supported_title
    }
    static func setCheckOutdatedOsAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_MESSAGE)
    }
    
    static func getCheckOutdatedOsAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_OUTDATED_OS_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_os_not_supported_continue
            }
            return value
        }
        return PreferencesKey.ss_os_not_supported_continue
    }
    static func setMinimumOsVersion(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MINIMUM_OS_VERSION)
    }
    
    static func getMinimumOsVersion() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MINIMUM_OS_VERSION) {
            return value
        }
        return "14"
    }
    
    /**
     * Tempering Detection
     */
    static func setCheckTempering(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING)
    }
    
    static func getCheckTempering() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING) {
            return value
        }
        return false
    }
    static func setCheckTemperingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ACTION)
    }
    
    static func getCheckTemperingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckTemperingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_TITLE)
    }
    
    static func getCheckTemperingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_tempering_title
            }
            return value
        }
        return PreferencesKey.ss_tempering_title
    }
    static func setCheckTemperingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_MESSAGE)
    }
    
    static func getCheckTemperingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_TEMPERING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_tempering_warning
            }
            return value
        }
        return PreferencesKey.ss_tempering_warning
    }
    
    /**
     * Debugging Detection
     */
    static func setCheckDebugging(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING)
    }
    
    static func getCheckDebugging() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING) {
            return value
        }
        return integrityBaseline
    }
    static func setCheckDebuggingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ACTION)
    }
    
    static func getCheckDebuggingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckDebuggingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_TITLE)
    }
    
    static func getCheckDebuggingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_title
            }
            return value
        }
        return PreferencesKey.ss_debugging_title
    }
    static func setCheckDebuggingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_MESSAGE)
    }
    
    static func getCheckDebuggingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_DEBUGGING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_warning
            }
            return value
        }
        return PreferencesKey.ss_debugging_warning
    }
    
    /**
     * Screen Casting
     */
    static func setCheckScreenCasting(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING)
    }
    
    static func getCheckScreenCasting() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING) {
            return value
        }
        return false
    }
    static func setCheckScreenCastingAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ACTION)
    }
    
    static func getCheckScreenCastingAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenCastingAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_TITLE)
    }
    
    static func getCheckScreenCastingAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_title
            }
            return value
        }
        return PreferencesKey.ss_debugging_title
    }
    static func setCheckScreenCastingAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE)
    }
    
    static func getCheckScreenCastingAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_debugging_warning
            }
            return value
        }
        return PreferencesKey.ss_debugging_warning
    }
    
    /**
     * Screen Overlay
     */
    static func setCheckScreenOverlay(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY)
    }
    
    static func getCheckScreenOverlay() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY) {
            return value
        }
        return false
    }
    static func setCheckScreenOverlayAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ACTION)
    }
    
    static func getCheckScreenOverlayAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckScreenOverlayAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE)
    }
    
    static func getCheckScreenOverlayAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenoverlay_title
            }
            return value
        }
        return PreferencesKey.ss_screenoverlay_title
    }
    static func setCheckScreenOverlayAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE)
    }
    
    static func getCheckScreenOverlayAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_screenoverlay_continue
            }
            return value
        }
        return PreferencesKey.ss_screenoverlay_continue
    }
    
    /**
     * Call Redirection Detection
     */
    static func setCheckCallForward(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD)
    }
    
    static func getCheckCallForward() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD) {
            return value
        }
        return false
    }
    static func setCheckCallForwardAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ACTION)
    }
    
    static func getCheckCallForwardAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckCallForwardAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_TITLE)
    }
    
    static func getCheckCallForwardAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_callforward_title
            }
            return value
        }
        return PreferencesKey.ss_callforward_title
    }
    static func setCheckCallForwardAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_MESSAGE)
    }
    
    static func getCheckCallForwardAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CALL_FORWARD_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_callforward_continue
            }
            return value
        }
        return PreferencesKey.ss_callforward_continue
    }
    
    /**
     * Multiple Login Detection
     */
    static func setCheckMultipleLogin(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN)
    }
    
    static func getCheckMultipleLogin() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN) {
            return value
        }
        return false
    }
    static func setCheckMultipleLoginAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ACTION)
    }
    
    static func getCheckMultipleLoginAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckMultipleLoginAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE)
    }
    
    static func getCheckMultipleLoginAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_multiple_login_title
            }
            return value
        }
        return PreferencesKey.ss_multiple_login_title
    }
    static func setCheckMultipleLoginAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE)
    }
    
    static func getCheckMultipleLoginAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_multiple_login_warning
            }
            return value
        }
        return PreferencesKey.ss_multiple_login_warning
    }
    
    /**
     * SIM Swap Detection
     */
    static func setCheckSimSwap(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP)
    }
    
    static func getCheckSimSwap() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP) {
            return value
        }
        return false
    }
    static func setCheckSimSwapAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ACTION)
    }
    
    static func getCheckSimSwapAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckSimSwapAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_TITLE)
    }
    
    static func getCheckSimSwapAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_simswap_title
            }
            return value
        }
        return PreferencesKey.ss_simswap_title
    }
    static func setCheckSimSwapAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_MESSAGE)
    }
    
    static func getCheckSimSwapAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_SIM_SWAP_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_simswap_warning
            }
            return value
        }
        return PreferencesKey.ss_simswap_warning
    }
    
    /**
     * Geo-Velocity Checks
     */
    static func setCheckGeoVelocity(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY)
    }
    
    static func getCheckGeoVelocity() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY) {
            return value
        }
        return false
    }
    static func setCheckGeoVelocityAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ACTION)
    }
    
    static func getCheckGeoVelocityAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckGeoVelocityAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_TITLE)
    }
    
    static func getCheckGeoVelocityAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_geo_velocity_title
            }
            return value
        }
        return PreferencesKey.ss_geo_velocity_title
    }
    static func setCheckGeoVelocityAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE)
    }
    
    static func getCheckGeoVelocityAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_geo_velocity_warning
            }
            return value
        }
        return PreferencesKey.ss_geo_velocity_warning
    }
    
    /**
     * Behavioral Anomaly Detection
     */
    static func setCheckBehaviourAnalysis(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS)
    }
    
    static func getCheckBehaviourAnalysis() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS) {
            return value
        }
        return false
    }
    static func setCheckBehaviourAnalysisAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION)
    }
    
    static func getCheckBehaviourAnalysisAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckBehaviourAnalysisAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE)
    }
    
    static func getCheckBehaviourAnalysisAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_behaviour_anomaly_title
            }
            return value
        }
        return PreferencesKey.ss_behaviour_anomaly_title
    }
    static func setCheckBehaviourAnalysisAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE)
    }
    
    static func getCheckBehaviourAnalysisAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_behaviour_anomaly_warning
            }
            return value
        }
        return PreferencesKey.ss_behaviour_anomaly_warning
    }
    
    /**
     * Hooked Detection
     */
    static func setCheckHooked(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED)
    }
    
    static func getCheckHooked() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED) {
            return value
        }
        return integrityBaseline
    }
    static func setCheckHookedAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ACTION)
    }
    
    static func getCheckHookedAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckHookedAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_TITLE)
    }
    
    static func getCheckHookedAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_hooked_title
            }
            return value
        }
        return PreferencesKey.ss_hooked_title
    }
    static func setCheckHookedAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_MESSAGE)
    }
    
    static func getCheckHookedAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_HOOKED_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_hooked_warning
            }
            return value
        }
        return PreferencesKey.ss_hooked_warning
    }
    
    /**
     * Cloned Detection
     */
    static func setCheckCloned(value: Bool){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CLONED)
    }
    
    static func getCheckCloned() -> Bool {
        if let value: Bool = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CLONED) {
            return value
        }
        return false
    }
    static func setCheckClonedAction(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CLONED_ACTION)
    }
    
    static func getCheckClonedAction() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CLONED_ACTION) {
            return value
        }
        return "0"
    }
    static func setCheckClonedAlertTitle(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CLONED_ALERT_TITLE)
    }
    
    static func getCheckClonedAlertTitle() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CLONED_ALERT_TITLE) {
            if value.isEmpty {
                return PreferencesKey.ss_clone_title
            }
            return value
        }
        return PreferencesKey.ss_clone_title
    }
    static func setCheckClonedAlertMessage(value: String){
        SecureUserDefaultsSS.shared.set(value, forKey: PreferencesKey.SS_CHECK_CLONED_ALERT_MESSAGE)
    }
    
    static func getCheckClonedAlertMessage() -> String {
        if let value: String = SecureUserDefaultsSS.shared.value(forKey: PreferencesKey.SS_CHECK_CLONED_ALERT_MESSAGE) {
            if value.isEmpty {
                return PreferencesKey.ss_clone_continue
            }
            return value
        }
        return PreferencesKey.ss_clone_continue
    }
    
}

private class PreferencesKey {
    static let SECURITY_SHIELD_ALERT_EXIT = "0"
    static let SECURITY_SHIELD_ALERT_CONTINUE = "1"
    
    static let ERR121 = "121:Emulator detected"
    static let ERR122 = "122:Malware detected"
    static let ERR123 = "123:USB/WiFi debugging detected"
    static let ERR124 = "124:Cloned app detected"
    static let ERR125 = "125:Call forwarding detected"
    static let ERR126 = "126:Screen sharing detected"
    static let ERR127 = "127:OS Version not supported"
    static let ERR128 = "128:Application backup detected"
    static let ERR129 = "129:Failed security reasons"
    static let ERR130 = "130:Tampering detected"
    static let ERR131 = "131:SIM Swap detected"
    static let ERR132 = "132:Behavioral Anomaly detected"
    
    static let SS_CONNECTION_ID = "ss_connection_id"
    
    static let SS_USER_APP_ID = "ss_user_app_id"
    static let SS_USER_ACCOUNT = "ss_user_account"
    static let SS_DOMAIN_OPR = "domain_opr"
    static let SS_IP_PORT_OPR = "ip_opr"
    
    static let SS_CHECK_KEYLOGGER = "ss_check_keylogger"
    static let SS_CHECK_KEYLOGGER_ACTION = "ss_check_keylogger_action"
    static let SS_CHECK_KEYLOGGER_ALERT_TITLE = "ss_check_keylogger_alert_title"
    static let SS_CHECK_KEYLOGGER_ALERT_MESSAGE = "ss_check_keylogger_alert_message"

    static let SS_CHECK_SCREEN_CAPTURE = "ss_check_screen_capture"
    static let SS_CHECK_SCREEN_CAPTURE_ACTION = "ss_check_screen_capture_action"
    static let SS_CHECK_SCREEN_CAPTURE_ALERT_TITLE = "ss_check_screen_capture_alert_title"
    static let SS_CHECK_SCREEN_CAPTURE_ALERT_MESSAGE = "ss_check_screen_capture_alert_message"
    static let ss_screenshare_title = "Screen Sharing Detected!"
    static let ss_screenshare_warning = "We are sorry for the inconvenience. For security reasons this app is not allowed to cast/share screen display. The application will automatically stop.<br><br>To try again, please stop the screen casting/sharing."
        
    
    static let SS_CHECK_EMULATOR = "ss_check_emulator"
    static let SS_CHECK_EMULATOR_ACTION = "ss_check_emulator_action"
    static let SS_CHECK_EMULATOR_ALERT_TITLE = "ss_check_emulator_alert_title"
    static let SS_CHECK_EMULATOR_ALERT_MESSAGE = "ss_check_emulator_alert_message"
    static let ss_emulator_title = "Emulator Detected!"
    static let ss_emulator_continue = "We are sorry for the inconvenience. For security reasons this app is not allowed to run on an emulator."
    
    static let SS_CHECK_ROOTED = "ss_check_rooted"
    static let SS_CHECK_ROOTED_ACTION = "ss_check_rooted_action"
    static let SS_CHECK_ROOTED_ALERT_TITLE = "ss_check_rooted_alert_title"
    static let SS_CHECK_ROOTED_ALERT_MESSAGE = "ss_check_rooted_alert_message"
    static let ss_rooted_title = "Root or Jailbreak Detected!"
    static let ss_rooted_warning = "The operating system on your device has been modified unauthorizedly(the root). The modification might compromise secure access to organizational resources such as email and documents.<br><br> %app_name% will not work on your device. Please reset/unroot your device or contact %app_name% customer center for further information. We apologize for the inconvenient."
    
    static let SS_CHECK_OUTDATED_OS = "ss_check_outdated_os"
    static let SS_CHECK_OUTDATED_OS_ACTION = "ss_check_outdated_os_action"
    static let SS_CHECK_OUTDATED_OS_ALERT_TITLE = "ss_check_outdated_os_alert_title"
    static let SS_CHECK_OUTDATED_OS_ALERT_MESSAGE = "ss_check_outdated_os_alert_message"
    static let SS_CHECK_MINIMUM_OS_VERSION = "ss_minimum_os_version"
    static let ss_os_not_supported_title = "Android Version Not Secure!"
    static let ss_os_not_supported_continue = "We are sorry for the inconvenience. This device's Android version has been deemed as no longer secure."
    
    static let SS_CHECK_TEMPERING = "ss_check_tempering"
    static let SS_CHECK_TEMPERING_ACTION = "ss_check_tempering_action"
    static let SS_CHECK_TEMPERING_ALERT_TITLE = "ss_check_tempering_alert_title"
    static let SS_CHECK_TEMPERING_ALERT_MESSAGE = "ss_check_tempering_alert_message"
    static let ss_tempering_title = "Tempering Detected!"
    static let ss_tempering_warning = "Our security shield has detected changes in the application that may indicate tempering, which could potentially lead to malware infection, data manipulation, and other risks. Please remove this apps and download from official Google Play Store."
    
    static let SS_CHECK_DEBUGGING = "ss_check_debugging"
    static let SS_CHECK_DEBUGGING_ACTION = "ss_check_debugging_action"
    static let SS_CHECK_DEBUGGING_ALERT_TITLE = "ss_check_debugging_alert_title"
    static let SS_CHECK_DEBUGGING_ALERT_MESSAGE = "ss_check_debugging_alert_message"
    static let ss_debugging_title = "Debugging Mode Detected!"
    static let ss_debugging_warning = "Your device running on debugging mode. Please disable it."
    
    static let SS_CHECK_SCREEN_CASTING = "ss_check_screen_casting"
    static let SS_CHECK_SCREEN_CASTING_ACTION = "ss_check_screen_casting_action"
    static let SS_CHECK_SCREEN_CASTING_ALERT_TITLE = "ss_check_screen_casting_alert_title"
    static let SS_CHECK_SCREEN_CASTING_ALERT_MESSAGE = "ss_check_screen_casting_alert_message"
    
    static let SS_CHECK_SCREEN_OVERLAY = "ss_check_screen_overlay"
    static let SS_CHECK_SCREEN_OVERLAY_ACTION = "ss_check_screen_overlay_action"
    static let SS_CHECK_SCREEN_OVERLAY_ALERT_TITLE = "ss_check_screen_overlay_alert_title"
    static let SS_CHECK_SCREEN_OVERLAY_ALERT_MESSAGE = "ss_check_screen_overlay_alert_message"
    static let ss_screenoverlay_title = "Screen Overlay Detected!"
    static let ss_screenoverlay_continue = "We are sorry for the inconvenience. For security reasons this app is not allowed to share screen overlay. Please stop the screen overlay in app setting."
    
    static let SS_CHECK_CALL_FORWARD = "ss_check_call_forward"
    static let SS_CHECK_CALL_FORWARD_ACTION = "ss_check_call_forward_action"
    static let SS_CHECK_CALL_FORWARD_ALERT_TITLE = "ss_check_call_forward_alert_title"
    static let SS_CHECK_CALL_FORWARD_ALERT_MESSAGE = "ss_check_call_forward_alert_message"
    static let ss_callforward_title = "Call Forwarding Detected!";
    static let ss_callforward_continue = "We are sorry for the inconvenience. For security reasons this app does not recommend allowing call forwarding to be active.";
    
    static let SS_CHECK_MULTIPLE_LOGIN = "ss_check_multiple_login"
    static let SS_CHECK_MULTIPLE_LOGIN_ACTION = "ss_check_multiple_login_action"
    static let SS_CHECK_MULTIPLE_LOGIN_ALERT_TITLE = "ss_check_multiple_login_alert_title"
    static let SS_CHECK_MULTIPLE_LOGIN_ALERT_MESSAGE = "ss_check_multiple_login_alert_message"
    static let ss_multiple_login_title = "Multiple Login Detected!"
    static let ss_multiple_login_warning = "We have detected multiple login attempts to your account from different devices or locations within a short period. This alert is designed to protect your account and ensure your security.<br><br> If you initiated these logins, no further action is required. However, if you did not authorize this activity, it is crucial to take immediate steps to safeguard your account. Unauthorized access may put your personal information at risk."
    
    static let SS_CHECK_SIM_SWAP = "ss_check_sim_swap"
    static let SS_CHECK_SIM_SWAP_ACTION = "ss_check_sim_swap_action"
    static let SS_CHECK_SIM_SWAP_ALERT_TITLE = "ss_check_sim_swap_alert_title"
    static let SS_CHECK_SIM_SWAP_ALERT_MESSAGE = "ss_check_sim_swap_alert_message"
    static let ss_simswap_title = "Sim Swap Detected!"
    static let ss_simswap_warning = "We noticed some unusual app behaviors and activities, including SimCard Swap on your device. If these actions were not initiated by you or you are unsure about any apps, please change your true number imediately."
    
    static let SS_CHECK_GEO_VELOCITY = "ss_check_geo_velocity"
    static let SS_CHECK_GEO_VELOCITY_ACTION = "ss_check_geo_velocity_action"
    static let SS_CHECK_GEO_VELOCITY_ALERT_TITLE = "ss_check_geo_velocity_alert_title"
    static let SS_CHECK_GEO_VELOCITY_ALERT_MESSAGE = "ss_check_geo_velocity_alert_message"
    static let ss_geo_velocity_title = "Geo Velocity Anomaly Detected!"
    static let ss_geo_velocity_warning = "Anomalies have been identified in the location check associated with your account. This warning is issued to inform you of significant irregularities in the expected location data. Immediate attention is required to address these anomalies, as they may impact your account's functionality, security, and overall user experience."

    static let SS_CHECK_BEHAVIOUR_ANALYSIS = "ss_check_behaviour_analysis"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ACTION = "ss_check_behaviour_analysis_action"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_TITLE = "ss_check_behaviour_analysis_alert_title"
    static let SS_CHECK_BEHAVIOUR_ANALYSIS_ALERT_MESSAGE = "ss_check_behaviour_analysis_alert_message"
    static let ss_behaviour_anomaly_title = "Behaviour Anomaly Detected!"
    static let ss_behaviour_anomaly_warning = "We have identified a significant anomaly in the behavior of your device. This notification serves as a precautionary measure, as unusual patterns can indicate potential security threats, unauthorized access, or software malfunctions that could compromise your data and overall device performance."
    
    static let SS_CHECK_HOOKED = "ss_check_hooked"
    static let SS_CHECK_HOOKED_ACTION = "ss_check_hooked_action"
    static let SS_CHECK_HOOKED_ALERT_TITLE = "ss_check_hooked_alert_title"
    static let SS_CHECK_HOOKED_ALERT_MESSAGE = "ss_check_hooked_alert_message"
    static let ss_hooked_title = "Hooked Detected!"
    static let ss_hooked_warning = "Our security shield has detected changes in the application that may indicate Hook or Anti Frida, which could potentially lead to malware infection, data manipulation, and other risks. Please remove this apps and download from official App Store."
    
    static let SS_CHECK_CLONED = "ss_check_cloned"
    static let SS_CHECK_CLONED_ACTION = "ss_check_cloned_action"
    static let SS_CHECK_CLONED_ALERT_TITLE = "ss_check_cloned_alert_title"
    static let SS_CHECK_CLONED_ALERT_MESSAGE = "ss_check_cloned_alert_message"
    static let ss_clone_title = "App Clone Detected!"
    static let ss_clone_continue = "We are sorry for the inconvenience. For security reasons this app is not allowed to run in cloned instance.";
}

extension UIImage {
    static func imageWithColorSS(color: UIColor, size: CGSize) -> UIImage? {
        UIGraphicsImageRenderer(size: size).image { ctx in
            color.setFill()
            ctx.fill(CGRect(origin: .zero, size: size))
        }
    }
}

private final class SSLibAlertController: UIAlertController {
    /// The window this alert was put up on, released once the alert goes.
    weak var hostWindow: UIWindow?

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if let window = hostWindow {
            SecurityShield.releaseAlertWindow(window)
            hostWindow = nil
        }
    }
}

private class SecureUserDefaultsSS {
    static let shared = SecureUserDefaultsSS()
    private let defaults: UserDefaults
    private let prefsKeyAlias = "_iosx_security_master_key_easysoft_"

    // Initialization with a SymmetricKey
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        do {
            try generateAndStorePrefsKey()
        } catch {
            
        }
    }
    
    func generateAndStorePrefsKey() throws {
        if try isKeyExists(keyAliasCode: prefsKeyAlias) {
            return
        }
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: prefsKeyAlias,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        
        SecItemDelete(query as CFDictionary) // Remove if it exists
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
    }
    
    func isKeyExists(keyAliasCode: String) throws -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyAliasCode,
            kSecReturnData as String: false // We only check existence, not retrieve data
        ]

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        if status == errSecItemNotFound {
            return false
        } else if status == errSecSuccess {
            return true
        } else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
    }
    
    func getPrefsKey() throws -> SymmetricKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: prefsKeyAlias,
            kSecReturnData as String: true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainError", code: Int(status), userInfo: nil)
        }
        
        guard let keyData = item as? Data else {
            throw NSError(domain: "KeyRetrievalError", code: -1, userInfo: nil)
        }
        
        return SymmetricKey(data: keyData)
    }

    func encrypt(data: Data) throws -> Data {
        let key = try getPrefsKey()
        let sealedBox = try AES.GCM.seal(data, using: key)
        return sealedBox.combined!
    }
    
    func decrypt(data: Data) throws -> Data {
        let key = try getPrefsKey()
        let sealedBox = try AES.GCM.SealedBox(combined: data)
        return try AES.GCM.open(sealedBox, using: key)
    }

    func set<T: Codable>(_ value: T, forKey key: String) {
        let encoder = JSONEncoder()
        guard let encodedData = try? encoder.encode(value),
              let encryptedData = try? encrypt(data: encodedData) else {
            return
        }
        defaults.set(encryptedData, forKey: key)
    }

    // Retrieve a value
    func value<T: Codable>(forKey key: String) -> T? {
        guard let encryptedData = defaults.data(forKey: key),
              let decryptedData = try? decrypt(data: encryptedData) else {
            return nil
        }
        let decoder = JSONDecoder()
        return try? decoder.decode(T.self, from: decryptedData)
    }

    // Remove a value
    func removeValue(forKey key: String) {
        defaults.removeObject(forKey: key)
    }
    
    func sync() {
        defaults.synchronize()
    }
}

private final class PinnedURLSessionSSDelegate: NSObject,
    URLSessionTaskDelegate, URLSessionDataDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition,
                                                   URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        var cfError: CFError?
        guard SecTrustEvaluateWithError(trust, &cfError) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let host = challenge.protectionSpace.host.lowercased()
        // Mutable UserDefaults pin JSON is deliberately NOT consulted. First-party hosts use
        // the Sentinel immutable primary/backup floor plus only signature-verified rotations.
        if RASPGuard.shared().isPinnedHost(host) {
            guard RASPGuard.shared().serverTrust(trust, matchesPinnedSPKIForHost: host)
                    || PinSetStore.matches(trust: trust, host: host) else {
                RASPGuard.shared().reportPinningFailure(forHost: host)
                completionHandler(.cancelAuthenticationChallenge, nil)
                return
            }
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

// MARK: - No-code shielding bridge

/// What NexilisZTA's no-code shield (NXShieldAutostart) calls, by name through the Objective-C
/// runtime: NexilisZTA cannot import this package, which depends on it.
///     +[NXSecurityShieldBridge runWithAppName:apiKey:completion:]
@objc(NXSecurityShieldBridge)
public final class SecurityShieldBridge: NSObject {
    @objc public static func run(appName: String, apiKey: String, completion: @escaping (Bool) -> Void) {
        SecurityShield.run(appName: appName, apiKey: apiKey, completion: completion)
    }
}
