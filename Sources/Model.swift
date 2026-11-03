import Foundation
import SwiftUI

struct DownloadItem: Identifiable {
    let path: String
    let pid: Int
    var process: String
    var size: Int64
    var total: Int64?
    var speed: Double          // bytes/s from the file's own growth
    var lastGrowth: Date
    var id: String { "\(pid):\(path)" }
    var stalled: Bool { Date().timeIntervalSince(lastGrowth) > 20 }
    var progress: Double? { total.map { min(1, Double(size) / Double(max($0, 1))) } }
    var eta: TimeInterval? {
        guard let t = total, speed > 1, t > size else { return nil }
        return Double(t - size) / speed
    }
}

final class Host: ObservableObject, Identifiable, Hashable {
    let name: String
    let ssh: String?
    @Published var procs: [ProcInfo] = []
    @Published var downloads: [DownloadItem] = []
    @Published var history: [Double] = Array(repeating: 0, count: 90)
    @Published var historyOut: [Double] = Array(repeating: 0, count: 90)
    @Published var received: Double = 0   // bytes since Dolkoon started watching
    @Published var totalIn: Double = 0
    @Published var totalOut: Double = 0
    @Published var error: String?
    @Published var lastUpdate: Date?
    private var seen: [String: (size: Int64, time: Date, grew: Date, speed: Double)] = [:]
    private var running = false

    var id: String { name }
    init(name: String, ssh: String?) { self.name = name; self.ssh = ssh }
    static func == (a: Host, b: Host) -> Bool { a.name == b.name }
    func hash(into h: inout Hasher) { h.combine(name) }

    func start() {
        guard !running else { return }
        running = true
        Thread.detachNewThread { [weak self] in
            while let self, self.running {
                let s = Collector.run(host: self)
                DispatchQueue.main.async { self.apply(s) }
                Thread.sleep(forTimeInterval: s.error == nil ? 1 : 5)
            }
        }
    }

    func stop() { running = false }

    func apply(_ s: Sample) {
        error = s.error
        guard s.error == nil else { return }
        lastUpdate = Date()
        procs = s.procs.sorted { ($0.bytesIn, $0.bytesOut) > ($1.bytesIn, $1.bytesOut) }
        totalIn = s.procs.reduce(0) { $0 + $1.bytesIn }
        totalOut = s.procs.reduce(0) { $0 + $1.bytesOut }
        received += totalIn
        history.append(totalIn)
        historyOut.append(totalOut)
        if history.count > 90 { history.removeFirst(history.count - 90) }
        if historyOut.count > 90 { historyOut.removeFirst(historyOut.count - 90) }

        let now = Date()
        let procByPid = Dictionary(uniqueKeysWithValues: s.procs.map { ($0.pid, $0) })
        var next: [String: (Int64, Date, Date, Double)] = [:]
        var items: [DownloadItem] = []
        for f in Set(s.files) {
            let key = "\(f.pid):\(f.path)"
            var grew = now, speed = 0.0
            if let old = seen[key] {
                let dt = now.timeIntervalSince(old.time)
                let raw = dt > 0 ? Double(f.size - old.size) / dt : 0
                speed = raw > 0 ? old.speed * 0.5 + raw * 0.5 : old.speed * 0.3
                grew = f.size > old.size ? now : old.grew
            }
            next[key] = (f.size, now, grew, speed)
            let proc = procByPid[f.pid]
            var total: Int64?
            if let args = proc?.args, let url = firstURL(in: args),
               s.files.filter({ $0.pid == f.pid }).count == 1 {
                total = SizeLookup.shared.size(for: url)
            }
            // Hide files that never grew while we watched (config, caches) unless a download tool owns them.
            let isTool = ["curl", "wget", "aria2c", "hf", "python", "Python", "uv", "pip", "yt-dlp"].contains { (proc?.name ?? "").hasPrefix($0) }
            if seen[key] == nil && !isTool && f.size < 1_000_000 { continue }
            if let old = seen[key], old.size == f.size, now.timeIntervalSince(old.grew) > 60, !isTool { continue }
            items.append(DownloadItem(path: f.path, pid: f.pid, process: proc?.name ?? "pid \(f.pid)",
                                      size: f.size, total: total, speed: speed, lastGrowth: grew))
        }
        seen = next.mapValues { (size: $0.0, time: $0.1, grew: $0.2, speed: $0.3) }
        downloads = items.sorted { ($0.speed, $0.size) > ($1.speed, $1.size) }
    }
}

final class AppModel: ObservableObject {
    @Published var hosts: [Host] = []
    @Published var selection: Host?
    @Published var showPackets = false
    let capture = PacketCapture()
    @AppStorage("extraHosts") private var extraHosts = ""

    init() {
        hosts = [Host(name: "This Mac", ssh: nil)] + extraHosts.split(separator: ",").map {
            Host(name: String($0), ssh: String($0))
        }
        hosts.forEach { $0.start() }
        selection = hosts.first
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.totalIn = self.hosts.reduce(0) { $0 + $1.totalIn }
        }
    }

    func add(_ alias: String) {
        let a = alias.trimmingCharacters(in: .whitespaces)
        guard !a.isEmpty, !hosts.contains(where: { $0.name == a }) else { return }
        let h = Host(name: a, ssh: a)
        hosts.append(h); h.start()
        extraHosts = hosts.compactMap(\.ssh).joined(separator: ",")
    }

    func remove(_ h: Host) {
        guard h.ssh != nil else { return }
        h.stop()
        hosts.removeAll { $0 == h }
        if selection == h { selection = hosts.first }
        extraHosts = hosts.compactMap(\.ssh).joined(separator: ",")
    }

    /// Refreshed once a second; the menu bar label and menu read it instead of running their own timers.
    @Published var totalIn: Double = 0
    private var timer: Timer?
}

func fmtBytes(_ b: Double) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"]
    var v = b, i = 0
    while v >= 1000, i < u.count - 1 { v /= 1000; i += 1 }
    return i == 0 ? "\(Int(v)) B" : String(format: v < 10 ? "%.2f %@" : v < 100 ? "%.1f %@" : "%.0f %@", v, u[i])
}

func fmtSpeed(_ b: Double) -> String { fmtBytes(b) + "/s" }

func fmtETA(_ t: TimeInterval) -> String {
    let s = Int(t)
    if s >= 3600 { return "\(s / 3600)h \(s % 3600 / 60)m" }
    if s >= 60 { return "\(s / 60)m \(s % 60)s" }
    return "\(s)s"
}
