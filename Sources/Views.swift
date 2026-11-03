import SwiftUI
import AppKit

struct RootView: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        NavigationSplitView {
            Sidebar().navigationSplitViewColumnWidth(min: 210, ideal: 230)
        } detail: {
            ZStack {
                Theme.bg.ignoresSafeArea()
                if model.showPackets { PacketView(cap: model.capture) }
                else if let h = model.selection { HostView(host: h) } else { Text("Pick a machine").foregroundStyle(Theme.secondary) }
            }
        }
        .tint(Theme.accent)
    }
}

struct Sidebar: View {
    @EnvironmentObject var model: AppModel
    @State private var newHost = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Machines").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
                .padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 4)
            ForEach(model.hosts) { h in
                HostRow(host: h, selected: !model.showPackets && model.selection == h)
                    .contentShape(Rectangle())
                    .onTapGesture { model.selection = h; model.showPackets = false }
                    .contextMenu { if h.ssh != nil { Button("Remove \(h.name)") { model.remove(h) } } }
            }
            Text("Inspect").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
                .padding(.horizontal, 12).padding(.top, 14).padding(.bottom, 4)
            PacketsSidebarRow(cap: model.capture, selected: model.showPackets)
                .contentShape(Rectangle())
                .onTapGesture { model.showPackets = true }
            Spacer()
            HStack(spacing: 7) {
                Image(systemName: "plus").font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
                TextField("Add ssh host", text: $newHost).textFieldStyle(.plain).font(.system(size: 12.5))
                    .onSubmit { model.add(newHost); newHost = "" }
            }
            .padding(.horizontal, 10).padding(.vertical, 8)
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .padding(10)
        .frame(maxHeight: .infinity)
        .background(Theme.sidebar)
    }
}

struct HostRow: View {
    @ObservedObject var host: Host
    var selected = false
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: host.ssh == nil ? "laptopcomputer" : "desktopcomputer")
                .font(.system(size: 14)).foregroundStyle(selected ? Theme.text : Theme.secondary).frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(host.name).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                    Circle().fill(host.error != nil ? Theme.stalled : host.lastUpdate == nil ? Theme.tertiary : Theme.live)
                        .frame(width: 5, height: 5)
                }
                Text(host.error == nil ? fmtSpeed(host.totalIn) : "Offline")
                    .font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.secondary)
            }
            Spacer(minLength: 4)
            MiniSpark(values: host.history, color: selected ? Theme.accent : Theme.tertiary).frame(width: 40, height: 16)
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(selected ? Theme.raised : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}

struct HostView: View {
    @ObservedObject var host: Host
    var body: some View {
        ScrollView { HostContent(host: host).padding(.horizontal, 32).padding(.vertical, 26) }
            .background(Theme.bg)
            .navigationTitle("")
    }
}

/// Everything in the detail pane (no ScrollView, so it can be rendered offscreen for QA).
struct HostContent: View {
    @ObservedObject var host: Host
    var body: some View {
        VStack(alignment: .leading, spacing: 28) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 4) {
                    Text(host.name).font(.system(size: 24, weight: .semibold)).foregroundStyle(Theme.text)
                    Text(host.ssh.map { "ssh \($0)" } ?? "This computer").font(.system(size: 12)).foregroundStyle(Theme.tertiary)
                }
                Spacer()
                HStack(spacing: 6) {
                    Circle().fill(host.error == nil ? Theme.live : Theme.stalled).frame(width: 6, height: 6)
                    Text(host.error == nil ? "Live" : "Offline").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.secondary)
                }
            }
            if let e = host.error { ErrorBanner(text: e) }
            Hero(host: host)
            Group {
                SectionTitle(title: "Downloading", count: host.downloads.count)
                DownloadList(items: host.downloads).padding(.top, -16)
                SectionTitle(title: "Network activity", count: host.procs.count)
                AppList(procs: host.procs).padding(.top, -16)
            }
        }
        .frame(maxWidth: 1080, alignment: .leading)
    }
}

struct Card<C: View>: View {
    @ViewBuilder var content: C
    var body: some View {
        content
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).stroke(Theme.hairline, lineWidth: 1))
    }
}

struct Hero: View {
    @ObservedObject var host: Host
    var body: some View {
        Card {
            VStack(spacing: 0) {
                HStack(alignment: .top, spacing: 30) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Download").font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.secondary)
                        SpeedText(value: host.totalIn, size: 46, unitColor: Theme.secondary).foregroundStyle(Theme.accent)
                        HStack(spacing: 6) {
                            Text("Upload").foregroundStyle(Theme.tertiary)
                            Text(fmtSpeed(host.totalOut)).foregroundStyle(Theme.secondary).monospacedDigit()
                        }
                        .font(.system(size: 12.5, weight: .medium))
                    }
                    .frame(width: 230, alignment: .leading)
                    AreaChart(down: host.history, up: host.historyOut).frame(height: 116)
                }
                .padding(22)
                Rectangle().fill(Theme.hairline).frame(height: 1)
                HStack(spacing: 0) {
                    Stat(label: "Received", value: fmtBytes(host.received))
                    Stat(label: "Peak", value: fmtSpeed(host.history.max() ?? 0))
                    Stat(label: "Active", value: "\(host.downloads.filter { !$0.stalled }.count)")
                    Stat(label: "Stalled", value: "\(host.downloads.filter(\.stalled).count)",
                         alert: host.downloads.contains(where: \.stalled))
                    Stat(label: "Apps", value: "\(host.procs.count)", last: true)
                }
            }
        }
    }
}

struct Stat: View {
    let label: String, value: String
    var alert = false
    var last = false
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.tertiary)
                Text(value).font(.system(size: 15, weight: .semibold)).monospacedDigit()
                    .foregroundStyle(alert ? Theme.stalled : Theme.text).lineLimit(1).fixedSize()
            }
            .padding(.horizontal, 22).padding(.vertical, 14)
            Spacer(minLength: 0)
            if !last { Rectangle().fill(Theme.hairline).frame(width: 1, height: 30) }
        }
        .frame(maxWidth: .infinity)
    }
}

struct SpeedText: View {
    let value: Double
    let size: CGFloat
    var unitColor: Color? = nil
    var body: some View {
        let parts = fmtSpeed(value).split(separator: " ", maxSplits: 1).map(String.init)
        HStack(alignment: .firstTextBaseline, spacing: size * 0.12) {
            Text(parts.first ?? "0").font(.system(size: size, weight: .semibold, design: .rounded))
            Text(parts.count > 1 ? parts[1] : "").font(.system(size: size * 0.36, weight: .medium))
                .foregroundStyle(unitColor ?? .primary)
        }
        .monospacedDigit()
    }
}

struct SectionTitle: View {
    let title: String, count: Int
    var body: some View {
        HStack(spacing: 8) {
            Text(title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
            Text(verbatim: String(count)).font(.system(size: 12, weight: .medium)).foregroundStyle(Theme.tertiary)
        }
    }
}

struct Divider1: View {
    var inset: CGFloat = 0
    var body: some View { Rectangle().fill(Theme.hairline).frame(height: 1).padding(.leading, inset) }
}

struct DownloadList: View {
    let items: [DownloadItem]
    var body: some View {
        Card {
            VStack(spacing: 0) {
                if items.isEmpty {
                    HStack(spacing: 12) {
                        GlyphTile(symbol: "checkmark", size: 30)
                        Text("Nothing downloading right now").font(.system(size: 13)).foregroundStyle(Theme.secondary)
                        Spacer()
                    }
                    .padding(16)
                }
                ForEach(Array(items.enumerated()), id: \.element.id) { i, d in
                    DownloadRow(item: d)
                    if i < items.count - 1 { Divider1(inset: 62) }
                }
            }
        }
    }
}

struct DownloadRow: View {
    let item: DownloadItem
    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            GlyphTile(symbol: Icons.file(item.path), size: 34, tint: item.stalled ? Theme.stalled : Theme.secondary)
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .firstTextBaseline) {
                    Text((item.path as NSString).lastPathComponent).font(.system(size: 13.5, weight: .medium))
                        .foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 12)
                    Text(item.progress.map { String(format: "%.0f%%", $0 * 100) } ?? fmtBytes(Double(item.size)))
                        .font(.system(size: 13, weight: .semibold)).monospacedDigit()
                        .foregroundStyle(item.stalled ? Theme.stalled : Theme.text)
                }
                ProgressLine(value: item.progress, stalled: item.stalled)
                HStack(spacing: 0) {
                    Text(meta).foregroundStyle(item.stalled ? Theme.stalled : Theme.secondary)
                    Spacer(minLength: 10)
                    Text(verbatim: "\(item.process) \(item.pid)").foregroundStyle(Theme.tertiary)
                }
                .font(.system(size: 11.5)).monospacedDigit()
                Text(item.path).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.tertiary)
                    .lineLimit(1).truncationMode(.head).textSelection(.enabled)
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 14)
    }

    var meta: String {
        var parts: [String] = []
        if item.stalled {
            parts.append("Stalled for \(Int(Date().timeIntervalSince(item.lastGrowth)))s")
        } else {
            parts.append(fmtSpeed(item.speed))
            if let e = item.eta { parts.append(fmtETA(e) + " left") }
        }
        if let t = item.total { parts.append("\(fmtBytes(Double(item.size))) of \(fmtBytes(Double(t)))") }
        else { parts.append("size unknown") }
        return parts.joined(separator: "  ·  ")
    }
}

struct AppList: View {
    let procs: [ProcInfo]
    var body: some View {
        let peak = max(procs.map(\.bytesIn).max() ?? 1, 1)
        let rows = Array(procs.prefix(40))
        Card {
            VStack(spacing: 0) {
                if rows.isEmpty {
                    Text("No network traffic").font(.system(size: 13)).foregroundStyle(Theme.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading).padding(16)
                }
                ForEach(Array(rows.enumerated()), id: \.element.id) { i, p in
                    AppRow(proc: p, peak: peak)
                    if i < rows.count - 1 { Divider1(inset: 56) }
                }
            }
        }
    }
}

struct AppRow: View {
    let proc: ProcInfo
    let peak: Double
    var body: some View {
        HStack(spacing: 13) {
            ProcIcon(name: proc.name, args: proc.args, size: 28)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(proc.name).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text).lineLimit(1)
                    Text(verbatim: String(proc.pid)).font(.system(size: 11)).foregroundStyle(Theme.tertiary)
                }
                if !proc.args.isEmpty {
                    Text(proc.args).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.tertiary)
                        .lineLimit(1).truncationMode(.middle).help(proc.args)
                }
            }
            Spacer(minLength: 16)
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.06))
                Capsule().fill(Theme.accent.opacity(proc.bytesIn > 50_000 ? 1 : 0.45))
                    .frame(width: max(3, 110 * proc.bytesIn / peak))
            }
            .frame(width: 110, height: 4)
            Text(fmtSpeed(proc.bytesIn)).font(.system(size: 12.5, weight: .medium)).monospacedDigit()
                .foregroundStyle(proc.bytesIn > 50_000 ? Theme.text : Theme.secondary).frame(width: 86, alignment: .trailing)
            Text("↑ " + fmtSpeed(proc.bytesOut)).font(.system(size: 11.5)).monospacedDigit()
                .foregroundStyle(Theme.tertiary).frame(width: 82, alignment: .trailing)
        }
        .padding(.horizontal, 14).padding(.vertical, 10)
    }
}

struct ErrorBanner: View {
    let text: String
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle").foregroundStyle(Theme.stalled)
            Text(text).font(.system(size: 12.5)).foregroundStyle(Theme.text).lineLimit(3)
            Spacer()
        }
        .padding(14)
        .background(Theme.stalled.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

// MARK: menu bar

struct MenuLabel: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        Text("↓ " + fmtSpeed(model.totalIn)).monospacedDigit()
    }
}

struct MenuView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("Dolkoon").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.secondary)
                Spacer()
                SpeedText(value: model.totalIn, size: 22, unitColor: Theme.secondary).foregroundStyle(Theme.accent)
            }
            ForEach(model.hosts) { h in MenuHost(host: h) }
            HStack {
                Button("Open Dolkoon") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }
            }
            .buttonStyle(.borderless).font(.system(size: 12)).foregroundStyle(Theme.secondary)
        }
        .padding(14).frame(width: 330)
        .background(Theme.bg)
    }
}

struct MenuHost: View {
    @ObservedObject var host: Host
    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 7) {
                    Circle().fill(host.error == nil ? Theme.live : Theme.stalled).frame(width: 5, height: 5)
                    Text(host.name).font(.system(size: 12.5, weight: .medium)).foregroundStyle(Theme.text)
                    Spacer()
                    MiniSpark(values: host.history, color: Theme.tertiary).frame(width: 44, height: 12)
                    Text(fmtSpeed(host.totalIn)).font(.system(size: 12, weight: .medium)).monospacedDigit()
                        .foregroundStyle(Theme.text).frame(width: 76, alignment: .trailing)
                }
                ForEach(host.downloads.prefix(3)) { d in
                    VStack(alignment: .leading, spacing: 5) {
                        HStack {
                            Text((d.path as NSString).lastPathComponent).font(.system(size: 11.5))
                                .foregroundStyle(Theme.secondary).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(d.stalled ? "Stalled" : fmtSpeed(d.speed)).font(.system(size: 11)).monospacedDigit()
                                .foregroundStyle(d.stalled ? Theme.stalled : Theme.secondary)
                        }
                        ProgressLine(value: d.progress, stalled: d.stalled, height: 3)
                    }
                }
            }
            .padding(12)
        }
    }
}
