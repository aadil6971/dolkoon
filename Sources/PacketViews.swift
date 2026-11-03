import SwiftUI
import AppKit
import UniformTypeIdentifiers

extension Theme {
    /// One colour per OSI layer, index 0 = layer 1. Layer 7 keeps the app's yellow accent.
    static let layer: [Color] = [0x8B9099, 0xB48CFF, 0x3DDC84, 0x5AB0FF, 0x4FD1C5, 0xFF9F43, 0xFFD23F].map { Color(hex: $0) }
}

struct PacketView: View {
    @ObservedObject var cap: PacketCapture
    @State private var selectedID: Int?
    @State private var filter = ""
    @State private var follow = true
    @State private var focus: Int?

    var body: some View {
        let shown = filter.isEmpty ? cap.packets : cap.packets.filter { $0.matches(filter) }
        let selected = selectedID.flatMap { id in cap.packets.last { $0.id == id } }
        VStack(spacing: 0) {
            PacketHeader(cap: cap, filter: $filter).padding(.horizontal, 24).padding(.top, 18).padding(.bottom, 12)
            if cap.state == .needsPermission { PermissionBanner(cap: cap).padding(.horizontal, 24).padding(.bottom, 12) }
            if case .failed(let e) = cap.state { ErrorBanner(text: e).padding(.horizontal, 24).padding(.bottom, 12) }
            VSplitView {
                PacketTable(packets: shown, t0: cap.packets.first?.time, selectedID: $selectedID, follow: $follow)
                    .frame(minHeight: 140, idealHeight: 250)
                Group {
                    if let p = selected { PacketDetail(packet: p, focus: $focus) } else { OSIGuide() }
                }
                .frame(minHeight: 300, maxHeight: .infinity)
                .background(Theme.bg)
            }
        }
        .background(Theme.bg)
        .onAppear { if cap.state == .idle { cap.start() } }
        .onDisappear { cap.pause() }
        .onChange(of: selectedID) { focus = selected?.top }
    }
}

struct PacketHeader: View {
    @ObservedObject var cap: PacketCapture
    @Binding var filter: String

    var status: String {
        switch cap.state {
        case .idle: return "Not capturing"
        case .running: return "Live on \(cap.iface) · \(Int(cap.rate.rounded())) packets/s · \(cap.total) seen"
        case .paused: return "Paused · \(cap.total) seen"
        case .needsPermission: return "Waiting for permission"
        case .failed: return "Capture stopped"
        case .file(let name): return "\(name) · \(cap.packets.count) packets"
        case .demo: return "Demo — made-up example packets"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Packets").font(.system(size: 24, weight: .semibold)).foregroundStyle(Theme.text)
                    HStack(spacing: 6) {
                        Circle().fill(cap.state == .running ? Theme.live : Theme.tertiary).frame(width: 6, height: 6)
                        Text(status).font(.system(size: 12)).monospacedDigit().foregroundStyle(Theme.tertiary)
                    }
                }
                Spacer(minLength: 8)
                HStack(spacing: 6) {
                    Image(systemName: "line.3.horizontal.decrease").font(.system(size: 11)).foregroundStyle(Theme.tertiary)
                    TextField("Filter: dns, 443, 192.168…", text: $filter).textFieldStyle(.plain).font(.system(size: 12.5))
                }
                .padding(.horizontal, 10).padding(.vertical, 7)
                .background(Theme.surface, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                .frame(width: 190)
                Picker("", selection: $cap.iface) {
                    ForEach(cap.interfaces, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden().frame(width: 96)
                .onChange(of: cap.iface) { if cap.state == .running { cap.start() } }
                Button {
                    cap.state == .running ? cap.pause() : cap.start()
                } label: {
                    Label(cap.state == .running ? "Pause" : "Capture", systemImage: cap.state == .running ? "pause.fill" : "record.circle")
                        .font(.system(size: 12.5, weight: .semibold))
                        .padding(.horizontal, 12).padding(.vertical, 6)
                        .foregroundStyle(cap.state == .running ? Theme.text : Color.black)
                        .background(cap.state == .running ? Theme.raised : Theme.accent, in: Capsule())
                }
                .buttonStyle(.plain)
                Menu {
                    Button("Clear") { cap.clear() }
                    Button("Open capture file…") { openFile() }
                    Button("Demo packets") { cap.loadDemo() }
                } label: { Image(systemName: "ellipsis.circle") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 28)
            }
            ProtocolMix(cap: cap)
        }
    }

    func openFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["pcap", "pcapng", "cap"].compactMap { UTType(filenameExtension: $0) } + [.data]
        if panel.runModal() == .OK, let url = panel.url { cap.open(url) }
    }
}

/// Top protocols seen so far, coloured by the OSI layer they live on.
struct ProtocolMix: View {
    @ObservedObject var cap: PacketCapture
    var body: some View {
        let layerOf = Dictionary(cap.packets.suffix(500).map { ($0.proto, $0.top) }, uniquingKeysWith: { a, _ in a })
        let top = cap.counts.sorted { $0.value > $1.value }.prefix(8)
        let all = max(cap.counts.values.reduce(0, +), 1)
        HStack(spacing: 6) {
            ForEach(Array(top), id: \.key) { name, n in
                HStack(spacing: 5) {
                    RoundedRectangle(cornerRadius: 2).fill(Theme.layer[(layerOf[name] ?? 1) - 1]).frame(width: 7, height: 7)
                    Text(name).foregroundStyle(Theme.text)
                    Text("\(Int((Double(n) / Double(all) * 100).rounded()))%").foregroundStyle(Theme.tertiary)
                }
                .font(.system(size: 11.5, weight: .medium)).monospacedDigit()
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(Theme.surface, in: Capsule())
            }
            if top.isEmpty { Text("No packets yet").font(.system(size: 11.5)).foregroundStyle(Theme.tertiary) }
            Spacer()
        }
        .frame(height: 22)
    }
}

struct PermissionBanner: View {
    @ObservedObject var cap: PacketCapture
    @State private var granted = false
    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield").font(.system(size: 18)).foregroundStyle(Theme.accent)
            VStack(alignment: .leading, spacing: 3) {
                Text(granted ? "Access added — log out and back in if capture is still blocked"
                             : "macOS needs your OK before Dolkoon can read packets")
                    .font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                Text(cap.canGrant
                     ? "Allow adds your user to the access_bpf group, the same thing Wireshark does. It asks for your Mac password."
                     : "Install Wireshark's ChmodBPF (Wireshark.app › Contents › Resources › Extras), then press Capture.")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.secondary)
            }
            Spacer(minLength: 8)
            if cap.canGrant {
                Button("Allow capture…") { cap.grant { ok in granted = ok; if ok { cap.start() } } }
            }
            Button("Demo packets") { cap.loadDemo() }
        }
        .padding(14)
        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

// MARK: list

struct PacketTable: View {
    let packets: [Packet]
    let t0: Date?
    @Binding var selectedID: Int?
    @Binding var follow: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                PacketColumns(no: "No.", time: "Time", src: "Source", dst: "Destination", proto: "Protocol", len: "Length", info: "Info")
                Button { follow.toggle() } label: {
                    Image(systemName: "arrow.down.to.line").font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(follow ? Theme.accent : Theme.tertiary)
                }
                .buttonStyle(.plain).help(follow ? "Following new packets" : "Follow new packets").padding(.trailing, 12)
            }
            .font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
            .padding(.vertical, 7)
            Divider1()
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(packets) { p in
                            PacketRow(packet: p, t0: t0, selected: p.id == selectedID)
                                .id(p.id)
                                .contentShape(Rectangle())
                                .onTapGesture { selectedID = p.id; follow = false }
                        }
                    }
                }
                .onChange(of: packets.last?.id) {
                    if follow, let id = packets.last?.id { proxy.scrollTo(id, anchor: .bottom) }
                }
                .onChange(of: selectedID) { if let id = selectedID { proxy.scrollTo(id) } }
            }
        }
        .background(Theme.surface)
        .focusable()
        .focusEffectDisabled()
        .onKeyPress(.upArrow) { step(-1) }
        .onKeyPress(.downArrow) { step(1) }
    }

    func step(_ d: Int) -> KeyPress.Result {
        guard !packets.isEmpty else { return .ignored }
        let i = packets.firstIndex { $0.id == selectedID } ?? (d > 0 ? -1 : packets.count)
        selectedID = packets[max(0, min(packets.count - 1, i + d))].id
        follow = false
        return .handled
    }
}

struct PacketColumns: View {
    let no: String, time: String, src: String, dst: String, proto: String, len: String, info: String
    var protoColor: Color? = nil
    var body: some View {
        HStack(spacing: 10) {
            Text(no).frame(width: 46, alignment: .trailing)
            Text(time).frame(width: 62, alignment: .trailing)
            Text(src).lineLimit(1).truncationMode(.middle).frame(minWidth: 90, maxWidth: 190, alignment: .leading).layoutPriority(2)
            Text(dst).lineLimit(1).truncationMode(.middle).frame(minWidth: 90, maxWidth: 190, alignment: .leading).layoutPriority(2)
            HStack(spacing: 6) {
                if let c = protoColor { RoundedRectangle(cornerRadius: 2).fill(c).frame(width: 7, height: 7) }
                Text(proto).lineLimit(1)
            }
            .frame(width: 92, alignment: .leading)
            Text(len).frame(width: 46, alignment: .trailing)
            Text(info).lineLimit(1).frame(maxWidth: .infinity, alignment: .leading).layoutPriority(1)
        }
        .padding(.leading, 6).padding(.trailing, 12)
    }
}

struct PacketRow: View {
    let packet: Packet
    let t0: Date?
    let selected: Bool
    var body: some View {
        PacketColumns(no: "\(packet.id)", time: String(format: "%.3f", packet.time.timeIntervalSince(t0 ?? packet.time)),
                      src: packet.src, dst: packet.dst, proto: packet.proto, len: "\(packet.wireLength)", info: packet.info,
                      protoColor: Theme.layer[packet.top - 1])
            .font(.system(size: 12)).monospacedDigit()
            .foregroundStyle(selected ? Theme.text : Theme.secondary)
            .frame(height: 24)
            .background(selected ? Theme.accentSoft : .clear)
    }
}

// MARK: detail

struct PacketDetail: View {
    let packet: Packet
    @Binding var focus: Int?
    var body: some View {
        GeometryReader { g in
            let wide = g.size.width > 820
            VStack(alignment: .leading, spacing: 14) {
                HStack(alignment: .firstTextBaseline, spacing: 10) {
                    Text("Packet \(packet.id)").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("\(packet.wireLength) bytes · \(packet.src) → \(packet.dst)").font(.system(size: 12)).monospacedDigit()
                        .foregroundStyle(Theme.tertiary).lineLimit(1).truncationMode(.middle)
                }
                EncapsulationBar(packet: packet, focus: $focus)
                HStack(alignment: .top, spacing: 16) {
                    ScrollView { OSIStack(packet: packet, focus: $focus) }
                        .frame(minWidth: 280, maxWidth: .infinity)
                    BytesPanel(packet: packet, focus: focus, perRow: wide ? 16 : 8)
                        .frame(width: wide ? 392 : 228)
                }
            }
            .padding(.horizontal, 24).padding(.vertical, 16)
        }
    }
}

/// The packet as a row of headers: each lower layer's header comes first and wraps everything after it.
struct EncapsulationBar: View {
    let packet: Packet
    @Binding var focus: Int?

    struct Seg: Identifiable { let osi: Int?; let name: String; let count: Int; var id: String { "\(osi ?? 0)\(name)" } }

    var segs: [Seg] {
        var out: [Seg] = []
        var at = 0
        for l in packet.layers.compactMap({ l in l.range.map { (l, $0) } }).sorted(by: { $0.1.lowerBound < $1.1.lowerBound }) {
            let (layer, r) = l
            guard r.upperBound > at else { continue }
            if r.lowerBound > at { out.append(Seg(osi: nil, name: "Other", count: r.lowerBound - at)) }
            let name = layer.osi == 7 ? "\(DecoderLabel.short(layer.proto)) data" : DecoderLabel.short(layer.proto) + " header"
            out.append(Seg(osi: layer.osi, name: name, count: r.upperBound - max(at, r.lowerBound)))
            at = r.upperBound
        }
        if packet.bytes.count > at { out.append(Seg(osi: nil, name: at == 0 ? "Bytes" : "Padding", count: packet.bytes.count - at)) }
        return out
    }

    var body: some View {
        let s = segs
        let weights = s.map { max(1.0, Double($0.count).squareRoot()) }
        let sum = weights.reduce(0, +)
        VStack(alignment: .leading, spacing: 6) {
            GeometryReader { g in
                HStack(spacing: 2) {
                    ForEach(Array(s.enumerated()), id: \.element.id) { i, seg in
                        let c = seg.osi.map { Theme.layer[$0 - 1] } ?? Theme.tertiary
                        let dim = focus != nil && seg.osi != focus
                        VStack(alignment: .leading, spacing: 1) {
                            Text(seg.name).font(.system(size: 11, weight: .semibold)).lineLimit(1)
                            Text("\(seg.count) B").font(.system(size: 10.5)).monospacedDigit().opacity(0.75)
                        }
                        .foregroundStyle(Color.black.opacity(0.85))
                        .padding(.horizontal, 7)
                        .frame(width: max(30, (g.size.width - CGFloat(s.count - 1) * 2) * weights[i] / sum), height: 38, alignment: .leading)
                        .background(c.opacity(dim ? 0.3 : 0.92), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                        .onTapGesture { if let o = seg.osi { focus = focus == o ? nil : o } }
                        .help(seg.osi.map { "Layer \($0) · \(OSI.names[$0 - 1])" } ?? "")
                    }
                }
            }
            .frame(height: 38)
            Text("Read left to right: each layer adds its header in front of the layer above it.")
                .font(.system(size: 11)).foregroundStyle(Theme.tertiary)
        }
        .animation(.easeOut(duration: 0.2), value: focus)
    }
}

enum DecoderLabel {
    static func short(_ s: String) -> String {
        let base = s.components(separatedBy: " · ").first ?? s
        return base == "Wi-Fi / Ethernet" ? "Frame" : base
    }
}

struct OSIStack: View {
    let packet: Packet
    @Binding var focus: Int?
    var body: some View {
        VStack(spacing: 5) {
            ForEach(packet.layers.reversed()) { l in
                LayerRow(layer: l, expanded: focus == l.osi)
                    .contentShape(Rectangle())
                    .onTapGesture { withAnimation(.easeOut(duration: 0.18)) { focus = focus == l.osi ? nil : l.osi } }
            }
        }
    }
}

struct LayerRow: View {
    let layer: OSILayer
    let expanded: Bool
    var body: some View {
        let c = Theme.layer[layer.osi - 1]
        HStack(alignment: .top, spacing: 12) {
            Text("\(layer.osi)").font(.system(size: 13, weight: .bold, design: .rounded))
                .foregroundStyle(layer.present ? Color.black.opacity(0.85) : c)
                .frame(width: 26, height: 26)
                .background(c.opacity(layer.present ? 1 : 0.14), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(OSI.names[layer.osi - 1]).font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
                    Text(layer.present ? layer.proto : "—").font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(layer.present ? Theme.text : Theme.tertiary).lineLimit(1)
                    Spacer(minLength: 6)
                    if let r = layer.range {
                        Text("\(r.count) B").font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.tertiary)
                    }
                }
                Text(layer.summary).font(.system(size: 12)).foregroundStyle(layer.present ? Theme.secondary : Theme.tertiary)
                    .lineLimit(expanded ? 4 : 1).truncationMode(.middle)
                if expanded {
                    Text(OSI.roles[layer.osi - 1]).font(.system(size: 11)).foregroundStyle(c.opacity(0.9)).padding(.top, 2)
                    if !layer.fields.isEmpty {
                        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 4) {
                            ForEach(layer.fields, id: \.self) { f in
                                GridRow {
                                    Text(f.key).font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
                                    Text(f.value).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.text)
                                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(.top, 6)
                    }
                }
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 9)
        .background(expanded ? Theme.raised : Theme.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(alignment: .leading) {
            if expanded { RoundedRectangle(cornerRadius: 2).fill(c).frame(width: 3).padding(.vertical, 8) }
        }
        .help(OSI.roles[layer.osi - 1])
    }
}

/// Hex dump with every byte coloured by the layer it belongs to.
struct BytesPanel: View {
    let packet: Packet
    let focus: Int?
    let perRow: Int

    var body: some View {
        let shown = min(packet.bytes.count, 1024)
        let owner = owners(shown)
        let rows = stride(from: 0, to: shown, by: perRow).map { $0 }
        return VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .firstTextBaseline) {
                Text("Bytes").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                Spacer()
                Text("\(packet.bytes.count) captured").font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.tertiary)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(rows, id: \.self) { start in
                        row(start, min(start + perRow, shown), owner)
                    }
                    if packet.bytes.count > shown {
                        Text("… \(packet.bytes.count - shown) more bytes").font(.system(size: 11)).foregroundStyle(Theme.tertiary).padding(.top, 4)
                    }
                }
                .padding(10)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
    }

    /// OSI layer number that owns each byte (0 = none).
    func owners(_ shown: Int) -> [Int] {
        var owner = [Int](repeating: 0, count: shown)
        for l in packet.layers { if let r = l.range { for i in r where i < shown { owner[i] = l.osi } } }
        return owner
    }

    func row(_ a: Int, _ b: Int, _ owner: [Int]) -> Text {
        var t = Text(String(format: "%04x  ", a)).foregroundColor(Theme.tertiary.opacity(0.7))
        for i in a..<b {
            let o = owner[i]
            let c = o == 0 ? Theme.tertiary : Theme.layer[o - 1]
            let dim = focus != nil && o != focus
            t = t + Text(String(format: "%02x ", packet.bytes[i])).foregroundColor(c.opacity(dim ? 0.22 : 1))
        }
        return t.font(.system(size: 11, design: .monospaced))
    }
}

/// Shown before a packet is picked: what each layer does, with everyday examples.
struct OSIGuide: View {
    let examples = ["Wi-Fi radio, Ethernet cable", "Ethernet / Wi-Fi frames, MAC addresses", "IP, ICMP (ping)",
                    "TCP, UDP, ports", "TCP handshake, TLS session", "TLS encryption", "HTTP, DNS, SSH"]
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Text("Click a packet to see its 7 layers").font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
                VStack(spacing: 5) {
                    ForEach((1...7).reversed(), id: \.self) { n in
                        HStack(spacing: 12) {
                            Text("\(n)").font(.system(size: 13, weight: .bold, design: .rounded)).foregroundStyle(Color.black.opacity(0.85))
                                .frame(width: 26, height: 26)
                                .background(Theme.layer[n - 1], in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                            VStack(alignment: .leading, spacing: 2) {
                                Text(OSI.names[n - 1]).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                Text(OSI.roles[n - 1]).font(.system(size: 11.5)).foregroundStyle(Theme.secondary)
                            }
                            Spacer()
                            Text(examples[n - 1]).font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
                        }
                        .padding(.horizontal, 12).padding(.vertical, 8)
                        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
                Text("Real networks use the simpler TCP/IP model, so layers 5 and 6 often have no protocol of their own — Dolkoon says so when that happens.")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
            }
            .padding(.horizontal, 24).padding(.vertical, 16)
            .frame(maxWidth: 820, alignment: .leading)
        }
    }
}

struct PacketsSidebarRow: View {
    @ObservedObject var cap: PacketCapture
    var selected: Bool
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "square.3.layers.3d").font(.system(size: 14))
                .foregroundStyle(selected ? Theme.text : Theme.secondary).frame(width: 20)
            VStack(alignment: .leading, spacing: 1) {
                Text("Packets").font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                Text(cap.state == .running ? "\(Int(cap.rate.rounded())) /s" : "OSI layers")
                    .font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(selected ? Theme.raised : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}
