import SwiftUI
import AppKit
import UniformTypeIdentifiers

extension Theme {
    /// One colour per OSI layer, index 0 = layer 1. Layer 7 keeps the app's yellow accent.
    static let layer: [Color] = [0x8B9099, 0xB48CFF, 0x3DDC84, 0x5AB0FF, 0x4FD1C5, 0xFF9F43, 0xFFD23F].map { Color(hex: $0) }
}

/// Plain-English help: a letter-in-the-post analogy per layer and what each field means.
enum Explain {
    static let analogy = [
        "the road and the truck — radio waves or a cable carry the bits",
        "the local mail carrier — hands it to the next stop on your street, usually your router",
        "the full address on the envelope — post offices pass it city to city until it arrives",
        "the apartment number — which app in the building gets it, with pages numbered so none go missing",
        "keeping the phone line open — hello, the talk, goodbye",
        "sealing the letter in a locked box that only the receiver can open",
        "the letter itself — what you actually wanted to say",
    ]
    static let examples = ["Wi-Fi radio, Ethernet cable", "Wi-Fi / Ethernet frames, MAC addresses", "IP addresses, ping",
                           "TCP, UDP, ports", "TCP handshake, TLS session", "TLS encryption", "Web pages, DNS, SSH"]

    static let hints: [String: String] = [
        "Interface": "Which network connection saw it. On a Mac, en0 is usually Wi-Fi.",
        "On the wire": "The full size of the packet as it travelled.",
        "Captured": "How much of it Dolkoon kept to show you.",
        "Not captured": "A few bytes of timing and error checking never reach the computer.",
        "From MAC": "The hardware ID of the device that sent this. Every network card has one.",
        "To MAC": "The next device it's handed to — usually your router, not the final destination.",
        "Carries": "What kind of thing is packed inside this layer.",
        "Family": "What kind of thing is packed inside this layer.",
        "From IP": "The internet address of the sender.",
        "To IP": "The internet address of the receiver.",
        "TTL": "How many more routers it may pass. Each router takes one off; at zero it's thrown away, so lost packets can't loop forever.",
        "Hop limit": "How many more routers it may pass. Each router takes one off; at zero it's thrown away.",
        "Length": "Size of this IP packet, headers included.",
        "Fragment": "Too big for one trip, so it was cut into pieces that get glued back together.",
        "From port": "Which app sent it. Big random numbers are temporary ports your Mac picks for one conversation.",
        "To port": "Which app should get it. 443 = secure websites, 53 = DNS, 80 = plain websites.",
        "Flags": "SYN = let's talk · ACK = got it · FIN = goodbye · PSH = deliver now · RST = hang up.",
        "Seq": "A byte counter, so the receiver can put pieces back in the right order.",
        "Ack": "“I have everything up to here” — tells the other side what arrived.",
        "Window": "How much more data the receiver can take right now. Stops a fast sender drowning a slow one.",
        "Data": "How many bytes of the app's own message ride in this packet.",
        "Record": "The kind of TLS message.",
        "Record size": "Size of the TLS message.",
        "Handshake": "Which step of setting up encryption this is.",
        "Server name": "The website's name. It is sent before encryption starts, so your network can see which site — but not what's on it.",
        "App protocol": "The language spoken inside the lock: h2 = HTTP/2, http/1.1 = older web.",
        "Packet": "The kind of QUIC packet.",
        "Version": "Which version of QUIC.",
        "Kind": "Question or answer.",
        "Asks for": "A = IPv4 address · AAAA = IPv6 address · PTR = who offers a service.",
        "Answer": "What came back.",
        "Line": "The first line of the request or reply.",
        "Host": "The website name asked for.",
        "Asks": "ARP asks a question (request) or answers one (reply).",
        "Sender": "IP and hardware address of the device speaking.",
        "Target": "The IP address it wants the hardware address for.",
        "Note": "",
    ]

    static func hint(_ key: String) -> String? {
        if key.hasSuffix(" type") { return "The kind of control message, as a number." }
        return hints[key].flatMap { $0.isEmpty ? nil : $0 }
    }
}

enum PacketMode: String, CaseIterable {
    case stories = "Stories", conversations = "Conversations", table = "Table"
}

/// One-click filters in everyday words.
enum QuickFilter: String, CaseIterable {
    case all = "All", web = "Websites", lookups = "Name lookups", nearby = "Nearby devices", locked = "Encrypted", readable = "Readable"

    static let webPorts: Set<Int> = [80, 443, 8080, 8443]

    var help: String {
        switch self {
        case .all: return "Everything"
        case .web: return "Web pages and apps talking to web servers"
        case .lookups: return "DNS: turning names like apple.com into addresses"
        case .nearby: return "Your router, printers, speakers, other devices at home"
        case .locked: return "Data nobody in between can read (HTTPS, QUIC, SSH)"
        case .readable: return "Data anyone on the path could read (DNS, plain HTTP)"
        }
    }

    func match(_ p: Packet) -> Bool {
        switch self {
        case .all: return true
        case .web: return Self.webPorts.contains(p.dport) || Self.webPorts.contains(p.sport)
        case .lookups: return ["DNS", "mDNS", "LLMNR"].contains(p.proto)
        case .nearby:
            return ["ARP", "mDNS", "SSDP", "DHCP", "LLMNR", "ICMPv6"].contains(p.proto)
                || [p.srcName, p.dstName].contains { $0.contains("router") || $0.contains("network") || $0.contains("nearby") }
        case .locked: return p.encrypted
        case .readable: return p.appBytes > 0 && !p.encrypted
        }
    }
}

struct PacketView: View {
    @ObservedObject var cap: PacketCapture
    @AppStorage("packetsMode") private var mode = PacketMode.stories
    @AppStorage("packetsHideAcks") private var hideNoise = true
    @State private var selectedID: Int?
    @State private var filter = ""
    @State private var quick = QuickFilter.all
    @State private var follow = true
    @State private var focus: Int?

    var body: some View {
        let filtered = cap.packets.filter { quick.match($0) && (filter.isEmpty || $0.matches(filter)) }
        let shown = mode == .stories && hideNoise ? filtered.filter { !$0.noise } : filtered
        let selected = selectedID.flatMap { id in cap.packets.last { $0.id == id } }
        VStack(spacing: 0) {
            PacketHeader(cap: cap, filter: $filter, mode: $mode, quick: $quick).padding(.horizontal, 24).padding(.top, 18).padding(.bottom, 12)
            if cap.state == .needsPermission { PermissionBanner(cap: cap).padding(.horizontal, 24).padding(.bottom, 12) }
            if case .failed(let e) = cap.state { ErrorBanner(text: e).padding(.horizontal, 24).padding(.bottom, 12) }
            VSplitView {
                Group {
                    switch mode {
                    case .stories:
                        StoryList(packets: shown, hidden: filtered.count - shown.count, t0: cap.packets.first?.time,
                                  empty: emptyText(filtered.isEmpty && !cap.packets.isEmpty),
                                  hideNoise: $hideNoise, selectedID: $selectedID, follow: $follow)
                    case .conversations:
                        ConversationList(cap: cap) { c in filter = c.remoteIP; quick = .all; mode = .stories }
                    case .table:
                        PacketTable(packets: shown, t0: cap.packets.first?.time, selectedID: $selectedID, follow: $follow)
                    }
                }
                .frame(minHeight: 150, idealHeight: 250)
                Group {
                    if let p = selected {
                        PacketDetail(packet: p, t0: cap.packets.first?.time, focus: $focus)
                    } else {
                        OSIGuide(showDemo: cap.packets.isEmpty) { cap.loadDemo() }
                    }
                }
                .frame(minHeight: 320, maxHeight: .infinity)
                .background(Theme.bg)
            }
        }
        .background(Theme.bg)
        .onAppear { if cap.state == .idle { cap.start() } }
        .onDisappear { cap.pause() }
        .onChange(of: selectedID) { focus = selected?.top }
    }

    func emptyText(_ filteredOut: Bool) -> String {
        if filteredOut { return "Nothing matches this filter yet." }
        switch cap.state {
        case .running: return "Listening… open a website and packets will appear here."
        case .needsPermission: return "Capture needs your OK above — or try the demo."
        default: return "No packets yet. Press Capture, open a capture file, or try the demo."
        }
    }
}

struct PacketHeader: View {
    @ObservedObject var cap: PacketCapture
    @Binding var filter: String
    @Binding var mode: PacketMode
    @Binding var quick: QuickFilter
    @State private var help = false

    var status: String {
        switch cap.state {
        case .idle: return "Not capturing"
        case .running: return "Live on \(cap.iface) · \(Int(cap.rate.rounded())) packets a second · \(cap.total) seen"
        case .paused: return "Paused · \(cap.total) seen"
        case .needsPermission: return "Waiting for your permission"
        case .failed: return "Capture stopped"
        case .file(let name): return "\(name) · \(cap.packets.count) packets"
        case .demo: return "Demo — a made-up visit to example.com"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .center, spacing: 10) {
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 8) {
                        Text("Packets").font(.system(size: 24, weight: .semibold)).foregroundStyle(Theme.text)
                        Button { help.toggle() } label: {
                            Image(systemName: "questionmark.circle").font(.system(size: 15)).foregroundStyle(Theme.tertiary)
                        }
                        .buttonStyle(.plain).help("What am I looking at?")
                        .popover(isPresented: $help, arrowEdge: .bottom) { HelpPopover() }
                    }
                    HStack(spacing: 6) {
                        Circle().fill(cap.state == .running ? Theme.live : Theme.tertiary).frame(width: 6, height: 6)
                        Text(status).font(.system(size: 12)).monospacedDigit().foregroundStyle(Theme.tertiary).lineLimit(1)
                    }
                }
                Spacer(minLength: 8)
                Picker("", selection: $mode) {
                    ForEach(PacketMode.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 250)
                Picker("", selection: $cap.iface) {
                    ForEach(cap.interfaces, id: \.self) { Text($0).tag($0) }
                }
                .labelsHidden().frame(width: 84)
                .help("Which network connection to watch. en0 is usually Wi-Fi.")
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
                    Button("Save capture as .pcap…") { saveFile() }.disabled(cap.packets.isEmpty)
                    Divider()
                    Button("Demo packets") { cap.loadDemo() }
                } label: { Image(systemName: "ellipsis.circle") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).frame(width: 28)
            }
            HStack(spacing: 6) {
                ForEach(QuickFilter.allCases, id: \.self) { q in
                    Button { quick = q } label: {
                        Text(q.rawValue).font(.system(size: 11.5, weight: .medium))
                            .foregroundStyle(quick == q ? Color.black.opacity(0.85) : Theme.secondary)
                            .padding(.horizontal, 10).padding(.vertical, 5)
                            .background(quick == q ? Theme.accent : Theme.surface, in: Capsule())
                    }
                    .buttonStyle(.plain).help(q.help)
                }
                HStack(spacing: 6) {
                    Image(systemName: "magnifyingglass").font(.system(size: 10.5)).foregroundStyle(Theme.tertiary)
                    TextField("Search names, IPs, ports…", text: $filter).textFieldStyle(.plain).font(.system(size: 12))
                    if !filter.isEmpty {
                        Button { filter = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(Theme.tertiary) }.buttonStyle(.plain)
                    }
                }
                .padding(.horizontal, 10).padding(.vertical, 5)
                .background(Theme.surface, in: Capsule())
                .frame(minWidth: 120, maxWidth: 220)
                Spacer(minLength: 8)
                PrivacyMeter(locked: cap.lockedBytes, readable: cap.readableBytes)
            }
            if mode == .table { ProtocolMix(cap: cap) }
        }
    }

    func openFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = ["pcap", "pcapng", "cap"].compactMap { UTType(filenameExtension: $0) } + [.data]
        if panel.runModal() == .OK, let url = panel.url { cap.open(url) }
    }

    func saveFile() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "dolkoon-capture.pcap"
        panel.allowedContentTypes = [UTType(filenameExtension: "pcap") ?? .data]
        if panel.runModal() == .OK, let url = panel.url { try? cap.save(to: url) }
    }
}

/// How much of the app data seen so far was locked vs readable by anyone on the path.
struct PrivacyMeter: View {
    let locked: Int, readable: Int
    var body: some View {
        let all = locked + readable
        if all > 0 {
            let f = Double(locked) / Double(all)
            HStack(spacing: 8) {
                Image(systemName: f >= 0.5 ? "lock.fill" : "lock.open.fill").font(.system(size: 11))
                    .foregroundStyle(f >= 0.5 ? Theme.live : Theme.stalled)
                VStack(alignment: .leading, spacing: 3) {
                    Text("\(Int((f * 100).rounded()))% encrypted").font(.system(size: 11.5, weight: .semibold)).foregroundStyle(Theme.text)
                    GeometryReader { g in
                        HStack(spacing: 1) {
                            Capsule().fill(Theme.live).frame(width: max(2, g.size.width * f))
                            Capsule().fill(Theme.stalled)
                        }
                    }
                    .frame(width: 92, height: 3)
                }
            }
            .help("Of the app data seen so far: \(PacketDecoder.sizeWords(locked)) was locked (HTTPS, QUIC, SSH) and \(PacketDecoder.sizeWords(readable)) could be read by anyone on the path (DNS lookups, plain HTTP).")
        }
    }
}

struct HelpPopover: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("What am I looking at?").font(.system(size: 14, weight: .semibold))
            Text("Everything your Mac sends or receives online is cut into small pieces called packets — usually under 1,500 bytes each. Loading one web page can take hundreds of them.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Each packet is wrapped in layers, like a letter inside an envelope inside a mailbag. The colours show which layer each part belongs to:")
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 5) {
                ForEach((1...7).reversed(), id: \.self) { n in
                    HStack(spacing: 8) {
                        LayerBadge(n: n, size: 18)
                        Text(OSI.names[n - 1]).font(.system(size: 12, weight: .medium)).frame(width: 90, alignment: .leading)
                        Text(OSI.roles[n - 1]).font(.system(size: 11.5)).foregroundStyle(.secondary)
                    }
                }
            }
            Text("Dolkoon only watches this Mac's own traffic. It can see who your Mac talks to, but encrypted content (HTTPS) stays locked — to Dolkoon too.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        .font(.system(size: 12.5))
        .padding(18).frame(width: 440)
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
                             : "macOS needs your OK before Dolkoon can watch packets")
                    .font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                Text(cap.canGrant
                     ? "Allow adds your user to the access_bpf group, the same thing Wireshark does. It asks for your Mac password. Meanwhile, try the demo."
                     : "Install Wireshark's ChmodBPF (Wireshark.app › Contents › Resources › Extras), then press Capture. Meanwhile, try the demo.")
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

struct LayerBadge: View {
    let n: Int
    var size: CGFloat = 26
    var dim = false
    var body: some View {
        let c = Theme.layer[n - 1]
        Text("\(n)").font(.system(size: size * 0.5, weight: .bold, design: .rounded))
            .foregroundStyle(dim ? c : Color.black.opacity(0.85))
            .frame(width: size, height: size)
            .background(c.opacity(dim ? 0.14 : 1), in: RoundedRectangle(cornerRadius: size * 0.27, style: .continuous))
    }
}

// MARK: lists

private extension View {
    /// Up/down arrows move the selection through `packets`.
    func arrowKeys(_ ids: [Int], _ selectedID: Binding<Int?>, _ follow: Binding<Bool>) -> some View {
        func step(_ d: Int) -> KeyPress.Result {
            guard !ids.isEmpty else { return .ignored }
            let i = ids.firstIndex { $0 == selectedID.wrappedValue } ?? (d > 0 ? -1 : ids.count)
            selectedID.wrappedValue = ids[max(0, min(ids.count - 1, i + d))]
            follow.wrappedValue = false
            return .handled
        }
        return focusable().focusEffectDisabled()
            .onKeyPress(.upArrow) { step(-1) }
            .onKeyPress(.downArrow) { step(1) }
    }
}

struct FollowButton: View {
    @Binding var follow: Bool
    var body: some View {
        Button { follow.toggle() } label: {
            Label(follow ? "Following" : "Follow", systemImage: "arrow.down.to.line")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(follow ? Theme.accent : Theme.tertiary)
        }
        .buttonStyle(.plain).help(follow ? "Jumping to new packets as they arrive" : "Jump to new packets as they arrive")
    }
}

/// A run of packets that say the same thing ("example.com sent encrypted data…"), shown as one line.
struct StoryItem: Identifiable {
    var first: Packet
    var last: Packet
    var count = 1
    var bytes: Int
    var id: Int { first.id }

    var text: String {
        guard count > 1, !last.group.isEmpty else { return last.story }
        var t = last.group.replacingOccurrences(of: "{N}", with: PacketDecoder.sizeWords(bytes))
        if t.hasPrefix("{S}") { t = DecoderLabel.title(last.srcName) + t.dropFirst(3) }
        return t.replacingOccurrences(of: "{S}", with: last.srcName).replacingOccurrences(of: "{D}", with: last.dstName)
    }

    static func group(_ ps: [Packet]) -> [StoryItem] {
        var out: [StoryItem] = []
        for p in ps {
            if var g = out.last, !p.group.isEmpty, p.group == g.last.group, p.srcIP == g.last.srcIP, p.dstIP == g.last.dstIP,
               p.app == g.last.app, p.time.timeIntervalSince(g.last.time) < 3 {
                g.last = p; g.count += 1; g.bytes += p.appBytes
                out[out.count - 1] = g
            } else {
                out.append(StoryItem(first: p, last: p, bytes: p.appBytes))
            }
        }
        return out
    }
}

/// Stories mode: one plain-English sentence per packet, with repeats folded together.
struct StoryList: View {
    let packets: [Packet]
    let hidden: Int
    let t0: Date?
    let empty: String
    @Binding var hideNoise: Bool
    @Binding var selectedID: Int?
    @Binding var follow: Bool

    var body: some View {
        let items = StoryItem.group(packets)
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("What's happening").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.secondary)
                if hidden > 0 || !hideNoise {
                    Button {
                        hideNoise.toggle()
                    } label: {
                        Text(hideNoise ? "\(hidden) “got it” replies hidden · Show" : "Hide “got it” replies")
                            .font(.system(size: 11)).foregroundStyle(Theme.tertiary)
                    }
                    .buttonStyle(.plain)
                    .help("TCP confirms every piece it receives. Those confirmations are useful but repetitive.")
                }
                Spacer()
                FollowButton(follow: $follow)
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
            Divider1()
            if items.isEmpty {
                VStack(spacing: 8) {
                    Image(systemName: "dot.radiowaves.left.and.right").font(.system(size: 22)).foregroundStyle(Theme.tertiary)
                    Text(empty).font(.system(size: 12.5)).foregroundStyle(Theme.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(items) { item in
                                StoryRow(item: item, t0: t0, selected: (item.first.id...item.last.id).contains(selectedID ?? -1))
                                    .id(item.id)
                                    .contentShape(Rectangle())
                                    .onTapGesture { selectedID = item.last.id; follow = false }
                            }
                        }
                    }
                    .onChange(of: items.last?.last.id) { if follow, let id = items.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
                }
            }
        }
        .background(Theme.surface)
        .arrowKeys(items.map(\.last.id), $selectedID, $follow)
    }
}

struct StoryRow: View {
    let item: StoryItem
    let t0: Date?
    let selected: Bool
    var body: some View {
        let packet = item.last
        let c = Theme.layer[packet.top - 1]
        HStack(spacing: 10) {
            Text(String(format: "%.1fs", item.first.time.timeIntervalSince(t0 ?? packet.time)))
                .font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.tertiary).frame(width: 44, alignment: .trailing)
            Image(systemName: packet.sent == true ? "arrow.up.right" : packet.sent == false ? "arrow.down.left" : "arrow.left.arrow.right")
                .font(.system(size: 11, weight: .bold)).foregroundStyle(c).frame(width: 14)
                .help(packet.sent == true ? "Sent by your Mac" : packet.sent == false ? "Arrived at your Mac" : "Seen on the network")
            Group {
                if packet.app.isEmpty { Color.clear } else { ProcIcon(name: packet.app, args: packet.appPath, size: 16).help(packet.app) }
            }
            .frame(width: 16, height: 16)
            Text(item.text).font(.system(size: 13)).foregroundStyle(selected ? Theme.text : Theme.secondary)
                .lineLimit(1).truncationMode(.tail)
            if item.count > 1 {
                Text("×\(item.count)").font(.system(size: 10.5, weight: .semibold)).monospacedDigit().foregroundStyle(Theme.tertiary)
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background(Theme.raised, in: Capsule())
                    .help("\(item.count) packets in a row saying the same thing")
            }
            Spacer(minLength: 10)
            if packet.encrypted {
                Image(systemName: "lock.fill").font(.system(size: 9.5)).foregroundStyle(Theme.tertiary).help("Encrypted")
            }
            HStack(spacing: 5) {
                RoundedRectangle(cornerRadius: 2).fill(c).frame(width: 7, height: 7)
                Text(packet.proto).font(.system(size: 11, weight: .medium)).foregroundStyle(Theme.tertiary).lineLimit(1)
            }
            .frame(width: 84, alignment: .leading)
        }
        .padding(.horizontal, 14)
        .frame(height: 30)
        .background(selected ? Theme.accentSoft : .clear)
    }
}

/// Conversations mode: everyone this Mac talked to, busiest first.
struct ConversationList: View {
    @ObservedObject var cap: PacketCapture
    var open: (PacketCapture.Conversation) -> Void
    @State private var byRecent = false

    var body: some View {
        let list = cap.conversations.values.sorted {
            byRecent ? $0.last > $1.last : ($0.bytesIn + $0.bytesOut, $0.last) > ($1.bytesIn + $1.bytesOut, $1.last)
        }
        let peak = max(list.map { $0.bytesIn + $0.bytesOut }.max() ?? 1, 1)
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Text("Who your Mac is talking to").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.secondary)
                Text("\(list.count)").font(.system(size: 11)).foregroundStyle(Theme.tertiary)
                Spacer()
                Picker("", selection: $byRecent) {
                    Text("Busiest").tag(false)
                    Text("Latest").tag(true)
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 140)
            }
            .padding(.horizontal, 16).padding(.vertical, 6)
            Divider1()
            if list.isEmpty {
                Text("No conversations yet.").font(.system(size: 12.5)).foregroundStyle(Theme.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(list) { c in
                            ConversationRow(c: c, peak: peak, now: cap.packets.last?.time ?? c.last)
                                .contentShape(Rectangle())
                                .onTapGesture { open(c) }
                            Divider1(inset: 54)
                        }
                    }
                }
            }
        }
        .background(Theme.surface)
    }
}

struct ConversationRow: View {
    let c: PacketCapture.Conversation
    let peak: Int
    let now: Date
    var body: some View {
        let total = c.bytesIn + c.bytesOut
        HStack(spacing: 12) {
            GlyphTile(symbol: c.name == "your router" ? "wifi.router" : c.name.contains("nearby") || c.name.contains("everyone") ? "dot.radiowaves.left.and.right"
                      : c.name.contains("on your network") ? "desktopcomputer" : "globe", size: 30, tint: Theme.layer[c.top - 1])
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(DecoderLabel.title(c.name)).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text)
                        .lineLimit(1).truncationMode(.middle)
                    Text(c.service).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Color.black.opacity(0.8))
                        .padding(.horizontal, 6).padding(.vertical, 1.5)
                        .background(Theme.layer[c.top - 1].opacity(0.9), in: Capsule())
                    if c.encrypted && !c.readable {
                        Image(systemName: "lock.fill").font(.system(size: 10)).foregroundStyle(Theme.live).help("Everything was encrypted")
                    } else if c.readable {
                        Image(systemName: "lock.open.fill").font(.system(size: 10)).foregroundStyle(Theme.stalled).help("Some data could be read by anyone on the path")
                    }
                }
                Text(subtitle).font(.system(size: 11)).foregroundStyle(Theme.tertiary).lineLimit(1)
            }
            Spacer(minLength: 10)
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.06))
                Capsule().fill(Theme.accent.opacity(0.85)).frame(width: max(3, 90 * CGFloat(total) / CGFloat(peak)))
            }
            .frame(width: 90, height: 4)
            VStack(alignment: .trailing, spacing: 2) {
                Text("↓ \(fmtBytes(Double(c.bytesIn)))").foregroundStyle(Theme.text)
                Text("↑ \(fmtBytes(Double(c.bytesOut)))").foregroundStyle(Theme.tertiary)
            }
            .font(.system(size: 11.5)).monospacedDigit().frame(width: 84, alignment: .trailing)
            Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(Theme.tertiary)
        }
        .padding(.horizontal, 14).padding(.vertical, 9)
        .help("Show only this conversation")
    }

    var subtitle: String {
        var parts = [c.remoteIP]
        if !c.app.isEmpty { parts.append("via \(c.app)") }
        parts.append(c.packets == 1 ? "1 packet" : "\(c.packets) packets")
        let ago = Int(now.timeIntervalSince(c.last))
        parts.append(ago < 2 ? "just now" : "\(ago)s ago")
        return parts.joined(separator: " · ")
    }
}

/// Detailed mode: a classic packet table.
struct PacketTable: View {
    let packets: [Packet]
    let t0: Date?
    @Binding var selectedID: Int?
    @Binding var follow: Bool

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 0) {
                PacketColumns(no: "No.", time: "Time", app: "App", src: "Source", dst: "Destination", proto: "Protocol", len: "Length", info: "Info")
                FollowButton(follow: $follow).labelStyle(.iconOnly).padding(.trailing, 12)
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
                .onChange(of: packets.last?.id) { if follow, let id = packets.last?.id { proxy.scrollTo(id, anchor: .bottom) } }
                .onChange(of: selectedID) { if let id = selectedID { proxy.scrollTo(id) } }
            }
        }
        .background(Theme.surface)
        .arrowKeys(packets.map(\.id), $selectedID, $follow)
    }
}

struct PacketColumns: View {
    let no: String, time: String, app: String, src: String, dst: String, proto: String, len: String, info: String
    var protoColor: Color? = nil
    var body: some View {
        HStack(spacing: 10) {
            Text(no).frame(width: 46, alignment: .trailing)
            Text(time).frame(width: 62, alignment: .trailing)
            Text(app).lineLimit(1).truncationMode(.tail).frame(width: 74, alignment: .leading)
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
                      app: packet.app.isEmpty ? "—" : packet.app,
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
    let t0: Date?
    @Binding var focus: Int?
    var body: some View {
        GeometryReader { g in
            let wide = g.size.width > 860
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    StoryCard(packet: packet, t0: t0)
                    JourneyView(packet: packet)
                    VStack(alignment: .leading, spacing: 12) {
                        SectionHeading(title: "Inside the packet",
                                       note: "Click a layer to see its real values and what they mean.")
                        EncapsulationBar(packet: packet, focus: $focus)
                        HStack(alignment: .top, spacing: 16) {
                            OSIStack(packet: packet, focus: $focus).frame(minWidth: 280, maxWidth: .infinity)
                            BytesPanel(packet: packet, focus: focus, perRow: wide ? 16 : 8)
                                .frame(width: wide ? 392 : 228, height: 420)
                        }
                    }
                }
                .padding(.horizontal, 24).padding(.vertical, 18)
                .frame(maxWidth: 1180, alignment: .leading)
            }
        }
    }
}

struct SectionHeading: View {
    let title: String
    var note: String = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 15, weight: .semibold)).foregroundStyle(Theme.text)
            if !note.isEmpty { Text(note).font(.system(size: 12)).foregroundStyle(Theme.tertiary) }
        }
    }
}

/// "What happened" — the packet as one sentence, why it exists, and who it went between.
struct StoryCard: View {
    let packet: Packet
    let t0: Date?
    var body: some View {
        let c = Theme.layer[packet.top - 1]
        Card {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Label(packet.sent == true ? "Sent by your Mac" : packet.sent == false ? "Arrived at your Mac" : "Seen on the network",
                          systemImage: packet.sent == true ? "arrow.up.right" : packet.sent == false ? "arrow.down.left" : "arrow.left.arrow.right")
                        .font(.system(size: 11.5, weight: .semibold)).foregroundStyle(c)
                    Spacer()
                    Text("Packet \(packet.id) · \(DecoderSize.words(packet.wireLength)) · \(String(format: "%.2f", packet.time.timeIntervalSince(t0 ?? packet.time))) s")
                        .font(.system(size: 11.5)).monospacedDigit().foregroundStyle(Theme.tertiary)
                }
                Text(packet.story).font(.system(size: 19, weight: .semibold)).foregroundStyle(Theme.text)
                    .fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
                if !packet.why.isEmpty {
                    Text(packet.why).font(.system(size: 13.5)).foregroundStyle(Theme.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                AppLine(packet: packet)
                HStack(spacing: 10) {
                    Endpoint(label: "From", name: packet.srcName, raw: packet.src)
                    Image(systemName: "arrow.right").font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.tertiary)
                    Endpoint(label: "To", name: packet.dstName, raw: packet.dst)
                    Spacer(minLength: 0)
                }
                .padding(.top, 2)
            }
            .padding(18)
        }
    }
}

/// Which app on this Mac sent or received the packet, with its real icon.
struct AppLine: View {
    let packet: Packet
    var body: some View {
        if packet.sent != nil {
            HStack(spacing: 10) {
                if packet.app.isEmpty {
                    GlyphTile(symbol: "gearshape.2", size: 26)
                } else {
                    ProcIcon(name: packet.app, args: packet.appPath, size: 26)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(packet.app.isEmpty ? "App: probably a macOS system service" : "App: \(packet.app)")
                        .font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                    Text(verbatim: packet.app.isEmpty
                         ? "Lookups, time sync and Bonjour run as system services that only an admin can see. Dolkoon can't name them."
                         : "\(packet.sent == true ? "Sent from" : "Delivered to") port \(String(packet.sent == true ? packet.sport : packet.dport)), which \(packet.app) opened. The port number is how your Mac knows which app gets what.")
                        .font(.system(size: 11.5)).foregroundStyle(Theme.tertiary).fixedSize(horizontal: false, vertical: true)
                }
            }
            .padding(.horizontal, 12).padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        }
    }
}

struct Endpoint: View {
    let label: String, name: String, raw: String
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label).font(.system(size: 10.5, weight: .semibold)).foregroundStyle(Theme.tertiary)
            Text(name.isEmpty ? raw : DecoderLabel.title(name)).font(.system(size: 13, weight: .medium)).foregroundStyle(Theme.text).lineLimit(1).truncationMode(.middle)
            if !name.isEmpty, name != raw {
                Text(raw).font(.system(size: 10.5, design: .monospaced)).foregroundStyle(Theme.tertiary).lineLimit(1).truncationMode(.middle)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Theme.raised, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
    }
}

enum DecoderSize {
    static func words(_ n: Int) -> String { PacketDecoder.sizeWords(n) }
}

/// Animated trip: down the sender's layers (each adds its header), across the wire, up the receiver's (each removes it).
struct JourneyView: View {
    let packet: Packet
    var frozenStep: Int? = nil   // QA renders pin a step instead of animating
    @State private var step = 0
    @State private var run = 0

    static let rowH: CGFloat = 30, gap: CGFloat = 4, titleH: CGFloat = 26

    var top: Int { max(1, packet.top) }
    var total: Int { top * 2 + 1 }

    /// side −1 = sender, 0 = on the wire, 1 = receiver.
    func place(_ s: Int) -> (side: Int, layer: Int) {
        if s < top { return (-1, top - s) }
        if s == top { return (0, 1) }
        return (1, min(top, s - top))
    }

    func carried(_ n: Int) -> Bool { let l = packet.layer(n); return l.present && (l.range != nil || n == top) }

    var body: some View {
        let step = frozenStep ?? self.step
        let pl = place(step)
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                SectionHeading(title: "Its journey", note: "Each layer wraps the packet on the way down, and unwraps it on the way up.")
                Spacer()
                HStack(spacing: 14) {
                    Button { withAnimation(.easeInOut(duration: 0.45)) { self.step = max(0, step - 1) } } label: { Image(systemName: "chevron.left") }
                        .disabled(step == 0)
                    Button { run += 1 } label: { Label("Replay", systemImage: "arrow.counterclockwise").font(.system(size: 12, weight: .medium)) }
                    Button { withAnimation(.easeInOut(duration: 0.45)) { self.step = min(total - 1, step + 1) } } label: { Image(systemName: "chevron.right") }
                        .disabled(step == total - 1)
                }
                .buttonStyle(.plain).foregroundStyle(Theme.secondary)
            }
            Card {
                VStack(alignment: .leading, spacing: 14) {
                    GeometryReader { g in
                        let w = g.size.width
                        let colW = min(210, w * 0.3)
                        let y = { (n: Int) in Self.titleH + CGFloat(7 - n) * (Self.rowH + Self.gap) + Self.rowH / 2 }
                        let blocks = envelope(pl)
                        let envW = blocks.reduce(0) { $0 + $1.width } + CGFloat(max(0, blocks.count - 1)) * 2
                        let x: CGFloat = pl.side < 0 ? colW + 14 + envW / 2 : pl.side > 0 ? w - colW - 14 - envW / 2 : w / 2
                        ZStack(alignment: .topLeading) {
                            Path { p in p.move(to: CGPoint(x: colW, y: y(1))); p.addLine(to: CGPoint(x: w - colW, y: y(1))) }
                                .stroke(Theme.tertiary.opacity(0.6), style: StrokeStyle(lineWidth: 1.5, dash: [4, 4]))
                            Text(packet.layer(1).proto).font(.system(size: 10.5)).foregroundStyle(Theme.tertiary)
                                .position(x: w / 2, y: y(1) + 22)
                            DeviceStack(title: packet.srcName.isEmpty ? "Sender" : packet.srcName, packet: packet, top: top,
                                        active: pl.side < 0 ? pl.layer : nil)
                                .frame(width: colW).offset(x: 0)
                            DeviceStack(title: packet.dstName.isEmpty ? "Receiver" : packet.dstName, packet: packet, top: top,
                                        active: pl.side > 0 ? pl.layer : nil)
                                .frame(width: colW).offset(x: w - colW)
                            HStack(spacing: 2) {
                                ForEach(blocks) { b in
                                    RoundedRectangle(cornerRadius: 3, style: .continuous).fill(b.color).frame(width: b.width, height: 20)
                                }
                            }
                            .padding(3)
                            .background(Theme.bg.opacity(0.9), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                            .shadow(color: .black.opacity(0.45), radius: 6, y: 3)
                            .position(x: x, y: y(pl.layer))
                        }
                    }
                    .frame(height: Self.titleH + 7 * (Self.rowH + Self.gap) + 14)
                    HStack(alignment: .top, spacing: 10) {
                        LayerBadge(n: pl.side == 0 ? 1 : pl.layer, size: 20)
                        Text(caption(pl)).font(.system(size: 13)).foregroundStyle(Theme.text)
                            .fixedSize(horizontal: false, vertical: true)
                            .id(step).transition(.opacity)
                        Spacer(minLength: 0)
                    }
                    HStack(spacing: 4) {
                        ForEach(0..<total, id: \.self) { s in
                            Capsule().fill(s == step ? Theme.accent : s < step ? Theme.secondary.opacity(0.5) : Color.white.opacity(0.08))
                                .frame(height: 4)
                                .contentShape(Rectangle().inset(by: -6))
                                .onTapGesture { withAnimation(.easeInOut(duration: 0.45)) { self.step = s } }
                        }
                    }
                }
                .padding(18)
            }
        }
        .task(id: "\(packet.id)-\(run)") {
            self.step = 0
            for s in 1..<total {
                try? await Task.sleep(nanoseconds: 1_050_000_000)
                if Task.isCancelled { return }
                withAnimation(.easeInOut(duration: 0.5)) { self.step = s }
            }
        }
    }

    struct Block: Identifiable { let id: Int; let color: Color; let width: CGFloat }

    /// Headers currently wrapped around the message, lowest layer first (outermost).
    func envelope(_ pl: (side: Int, layer: Int)) -> [Block] {
        let lo = pl.side == 0 ? 1 : pl.layer
        return (lo...top).filter { carried($0) && $0 > 1 }.map { Block(id: $0, color: Theme.layer[$0 - 1], width: $0 == top ? 34 : 15) }
            + (top == 1 ? [Block(id: 1, color: Theme.layer[0], width: 34)] : [])
    }

    func caption(_ pl: (side: Int, layer: Int)) -> String {
        let l = packet.layer(pl.layer), name = OSI.names[pl.layer - 1]
        let who = packet.srcName.isEmpty ? "The sender" : DecoderLabel.title(packet.srcName)
        switch pl.side {
        case -1 where pl.layer == top:
            return "\(name) layer: \(who) writes the message — \(l.proto): “\(l.summary)”"
        case -1:
            let hdr = DecoderLabel.short(l.proto)
            return carried(pl.layer) ? "\(name) layer adds \(DecoderLabel.article(hdr)) \(hdr) header — \(l.summary)."
                : l.present ? "\(name) layer: \(l.proto) — \(l.summary). No extra bytes added."
                : "\(name) layer: nothing added here — \(l.summary.lowercased())."
        case 0:
            return "On the wire: \(packet.wireLength) bytes travel as \(packet.layer(1).proto.lowercased()) signals."
                + (top >= 4 ? " Routers on the way only open it up to layer 3 to read the address." : "")
        default:
            if pl.layer == top {
                return "\(name) layer: \(packet.dstName.isEmpty ? "the receiver" : packet.dstName) gets the message — “\(l.summary)”"
            }
            return carried(pl.layer) ? "\(name) layer reads the \(DecoderLabel.short(l.proto)) header, removes it, and passes the rest up."
                : "\(name) layer: nothing to unwrap here."
        }
    }
}

struct DeviceStack: View {
    let title: String
    let packet: Packet
    let top: Int
    let active: Int?
    var body: some View {
        VStack(alignment: .leading, spacing: JourneyView.gap) {
            HStack(spacing: 6) {
                Image(systemName: title.hasSuffix("your Mac") ? "laptopcomputer" : title == "your router" ? "wifi.router" : "server.rack")
                    .font(.system(size: 11)).foregroundStyle(Theme.secondary)
                Text(DecoderLabel.title(title)).font(.system(size: 12, weight: .semibold)).foregroundStyle(Theme.text)
                    .lineLimit(1).truncationMode(.middle)
            }
            .frame(height: JourneyView.titleH - JourneyView.gap, alignment: .top)
            ForEach((1...7).reversed(), id: \.self) { n in
                let used = n <= top
                let on = active == n
                HStack(spacing: 7) {
                    LayerBadge(n: n, size: 18, dim: !used)
                    Text(OSI.names[n - 1]).font(.system(size: 11.5, weight: on ? .semibold : .regular))
                        .foregroundStyle(used ? Theme.text : Theme.tertiary).lineLimit(1)
                    Spacer(minLength: 2)
                }
                .padding(.horizontal, 6)
                .frame(height: JourneyView.rowH)
                .background(on ? Theme.layer[n - 1].opacity(0.28) : used ? Theme.raised : Theme.raised.opacity(0.4),
                            in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                .animation(.easeInOut(duration: 0.3), value: on)
            }
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
            Text("Read left to right: the outer wrapping comes first. Each layer puts its header in front of everything above it.")
                .font(.system(size: 11)).foregroundStyle(Theme.tertiary)
        }
        .animation(.easeOut(duration: 0.2), value: focus)
    }
}

enum DecoderLabel {
    /// "your Mac" → "Your Mac", but a domain like "example.com" stays as it is.
    static func title(_ s: String) -> String {
        ["your", "a", "the", "everyone", "nearby"].contains(String(s.split(separator: " ").first ?? "")) ? s.prefix(1).uppercased() + s.dropFirst() : s
    }

    static func article(_ word: String) -> String { "AEIOU".contains(word.prefix(1).uppercased()) ? "an" : "a" }

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
            LayerBadge(n: layer.osi, dim: !layer.present)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(OSI.names[layer.osi - 1]).font(.system(size: 11, weight: .semibold)).foregroundStyle(Theme.tertiary)
                    Text(layer.present ? layer.proto : "—").font(.system(size: 13.5, weight: .semibold))
                        .foregroundStyle(layer.present ? Theme.text : Theme.tertiary).lineLimit(1)
                    Spacer(minLength: 6)
                    if let r = layer.range {
                        Text("\(r.count) B").font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.tertiary)
                    }
                    Image(systemName: expanded ? "chevron.up" : "chevron.down").font(.system(size: 9, weight: .semibold))
                        .foregroundStyle(Theme.tertiary)
                }
                Text(layer.summary).font(.system(size: 12)).foregroundStyle(layer.present ? Theme.secondary : Theme.tertiary)
                    .lineLimit(expanded ? 4 : 1).truncationMode(.middle)
                HStack(alignment: .firstTextBaseline, spacing: 5) {
                    Image(systemName: layer.range == nil ? "minus" : layer.osi == 7 ? "doc.text" : "plus")
                        .font(.system(size: 9, weight: .bold)).foregroundStyle(layer.range == nil ? Theme.tertiary : c)
                    Text(adds).font(.system(size: 11.5)).foregroundStyle(layer.range == nil ? Theme.tertiary : Theme.secondary)
                        .lineLimit(expanded ? 3 : 1)
                }
                .padding(.top, 1)
                if expanded {
                    Text(OSI.roles[layer.osi - 1]).font(.system(size: 11.5, weight: .medium)).foregroundStyle(c).padding(.top, 4)
                    HStack(alignment: .top, spacing: 7) {
                        Image(systemName: "envelope").font(.system(size: 10.5)).foregroundStyle(Theme.tertiary).padding(.top, 2)
                        Text("Like \(Explain.analogy[layer.osi - 1]).").font(.system(size: 11.5)).foregroundStyle(Theme.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .padding(.horizontal, 10).padding(.vertical, 7)
                    .background(Theme.bg.opacity(0.55), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
                    if !layer.fields.isEmpty {
                        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 8) {
                            ForEach(layer.fields, id: \.self) { f in
                                GridRow {
                                    Text(f.key).font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(f.value).font(.system(size: 11.5, design: .monospaced)).foregroundStyle(Theme.text)
                                            .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                                        if let h = Explain.hint(f.key) {
                                            Text(h).font(.system(size: 11)).foregroundStyle(Theme.tertiary)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
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

    /// What this layer contributes to the packet, in bytes and in words.
    var adds: String {
        let skip: Set<String> = ["Data", "Captured", "On the wire", "Not captured", "Note", "Kind", "Interface", "Length", "Record size"]
        let plain = ["From MAC": "sender's hardware address", "To MAC": "next device's hardware address", "Carries": "what's inside",
                     "From IP": "sender's IP", "To IP": "receiver's IP", "From port": "sender's port", "To port": "receiver's port",
                     "Seq": "sequence number", "Ack": "“got up to here” number", "Window": "free space", "Family": "what's inside",
                     "TTL": "hops left (TTL)", "Hop limit": "hops left"]
        let what = layer.fields.map(\.key).filter { !skip.contains($0) }.map { plain[$0] ?? $0.lowercased() }
        let list = what.isEmpty ? "" : ": " + what.joined(separator: ", ")
        switch (layer.osi, layer.range) {
        case (1, _): return layer.osi == 1 && layer.proto == "Capture file" ? "Signals on the original wire — not saved in the file"
            : "Adds the signals themselves — timing and a checksum the network card strips off"
        case (7, let r?): return "Carries the message itself: \(r.count) bytes"
        case (6, let r?) where layer.proto == "TLS": return "Adds a \(r.count)-byte label in front: what kind of TLS message and how long it is"
        case (_, let r?): return "Adds \(r.count) bytes\(list)"
        case (_, nil) where layer.present: return "Adds no bytes of its own — \(layer.osi == 5 ? "it rides inside the layers around it" : "its work happens inside the data")"
        default: return "Adds nothing — not used by this packet"
        }
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
                Text("Raw bytes").font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                Spacer()
                Text("\(packet.bytes.count) captured").font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.tertiary)
            }
            Text("What really travels: numbers from 00 to ff, coloured by layer.").font(.system(size: 11)).foregroundStyle(Theme.tertiary)
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

/// Shown before a packet is picked: the 7 layers as a letter in the post, and how to read the screen.
struct OSIGuide: View {
    var showDemo: Bool
    var onDemo: () -> Void = {}
    var body: some View { ScrollView { content } }

    var content: some View {
            VStack(alignment: .leading, spacing: 18) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Every message online travels in 7 layers").font(.system(size: 19, weight: .semibold)).foregroundStyle(Theme.text)
                    Text("Think of posting a letter. You write it, seal it, address it, and a truck carries it. The receiver undoes each step in reverse. Every packet in the list above is one of these letters — click one to open it.")
                        .font(.system(size: 13)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
                }
                if showDemo {
                    Button { onDemo() } label: {
                        Label("Show a demo: visiting example.com", systemImage: "play.fill")
                            .font(.system(size: 12.5, weight: .semibold)).foregroundStyle(Color.black)
                            .padding(.horizontal, 14).padding(.vertical, 7)
                            .background(Theme.accent, in: Capsule())
                    }
                    .buttonStyle(.plain)
                }
                VStack(spacing: 5) {
                    ForEach((1...7).reversed(), id: \.self) { n in
                        HStack(alignment: .top, spacing: 12) {
                            LayerBadge(n: n)
                            VStack(alignment: .leading, spacing: 3) {
                                HStack(alignment: .firstTextBaseline) {
                                    Text(OSI.names[n - 1]).font(.system(size: 13, weight: .semibold)).foregroundStyle(Theme.text)
                                    Spacer()
                                    Text(Explain.examples[n - 1]).font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
                                }
                                Text(OSI.roles[n - 1]).font(.system(size: 12)).foregroundStyle(Theme.secondary)
                                Text("Like \(Explain.analogy[n - 1]).").font(.system(size: 11.5)).foregroundStyle(Theme.tertiary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                        .padding(.horizontal, 12).padding(.vertical, 9)
                        .background(Theme.surface, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
                VStack(alignment: .leading, spacing: 8) {
                    Text("How to read this screen").font(.system(size: 14, weight: .semibold)).foregroundStyle(Theme.text)
                    ForEach(Array([
                        "Each line is one packet — a small piece of a conversation between your Mac and something else.",
                        "Click a line to read what it says in plain English and watch its trip through the layers.",
                        "Open a layer to see the real values inside it, with what each one means.",
                        "Switch to Detailed for a classic packet table with addresses and ports.",
                    ].enumerated()), id: \.offset) { i, s in
                        HStack(alignment: .top, spacing: 10) {
                            Text("\(i + 1)").font(.system(size: 11, weight: .bold, design: .rounded)).foregroundStyle(Color.black.opacity(0.85))
                                .frame(width: 18, height: 18).background(Theme.accent, in: Circle())
                            Text(s).font(.system(size: 12.5)).foregroundStyle(Theme.secondary).fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Text("Real networks use a simpler 4-layer model (TCP/IP), so layers 5 and 6 often have no protocol of their own. Dolkoon tells you when that happens.")
                    .font(.system(size: 11.5)).foregroundStyle(Theme.tertiary).fixedSize(horizontal: false, vertical: true)
            }
            .padding(.horizontal, 24).padding(.vertical, 18)
            .frame(maxWidth: 820, alignment: .leading)
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
                Text(cap.state == .running ? "\(Int(cap.rate.rounded())) a second" : "See the 7 layers")
                    .font(.system(size: 11)).monospacedDigit().foregroundStyle(Theme.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, 10).padding(.vertical, 8)
        .background(selected ? Theme.raised : .clear, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
    }
}
