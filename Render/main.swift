import SwiftUI
import AppKit

// Offscreen QA render of Dolkoon views with fake data: swift build via render.sh, writes PNGs.
let out = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "."

func wave(_ base: Double, _ amp: Double, _ seed: Double) -> [Double] {
    (0..<90).map { (i: Int) -> Double in
        let t = Double(i)
        let a: Double = amp * sin(t / 6 + seed)
        let b: Double = amp * 0.5 * sin(t / 2.3 + seed * 2)
        return max(0, base + a + b)
    }
}

@MainActor func run() {
    let h = Host(name: "studio", ssh: "studio")
    h.history = wave(6_200_000, 1_800_000, 0.3)
    h.historyOut = wave(120_000, 60_000, 1.1)
    h.totalIn = 6_870_000; h.totalOut = 48_000; h.received = 3_420_000_000
    h.lastUpdate = Date()
    h.procs = [
        ProcInfo(pid: 8280, name: "curl", bytesIn: 5_400_000, bytesOut: 900,
                 args: "curl -L -C - -o models/llama-3.1-8b-instruct-q4_k_m.gguf https://example.com/models/llama-3.1-8b-instruct-q4_k_m.gguf"),
        ProcInfo(pid: 8176, name: "wget", bytesIn: 1_380_000, bytesOut: 400,
                 args: "wget -c https://example.com/releases/ubuntu-24.04-desktop-arm64.iso"),
        ProcInfo(pid: 6250, name: "firefox", bytesIn: 82_000, bytesOut: 14_000, args: "/Applications/Firefox.app/Contents/MacOS/firefox"),
        ProcInfo(pid: 7819, name: "screensharingd", bytesIn: 31_000, bytesOut: 2_400_000, args: "/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd"),
        ProcInfo(pid: 463, name: "mDNSResponder", bytesIn: 1_200, bytesOut: 800, args: "/usr/sbin/mDNSResponder"),
        ProcInfo(pid: 7687, name: "sshd-session", bytesIn: 3_700, bytesOut: 4_200, args: "sshd-session: me@ttys001"),
    ]
    h.downloads = [
        DownloadItem(path: "/Users/me/models/llama-3.1-8b-instruct-q4_k_m.gguf", pid: 8280, process: "curl",
                     size: 3_745_673_216, total: 4_920_000_000, speed: 5_400_000, lastGrowth: Date()),
        DownloadItem(path: "/Users/me/Downloads/ubuntu-24.04-desktop-arm64.iso", pid: 8176, process: "wget",
                     size: 1_204_000_000, total: nil, speed: 1_380_000, lastGrowth: Date()),
        DownloadItem(path: "/Users/me/Downloads/dataset-shard-0007.tar.part", pid: 7742, process: "python3",
                     size: 85_667_840, total: 2_100_000_000, speed: 0, lastGrowth: Date().addingTimeInterval(-95)),
    ]
    let local = Host(name: "This Mac", ssh: nil)
    local.history = wave(400_000, 300_000, 2); local.totalIn = 512_000; local.lastUpdate = Date()

    func save<V: View>(_ v: V, _ name: String, width: CGFloat) {
        let r = ImageRenderer(content: v.frame(width: width).environment(\.colorScheme, .dark))
        r.scale = 1.5
        guard let img = r.nsImage, let tiff = img.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff),
              let png = rep.representation(using: .png, properties: [:]) else { print("render failed", name); return }
        try! png.write(to: URL(fileURLWithPath: "\(out)/\(name).png"))
        print("wrote", name)
    }
    save(HostContent(host: h).padding(26).background(Theme.bg), "detail", width: 1000)
    save(VStack(alignment: .leading, spacing: 4) {
        HostRow(host: local); HostRow(host: h, selected: true)
    }.padding(12).background(Theme.sidebar), "sidebar", width: 240)
    save(VStack(spacing: 10) { MenuHost(host: local); MenuHost(host: h) }.padding(16).background(Theme.bg), "menu", width: 340)

    let cap = PacketCapture()
    cap.loadDemo(animated: false)
    let pkt = cap.packets[6]
    print("demo packets:", cap.packets.count)
    save(VStack(spacing: 0) {
        ForEach(StoryItem.group(cap.packets.filter { !$0.noise })) { StoryRow(item: $0, t0: cap.packets.first?.time, selected: $0.id == pkt.id) }
    }.background(Theme.surface), "stories", width: 900)
    save(VStack(spacing: 0) {
        let list = cap.conversations.values.sorted { $0.bytesIn + $0.bytesOut > $1.bytesIn + $1.bytesOut }
        ForEach(list) { ConversationRow(c: $0, peak: list.map { $0.bytesIn + $0.bytesOut }.max() ?? 1, now: cap.packets.last!.time); Divider1(inset: 54) }
    }.background(Theme.surface), "conversations", width: 900)
    save(PacketHeader(cap: cap, filter: .constant(""), mode: .constant(.stories), quick: .constant(.all)).padding(24).background(Theme.bg), "header", width: 1100)
    save(VStack(alignment: .leading, spacing: 22) {
        StoryCard(packet: pkt, t0: cap.packets.first?.time)
        JourneyView(packet: pkt, frozenStep: 3)
    }.padding(24).background(Theme.bg), "story-journey", width: 900)
    for (k, st) in [(6, 9), (6, 7), (0, 1), (2, 12)] {
        save(JourneyView(packet: cap.packets[k], frozenStep: st).padding(20).background(Theme.bg), "journey-\(k)-\(st)", width: 760)
    }
    save(OSIStack(packet: pkt, focus: .constant(nil)).padding(20).background(Theme.bg), "stack", width: 640)
    save(StoryCard(packet: cap.packets[1], t0: cap.packets.first?.time).padding(20).background(Theme.bg), "card-dns", width: 760)
    var expanded = pkt.layer(4)
    save(VStack(spacing: 5) {
        LayerRow(layer: expanded, expanded: true)
        LayerRow(layer: pkt.layer(3), expanded: true)
    }.padding(20).background(Theme.bg), "layers", width: 620)
    expanded = cap.packets[2].layer(7)
    save(LayerRow(layer: expanded, expanded: true).padding(20).background(Theme.bg), "layer-dns", width: 620)
    save(OSIGuide(showDemo: true).content.background(Theme.bg), "guide", width: 820)
    save(PermissionBanner(cap: cap).padding(20).background(Theme.bg), "packets-permission", width: 900)
}

MainActor.assumeIsolated { run() }
