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
}

MainActor.assumeIsolated { run() }
