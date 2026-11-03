import SwiftUI
import AppKit

/// Graphite neutrals with a single yellow accent. Red only marks a stalled download.
enum Theme {
    static let bg = Color(hex: 0x0D0E11)
    static let sidebar = Color(hex: 0x111317)
    static let surface = Color(hex: 0x16181D)
    static let raised = Color(hex: 0x1C1F25)
    static let hairline = Color.white.opacity(0.06)
    static let text = Color(hex: 0xECEDEF)
    static let secondary = Color(hex: 0x8B9099)
    static let tertiary = Color(hex: 0x575C66)

    static let accent = Color(hex: 0xFFD23F)
    static let accentSoft = Color(hex: 0xFFD23F).opacity(0.14)
    static let stalled = Color(hex: 0xFF5B4F)
    static let live = Color(hex: 0x3DDC84)
}

extension Color {
    init(hex: UInt32) {
        self.init(red: Double(hex >> 16 & 0xFF) / 255, green: Double(hex >> 8 & 0xFF) / 255, blue: Double(hex & 0xFF) / 255)
    }
}

/// Quiet neutral square with a grey glyph, used where there is no real app icon.
struct GlyphTile: View {
    let symbol: String
    var size: CGFloat = 30
    var tint: Color = Theme.secondary
    var body: some View {
        RoundedRectangle(cornerRadius: size * 0.26, style: .continuous)
            .fill(Theme.raised)
            .overlay(RoundedRectangle(cornerRadius: size * 0.26, style: .continuous).stroke(Theme.hairline, lineWidth: 1))
            .overlay(Image(systemName: symbol).font(.system(size: size * 0.44, weight: .medium)).foregroundStyle(tint))
            .frame(width: size, height: size)
    }
}

/// Real macOS app icon when the process lives in an .app this Mac also has; otherwise a glyph tile.
struct ProcIcon: View {
    let name: String
    let args: String
    var size: CGFloat = 28
    var body: some View {
        if let img = Icons.app(args: args) {
            Image(nsImage: img).resizable().interpolation(.high).frame(width: size, height: size)
        } else {
            GlyphTile(symbol: Icons.symbol(for: name, args: args), size: size * 0.92).frame(width: size, height: size)
        }
    }
}

enum Icons {
    private static var cache: [String: NSImage?] = [:]

    static func app(args: String) -> NSImage? {
        guard let start = args.firstIndex(of: "/"), let r = args.range(of: ".app", range: start..<args.endIndex) else { return nil }
        let path = String(args[start..<r.upperBound])
        if let hit = cache[path] { return hit }
        var img: NSImage?
        if FileManager.default.fileExists(atPath: path) {
            // Shrink once to 64 px so redraws don't rescale a 1024 px icon every second.
            let big = NSWorkspace.shared.icon(forFile: path)
            img = NSImage(size: NSSize(width: 64, height: 64), flipped: false) { r in big.draw(in: r); return true }
            if let tiff = img?.tiffRepresentation, let rep = NSBitmapImageRep(data: tiff) {
                let small = NSImage(size: NSSize(width: 32, height: 32)); small.addRepresentation(rep); img = small
            }
        }
        cache[path] = img
        return img
    }

    static func symbol(for name: String, args: String) -> String {
        let n = name.lowercased(), a = args.lowercased()
        if n.hasPrefix("curl") || n.hasPrefix("wget") || n.hasPrefix("aria2") { return "arrow.down.to.line" }
        if a.contains("hf download") || a.contains("huggingface") { return "shippingbox" }
        if n.hasPrefix("python") || n.hasPrefix("uv") || n.hasPrefix("pip") { return "chevron.left.forwardslash.chevron.right" }
        if n.hasPrefix("ssh") { return "lock" }
        if n.contains("screensharing") { return "rectangle.on.rectangle" }
        if n.contains("mdns") || n.contains("netbios") || n.contains("rapport") || n.contains("apsd") { return "network" }
        if n.hasPrefix("ollama") { return "cpu" }
        if n.hasPrefix("git") { return "arrow.triangle.branch" }
        if n.hasPrefix("node") { return "hexagon" }
        if n.contains("nsurlsession") || n.contains("softwareupdate") { return "icloud.and.arrow.down" }
        return "app"
    }

    static func file(_ path: String) -> String {
        switch (path as NSString).pathExtension.lowercased() {
        case "gguf", "safetensors", "bin", "pt", "pth", "ckpt", "onnx", "mlmodel", "npz": return "cube"
        case "mp4", "mov", "mkv", "webm", "m4v": return "film"
        case "mp3", "wav", "m4a", "flac", "aac": return "waveform"
        case "zip", "tar", "gz", "xz", "zst", "7z", "dmg", "pkg", "whl": return "archivebox"
        case "png", "jpg", "jpeg", "webp", "heic", "gif": return "photo"
        default: return "doc"
        }
    }
}

/// Smooth area chart: download in accent with a soft fill, upload as a thin grey line.
struct AreaChart: View {
    let down: [Double]
    let up: [Double]
    var body: some View {
        Canvas { ctx, size in
            let peak = max((down + up).max() ?? 1, 1) * 1.12
            func points(_ v: [Double]) -> [CGPoint] {
                let step = size.width / CGFloat(max(v.count - 1, 1))
                return v.enumerated().map { CGPoint(x: CGFloat($0) * step, y: size.height - CGFloat($1 / peak) * size.height) }
            }
            func curve(_ p: [CGPoint]) -> Path {
                var path = Path()
                guard p.count > 1 else { return path }
                path.move(to: p[0])
                for i in 0..<p.count - 1 {
                    let p0 = p[max(i - 1, 0)], p1 = p[i], p2 = p[i + 1], p3 = p[min(i + 2, p.count - 1)]
                    path.addCurve(to: p2,
                                  control1: CGPoint(x: p1.x + (p2.x - p0.x) / 6, y: min(size.height, p1.y + (p2.y - p0.y) / 6)),
                                  control2: CGPoint(x: p2.x - (p3.x - p1.x) / 6, y: min(size.height, p2.y - (p3.y - p1.y) / 6)))
                }
                return path
            }
            for i in 1...3 {
                let y = size.height * CGFloat(i) / 4
                ctx.stroke(Path { $0.move(to: CGPoint(x: 0, y: y)); $0.addLine(to: CGPoint(x: size.width, y: y)) },
                           with: .color(.white.opacity(0.035)), lineWidth: 1)
            }
            ctx.stroke(curve(points(up)), with: .color(Theme.secondary.opacity(0.55)), lineWidth: 1.2)
            let p = points(down)
            let line = curve(p)
            var fill = line
            fill.addLine(to: CGPoint(x: size.width, y: size.height))
            fill.addLine(to: CGPoint(x: 0, y: size.height))
            ctx.fill(fill, with: .linearGradient(Gradient(colors: [Theme.accent.opacity(0.22), Theme.accent.opacity(0)]),
                                                 startPoint: .zero, endPoint: CGPoint(x: 0, y: size.height)))
            ctx.stroke(line, with: .color(Theme.accent), lineWidth: 2)
            if let last = p.last {
                ctx.fill(Path(ellipseIn: CGRect(x: last.x - 3.5, y: last.y - 3.5, width: 7, height: 7)), with: .color(Theme.accent))
            }
        }
    }
}

/// Thin solid progress bar; hidden fill when the total size is unknown.
struct ProgressLine: View {
    let value: Double?
    let stalled: Bool
    var height: CGFloat = 4
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.white.opacity(0.07))
                if let v = value {
                    Capsule().fill(stalled ? Theme.stalled : Theme.accent).frame(width: max(height, g.size.width * CGFloat(v)))
                }
            }
        }
        .frame(height: height)
        .animation(.easeOut(duration: 0.5), value: value)
    }
}

struct MiniSpark: View {
    let values: [Double]
    var color: Color = Theme.secondary
    var body: some View {
        Canvas { ctx, size in
            let v = Array(values.suffix(30))
            let peak = max(v.max() ?? 1, 1)
            let step = size.width / CGFloat(max(v.count - 1, 1))
            var p = Path()
            for (i, x) in v.enumerated() {
                let pt = CGPoint(x: CGFloat(i) * step, y: size.height - CGFloat(x / peak) * (size.height - 2) - 1)
                i == 0 ? p.move(to: pt) : p.addLine(to: pt)
            }
            ctx.stroke(p, with: .color(color), style: StrokeStyle(lineWidth: 1.3, lineCap: .round, lineJoin: .round))
        }
    }
}
