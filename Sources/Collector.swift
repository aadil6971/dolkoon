import Foundation

/// One sample from a host: per-process traffic, command lines, and files those processes are writing.
struct Sample {
    var procs: [ProcInfo] = []
    var files: [OpenFile] = []
    var error: String?
}

struct ProcInfo: Identifiable {
    let pid: Int
    var name: String
    var bytesIn: Double   // bytes during the sample window
    var bytesOut: Double
    var args: String = ""
    var id: Int { pid }
}

struct OpenFile: Hashable {
    let pid: Int
    let path: String
    let size: Int64
}

/// Runs a small shell script locally or over ssh. nettop gives per-process deltas over 1 s,
/// then ps/lsof describe the busy processes plus any known download tools (even when stalled).
enum Collector {
    static let script = #"""
    export PATH=/usr/bin:/bin:/usr/sbin:/sbin
    N=$(nettop -P -d -x -L 2 -s 1 -J bytes_in,bytes_out 2>/dev/null | awk -F, '/^,bytes_in/{b++; next} b==2 && ($2>0||$3>0)')
    echo '#NET'; echo "$N"
    BUSY=$(echo "$N" | awk -F, '$2>8000{n=split($1,a,"."); print a[n]}')
    TOOLS=$(pgrep -x curl wget aria2c axel 2>/dev/null; pgrep -f 'hf download|huggingface-cli|hf_transfer|pip install|uv pip|yt-dlp|brew (install|fetch|upgrade)|git-remote-http|ollama pull' 2>/dev/null)
    P=$(printf "%s\n%s\n" "$BUSY" "$TOOLS" | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
    ALL=$(printf "%s\n%s\n" "$(echo "$N" | awk -F, '{n=split($1,a,"."); print a[n]}')" "$TOOLS" | grep -E '^[0-9]+$' | sort -un | paste -sd, -)
    echo '#PS'
    [ -n "$ALL" ] && ps -o pid=,args= -p "$ALL" 2>/dev/null
    echo '#FILES'
    [ -n "$P" ] && lsof -nP -w -p "$P" -F pastn 2>/dev/null
    echo '#END'
    """#

    static func run(host: Host) -> Sample {
        let p = Process()
        if host.ssh == nil {
            p.executableURL = URL(fileURLWithPath: "/bin/zsh")
            p.arguments = ["-s"]
        } else {
            p.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
            let ctl = NSHomeDirectory() + "/.ssh/dolkoon-%C"
            p.arguments = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                           "-o", "ControlMaster=auto", "-o", "ControlPath=\(ctl)", "-o", "ControlPersist=300",
                           host.ssh!, "zsh -s"]
        }
        let input = Pipe(), output = Pipe(), err = Pipe()
        p.standardInput = input; p.standardOutput = output; p.standardError = err
        do { try p.run() } catch { return Sample(error: error.localizedDescription) }
        input.fileHandleForWriting.write(script.data(using: .utf8)!)
        try? input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let text = String(decoding: data, as: UTF8.self)
        guard text.contains("#END") else {
            let msg = String(decoding: errData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return Sample(error: msg.isEmpty ? "no answer from \(host.name)" : msg)
        }
        return parse(text)
    }

    static func parse(_ text: String) -> Sample {
        var s = Sample()
        var section = ""
        var byPid: [Int: ProcInfo] = [:]
        var curPid = 0, access = "", type = "", size: Int64 = 0
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            if line.hasPrefix("#") { section = String(line); continue }
            switch section {
            case "#NET":
                let f = line.split(separator: ",", omittingEmptySubsequences: false)
                guard f.count >= 3, let dot = f[0].lastIndex(of: "."),
                      let pid = Int(f[0][f[0].index(after: dot)...]) else { continue }
                byPid[pid] = ProcInfo(pid: pid, name: String(f[0][..<dot]),
                                      bytesIn: Double(f[1]) ?? 0, bytesOut: Double(f[2]) ?? 0)
            case "#PS":
                let t = line.trimmingCharacters(in: .whitespaces)
                guard let sp = t.firstIndex(of: " "), let pid = Int(t[..<sp]) else { continue }
                let args = String(t[t.index(after: sp)...])
                var info = byPid[pid] ?? ProcInfo(pid: pid, name: "", bytesIn: 0, bytesOut: 0)
                info.args = args
                if info.name.isEmpty {
                    let exe = args.split(separator: " ").first.map(String.init) ?? args
                    info.name = (exe as NSString).lastPathComponent
                }
                byPid[pid] = info
            case "#FILES":
                let tag = line.first!, val = String(line.dropFirst())
                switch tag {
                case "p": curPid = Int(val) ?? 0
                case "f": access = ""; type = ""; size = 0
                case "a": access = val
                case "t": type = val
                case "s": size = Int64(val) ?? 0
                case "n":
                    if type == "REG", access == "w" || access == "u", isDownloadLike(val, size: size) {
                        s.files.append(OpenFile(pid: curPid, path: val, size: size))
                    }
                default: break
                }
            default: break
            }
        }
        s.procs = Array(byPid.values)
        return s
    }

    /// Skip logs, databases and other small bookkeeping files a process keeps open for writing.
    static func isDownloadLike(_ path: String, size: Int64) -> Bool {
        let skip = [".log", ".db", ".sqlite", ".sqlite-wal", ".sqlite-shm", "-wal", "-shm", ".lock", ".plist", ".tmp-journal"]
        if skip.contains(where: { path.hasSuffix($0) }) { return false }
        if path.hasPrefix("/dev/") || path.contains("/Library/Logs/") { return false }
        return true
    }
}

/// Finds the full size of a URL (following redirects) so downloads get a progress bar.
final class SizeLookup {
    static let shared = SizeLookup()
    private var cache: [String: Int64] = [:]
    private var pending: Set<String> = []
    private let q = DispatchQueue(label: "dolkoon.size")

    func size(for url: String) -> Int64? {
        q.sync {
            if let v = cache[url] { return v > 0 ? v : nil }
            if !pending.contains(url) { pending.insert(url); fetch(url) }
            return nil
        }
    }

    private func fetch(_ s: String) {
        guard let url = URL(string: s) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "HEAD"
        req.timeoutInterval = 15
        URLSession.shared.dataTask(with: req) { _, resp, _ in
            let len = (resp as? HTTPURLResponse)?.expectedContentLength ?? -1
            self.q.async { self.cache[s] = len; self.pending.remove(s) }
        }.resume()
    }
}

func firstURL(in args: String) -> String? {
    args.split(separator: " ").first { $0.hasPrefix("http://") || $0.hasPrefix("https://") }.map(String.init)
}
