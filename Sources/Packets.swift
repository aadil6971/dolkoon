import Foundation
import AppKit
import Darwin

// MARK: decoded packet

struct Field: Hashable {
    let key: String
    let value: String
    init(_ key: String, _ value: String) { self.key = key; self.value = value }
}

/// One OSI layer of a packet. `proto` is empty when nothing separate runs at this layer.
/// `range` is where this layer's bytes sit in the captured packet.
struct OSILayer: Identifiable {
    let osi: Int
    var proto = ""
    var summary = ""
    var fields: [Field] = []
    var range: Range<Int>?
    var id: Int { osi }
    var present: Bool { !proto.isEmpty }
}

struct Packet: Identifiable {
    let id: Int
    let time: Date
    let wireLength: Int
    let bytes: [UInt8]
    var layers: [OSILayer]   // layers[0] is layer 1 (Physical) ... layers[6] is layer 7 (Application)
    var src = ""
    var dst = ""
    var proto = ""           // highest protocol found
    var info = ""
    var top = 1              // OSI number of that protocol
    var story = ""           // plain-English sentence; {S} and {D} become friendly names (see PacketCapture.finish)
    var why = ""             // why this packet exists, for someone new to networking
    var learned: [(ip: String, name: String)] = []
    var noise = false        // a bare TCP "got it" with no data
    var srcIP = "", dstIP = ""
    var srcName = "", dstName = ""
    var sent: Bool?          // true = left this Mac, false = arrived here, nil = neither
    var group = ""           // story template with {N} for the amount; packets with the same template and ends can merge
    var encrypted = false
    var appBytes = 0         // bytes of the app's own data (after all headers)
    var sport = 0, dport = 0
    var link: UInt32 = 1
    var app = ""             // the Mac app that owns this conversation, when lsof can tell
    var appPath = ""         // its executable, for the real app icon

    func layer(_ n: Int) -> OSILayer { layers[n - 1] }

    func matches(_ q: String) -> Bool {
        let q = q.lowercased()
        if q.isEmpty { return true }
        if src.lowercased().contains(q) || dst.lowercased().contains(q) || info.lowercased().contains(q) { return true }
        return layers.contains { $0.proto.lowercased().contains(q) || $0.fields.contains { $0.value.lowercased() == q } }
    }
}

enum OSI {
    static let names = ["Physical", "Data link", "Network", "Transport", "Session", "Presentation", "Application"]
    static let roles = [
        "Bits as radio waves or electrical signals",
        "Delivers the frame to the next device on this network (MAC address)",
        "Routes the packet across networks to the right computer (IP address)",
        "Gets data to the right app on that computer (port), reliably or fast",
        "Opens, keeps and closes the conversation",
        "Encryption and data format",
        "What the app actually says",
    ]
}

// MARK: decoder

enum PacketDecoder {
    static func decode(id: Int, time: Date, wireLength: Int, bytes b: [UInt8], linkType: UInt32, iface: String) -> Packet {
        var L = (1...7).map { OSILayer(osi: $0) }
        var p = Packet(id: id, time: time, wireLength: wireLength, bytes: b, layers: [])
        let n = b.count
        func u16(_ i: Int) -> Int { i + 1 < n ? Int(b[i]) << 8 | Int(b[i + 1]) : 0 }
        func u32(_ i: Int) -> UInt32 { i + 3 < n ? UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3]) : 0 }
        func mac(_ i: Int) -> String { i + 5 < n ? b[i..<i + 6].map { String(format: "%02x", $0) }.joined(separator: ":") : "?" }

        let medium = iface == "file" ? "Capture file" : iface.hasPrefix("lo") ? "Loopback" : iface.hasPrefix("utun") ? "VPN tunnel" : iface.hasPrefix("en") ? "Wi-Fi / Ethernet" : iface
        L[0] = OSILayer(osi: 1, proto: medium, summary: iface == "file" ? "\(wireLength) bytes on the original wire" : iface.hasPrefix("lo") ? "Never leaves this Mac — no real signal" : "\(wireLength) bytes sent as signals on \(iface)",
                        fields: [Field("Interface", iface), Field("On the wire", "\(wireLength) bytes"), Field("Captured", "\(n) bytes"),
                                 Field("Not captured", "preamble and checksum — the network card strips them")])

        // Layer 2
        var off = 0
        var etherType = 0
        switch linkType {
        case 1:
            guard n >= 14 else { break }
            etherType = u16(12); off = 14
            if etherType == 0x8100, n >= 18 { etherType = u16(16); off = 18 }
            let dmac = mac(0), smac = mac(6)
            L[1] = OSILayer(osi: 2, proto: "Ethernet", summary: "\(smac) → \(dmac == "ff:ff:ff:ff:ff:ff" ? "everyone (broadcast)" : dmac)",
                            fields: [Field("From MAC", smac), Field("To MAC", dmac), Field("Carries", etherName(etherType))], range: 0..<off)
        case 0, 108:
            guard n >= 4 else { break }
            let fam = linkType == 0 ? Int(b[0]) | Int(b[1]) << 8 : u16(2)
            etherType = fam == 2 ? 0x0800 : [24, 28, 30].contains(fam) ? 0x86DD : 0
            off = 4
            L[1] = OSILayer(osi: 2, proto: "Loopback", summary: "No MAC addresses — the packet stays inside this Mac",
                            fields: [Field("Family", etherName(etherType))], range: 0..<4)
        case 12, 14, 101:
            etherType = n > 0 && b[0] >> 4 == 6 ? 0x86DD : 0x0800
            L[1] = OSILayer(osi: 2, summary: "Tunnel — no link header, the VPN wraps it later")
        default:
            L[1] = OSILayer(osi: 2, proto: "Link type \(linkType)", summary: "Not decoded")
        }

        // Layer 3
        var st = Story()
        var ipProto = -1
        var end = n
        var srcIP = "", dstIP = ""
        switch etherType {
        case 0x0800 where n >= off + 20:
            let ihl = Int(b[off] & 0x0F) * 4
            let total = u16(off + 2)
            let frag = u16(off + 6)
            srcIP = ip4(b, off + 12); dstIP = ip4(b, off + 16)
            ipProto = Int(b[off + 9])
            end = min(n, off + max(total, ihl))
            var f = [Field("From IP", srcIP), Field("To IP", dstIP), Field("TTL", "\(b[off + 8]) hops left"),
                     Field("Carries", ipProtoName(ipProto)), Field("Length", "\(total) bytes")]
            if frag & 0x1FFF != 0 || frag & 0x2000 != 0 { f.append(Field("Fragment", "offset \((frag & 0x1FFF) * 8)")) }
            if frag & 0x1FFF != 0 { ipProto = -2 }
            L[2] = OSILayer(osi: 3, proto: "IPv4", summary: "\(srcIP) → \(dstIP)", fields: f, range: off..<min(n, off + ihl))
            off += ihl
        case 0x86DD where n >= off + 40:
            let start = off
            srcIP = ip6(b, off + 8); dstIP = ip6(b, off + 24)
            end = min(n, off + 40 + u16(off + 4))
            var next = Int(b[off + 6])
            let hop = b[off + 7]
            off += 40
            while [0, 43, 60, 44].contains(next), off + 8 <= n {
                let len = next == 44 ? 8 : (Int(b[off + 1]) + 1) * 8
                next = Int(b[off]); off += len
            }
            ipProto = next
            L[2] = OSILayer(osi: 3, proto: "IPv6", summary: "\(srcIP) → \(dstIP)",
                            fields: [Field("From IP", srcIP), Field("To IP", dstIP), Field("Hop limit", "\(hop) hops left"),
                                     Field("Carries", ipProtoName(ipProto))], range: start..<min(n, off))
        case 0x0806 where n >= off + 28:
            let op = u16(off + 6)
            let sip = ip4(b, off + 14), tip = ip4(b, off + 24), smac = mac(off + 8)
            let s = op == 1 ? "Who has \(tip)? Tell \(sip)" : "\(sip) is at \(smac)"
            L[2] = OSILayer(osi: 3, proto: "ARP", summary: s,
                            fields: [Field("Asks", op == 1 ? "request" : "reply"), Field("Sender", "\(sip)  \(smac)"), Field("Target", tip),
                                     Field("Note", "ARP finds the MAC address for an IP — it sits between layers 2 and 3")],
                            range: off..<off + 28)
            p.src = sip; p.dst = op == 1 ? "broadcast" : tip
            p.srcIP = sip; p.dstIP = op == 1 ? "broadcast" : tip
            st = op == 1
                ? Story("{S} shouted to every device nearby: “Who has \(tip)?”",
                        "Before sending anything to \(tip) (often your router), your Mac needs its hardware address. ARP is how it asks.")
                : Story("{S} answered: “\(sip) is me — my hardware address is \(smac)”",
                        "Now the asker can put the right hardware (MAC) address on its frames.")
        default: break
        }
        if !srcIP.isEmpty { p.src = srcIP; p.dst = dstIP; p.srcIP = srcIP; p.dstIP = dstIP }

        // Layer 4 (ICMP lives in layer 3)
        var payload = 0..<0
        var sport = 0, dport = 0
        var transport = ""
        switch ipProto {
        case let x where (x == 1 || x == 58) && off + 4 <= end:
            let (name, s) = icmpName(v6: ipProto == 58, type: Int(b[off]), code: Int(b[off + 1]))
            L[2].proto += " · " + name
            L[2].summary = s
            L[2].fields.append(Field(name + " type", "\(b[off]) code \(b[off + 1])"))
            L[2].range = (L[2].range?.lowerBound ?? off)..<min(end, off + 8)
            L[3].summary = "\(name) is a network-layer message — no ports"
            st = icmpStory(v6: ipProto == 58, type: Int(b[off]))
        case 6 where off + 20 <= end:
            transport = "TCP"
            sport = u16(off); dport = u16(off + 2)
            let hl = max(20, Int(b[off + 12] >> 4) * 4)
            let flags = b[off + 13]
            payload = min(end, off + hl)..<end
            let fl = tcpFlags(flags)
            L[3] = OSILayer(osi: 4, proto: "TCP", summary: "port \(sport) → \(dport)" + (fl.isEmpty ? "" : " · " + fl),
                            fields: [Field("From port", portLabel(sport)), Field("To port", portLabel(dport)), Field("Flags", fl.isEmpty ? "none" : fl),
                                     Field("Seq", "\(u32(off + 4))"), Field("Ack", "\(u32(off + 8))"), Field("Window", "\(u16(off + 14)) bytes"),
                                     Field("Data", "\(payload.count) bytes")],
                            range: off..<min(end, off + hl))
            if flags & 0x04 != 0 { L[4] = OSILayer(osi: 5, proto: "TCP · reset", summary: "Connection was cut off (RST)") }
            else if flags & 0x02 != 0 {
                L[4] = OSILayer(osi: 5, proto: "TCP · handshake",
                                summary: flags & 0x10 != 0 ? "Step 2 of 3: server agrees to open the connection" : "Step 1 of 3: asks to open a connection")
            } else if flags & 0x01 != 0 { L[4] = OSILayer(osi: 5, proto: "TCP · closing", summary: "Says goodbye — closing the connection (FIN)") }
            let door = portPhrase(knownPorts[dport] != nil || sport > dport ? dport : sport)
            if flags & 0x04 != 0 {
                st = Story("{S} hung up on {D}", "RST cuts a connection off at once — often the port is closed or the app gave up.")
            } else if flags & 0x02 != 0, flags & 0x10 == 0 {
                st = Story("{S} knocked on {D}'s door (\(door)): “Can we talk?”",
                           "Step 1 of TCP's 3-step handshake. TCP sends nothing real until both sides agree to talk.")
            } else if flags & 0x02 != 0 {
                st = Story("{S} said “Yes, let's talk” to {D}", "Step 2 of 3. Next the first side says “got it”, and the connection is open.")
            } else if flags & 0x01 != 0 {
                st = Story("{S} said goodbye to {D}", "FIN closes the conversation politely — each side says goodbye once.")
            } else if payload.isEmpty {
                st = Story(group: "{S} told {D}: “Got it”",
                           "TCP confirms everything it receives. If a confirmation never comes, the sender sends that piece again — that's how nothing gets lost.")
                p.noise = true
            }
        case 17 where off + 8 <= end:
            transport = "UDP"
            sport = u16(off); dport = u16(off + 2)
            payload = off + 8..<max(off + 8, min(end, off + u16(off + 4)))
            L[3] = OSILayer(osi: 4, proto: "UDP", summary: "port \(sport) → \(dport) · no handshake, just send",
                            fields: [Field("From port", portLabel(sport)), Field("To port", portLabel(dport)), Field("Data", "\(payload.count) bytes")],
                            range: off..<off + 8)
        case -2:
            L[3].summary = "Fragment — the transport header is in the first piece"
        case let x where x >= 0:
            L[3] = OSILayer(osi: 4, proto: ipProtoName(x), summary: "Not decoded")
        default: break
        }
        if !transport.isEmpty, !srcIP.isEmpty {
            p.src = (srcIP.contains(":") ? "[\(srcIP)]" : srcIP) + ":\(sport)"
            p.dst = (dstIP.contains(":") ? "[\(dstIP)]" : dstIP) + ":\(dport)"
        }

        // Layers 5–7
        if !transport.isEmpty { decodeApp(&L, &st, b, payload, transport, sport, dport, srcIP, dstIP) }
        if st.text.isEmpty {
            st = L[2].present ? Story("{S} sent a \(L[2].proto) packet to {D}", "")
                : Story("A \(L[1].proto.isEmpty ? "link-level" : L[1].proto) frame: \(L[1].summary)", "This frame never goes past the local network.")
        }

        // Fill quiet layers with a plain reason.
        if !L[4].present, L[4].summary.isEmpty { L[4].summary = transport.isEmpty ? "—" : "Not separate here — \(transport) and the app handle it" }
        if !L[5].present, L[5].summary.isEmpty { L[5].summary = transport.isEmpty ? "—" : "Not encrypted — plain bytes" }
        if !L[6].present, L[6].summary.isEmpty { L[6].summary = transport.isEmpty ? "—" : "No app data in this packet" }
        for i in 1...6 where !L[i].present && L[i].summary.isEmpty { L[i].summary = "—" }

        p.layers = L
        let topLayer = L.last { $0.present && $0.osi > 1 } ?? L[0]
        // TCP's handshake notes sit on layer 5 but the packet is still plain TCP.
        p.top = topLayer.osi == 5 && topLayer.proto.hasPrefix("TCP") ? 4 : topLayer.osi
        p.proto = shortName(topLayer.proto)
        p.info = topLayer.summary
        if p.src.isEmpty { p.src = L[1].fields.first?.value ?? "" ; p.dst = L[1].fields.dropFirst().first?.value ?? "" }
        p.story = st.text; p.why = st.why; p.learned = st.learned
        p.group = st.group; p.encrypted = st.encrypted; p.appBytes = payload.count
        p.sport = sport; p.dport = dport; p.link = linkType
        return p
    }

    private static func decodeApp(_ L: inout [OSILayer], _ st: inout Story, _ b: [UInt8], _ r: Range<Int>, _ t: String, _ sp: Int, _ dp: Int,
                                  _ srcIP: String, _ dstIP: String) {
        let data = Array(b[r])
        let port = knownPorts[dp] != nil ? dp : knownPorts[sp] != nil ? sp : min(sp, dp)
        let service = knownPorts[port]
        guard !data.isEmpty else { return }
        let text = String(decoding: data.prefix(200), as: UTF8.self)
        let firstLine = text.split(separator: "\r\n").first.map(String.init) ?? ""

        // DNS / mDNS / LLMNR
        if [53, 5353, 5355].contains(port), let d = dns(t == "TCP" ? Array(data.dropFirst(2)) : data) {
            let name = port == 5353 ? "mDNS" : port == 5355 ? "LLMNR" : "DNS"
            L[6] = OSILayer(osi: 7, proto: name, summary: d.summary, fields: d.fields, range: r)
            if port == 5353 || port == 5355 {
                let what = serviceName(d.qname)
                st = d.response
                    ? Story("{S} told nearby devices: “I'm here\(what.map { " — I offer \($0)" } ?? "")”", "Bonjour (mDNS) lets Apple devices, printers and speakers find each other without any setup.")
                    : Story("{S} asked nearby devices: “\(what.map { "Who offers \($0)?" } ?? "Who is \(d.qname)?")”", "Bonjour (mDNS) lets Apple devices, printers and speakers find each other without any setup.")
            } else if d.response {
                st = Story("{S} replied: “\(d.qname) is at \(d.answers.isEmpty ? "(no address)" : d.answers.joined(separator: ", "))”",
                           "Like getting a phone number back. Now the asker knows where to send the real request.")
                st.learned = d.answers.filter { $0.first?.isNumber == true || $0.contains(":") }.map { ($0, d.qname) }
            } else {
                st = Story("{S} asked {D}: “What's the address of \(d.qname)?”",
                           "Computers find each other by number (IP address), not by name. DNS is the internet's phone book.")
            }
            return
        }
        // TLS
        if t == "TCP", data.count >= 5, (20...23).contains(data[0]), data[1] == 3 {
            let kinds = [20: "Change cipher", 21: "Alert", 22: "Handshake", 23: "Encrypted data"]
            var f = [Field("Record", kinds[Int(data[0])] ?? "?"), Field("Record size", "\((Int(data[3]) << 8 | Int(data[4]))) bytes")]
            var s = data[0] == 23 ? "Encrypted — only the two ends can read this" : (kinds[Int(data[0])] ?? "")
            var host: String?
            if data[0] == 22, data.count > 5 {
                let hs = [1: "Client Hello", 2: "Server Hello", 4: "New session ticket", 11: "Certificate", 12: "Key exchange", 14: "Hello done", 16: "Key exchange", 20: "Finished"]
                let h = hs[Int(data[5])] ?? "Handshake"
                f.append(Field("Handshake", h))
                s = h + (data[5] == 1 ? " — starts encryption" : data[5] == 2 ? " — server picks the cipher" : "")
                if data[5] == 1, let ch = clientHello(data) {
                    host = ch.sni
                    if let sni = ch.sni { f.append(Field("Server name", sni)) }
                    if let alpn = ch.alpn { f.append(Field("App protocol", alpn)) }
                }
            }
            let start = r.lowerBound
            let hsType = data[0] == 22 && data.count > 5 ? Int(data[5]) : -1
            switch (Int(data[0]), hsType) {
            case (22, 1):
                st = Story("{S} started a secure, encrypted conversation with \(host ?? "{D}")",
                           "This hello is the last part anyone in between can read. It shows the website's name, but everything after it is locked.")
                if let host { st.learned = [(dstIP, host)] }
            case (22, 2): st = Story("{S} replied with its encryption choice — the secure line is almost ready", "Both sides now make secret keys that only they know.")
            case (22, 11): st = Story("{S} showed its ID card (certificate)", "Your Mac checks this certificate to make sure it's really talking to that website.")
            case (22, _): st = Story("{S} and {D} are agreeing on secret keys", "Part of the TLS handshake that sets up encryption.")
            case (23, _): st = Story(flow: "{S} sent {N} of encrypted data to {D}", data.count, "Locked by TLS. Nobody in between — not even your Wi-Fi or internet provider — can read it.")
            case (21, _): st = Story("{S} sent a TLS alert to {D}", "Usually means the secure line is closing.")
            default: st = Story("{S} switched to encrypted mode", "From here on, everything is locked.")
            }
            st.encrypted = true
            L[4] = OSILayer(osi: 5, proto: "TLS session", summary: data[0] == 22 ? "Handshake sets up a secure session" : "Inside an open TLS session")
            L[5] = OSILayer(osi: 6, proto: "TLS", summary: s, fields: f, range: start..<start + 5)
            L[6] = OSILayer(osi: 7, proto: service.map { $0 == "HTTP" ? "HTTPS" : $0 } ?? "Encrypted app",
                            summary: host.map { "Talking to \($0)" } ?? "Hidden by encryption", range: start + 5..<r.upperBound)
            return
        }
        // QUIC (HTTP/3)
        if t == "UDP", [443, 8443].contains(port) {
            let long = data[0] & 0x80 != 0
            let kind = long ? ["Initial", "0-RTT", "Handshake", "Retry"][Int(data[0] >> 4 & 3)] : "Encrypted (short header)"
            L[4] = OSILayer(osi: 5, proto: "QUIC connection", summary: long ? "Setting up a QUIC connection" : "Inside an open QUIC connection")
            L[5] = OSILayer(osi: 6, proto: "QUIC · TLS 1.3", summary: "\(kind) packet — encryption built into QUIC",
                            fields: [Field("Packet", kind)] + (long && data.count >= 5 ? [Field("Version", String(format: "0x%08x", UInt32(data[1]) << 24 | UInt32(data[2]) << 16 | UInt32(data[3]) << 8 | UInt32(data[4])))] : []))
            L[6] = OSILayer(osi: 7, proto: "HTTP/3", summary: "Web traffic over QUIC — hidden by encryption", range: r)
            st = long && kind == "Initial"
                ? Story("{S} started a fast, encrypted QUIC connection with {D}", "QUIC is the newer way to load websites (HTTP/3). It runs on UDP and is encrypted from the very first packet.")
                : Story(flow: "{S} sent {N} of encrypted web data to {D} (HTTP/3)", data.count, "QUIC traffic — encrypted, so only the two ends can read it.")
            st.encrypted = true
            return
        }
        // HTTP
        if ["GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI", "HTTP"].contains(where: { text.hasPrefix($0) }) {
            var f = [Field("Line", firstLine)]
            if let host = text.split(separator: "\r\n").first(where: { $0.lowercased().hasPrefix("host:") }) {
                f.append(Field("Host", host.dropFirst(5).trimmingCharacters(in: .whitespaces)))
            }
            L[6] = OSILayer(osi: 7, proto: "HTTP", summary: firstLine, fields: f, range: r)
            let words = firstLine.split(separator: " ")
            if text.hasPrefix("HTTP") {
                st = Story("{S} answered: “\(words.dropFirst().joined(separator: " "))”", "A plain-HTTP reply. Anyone on the network could read it, unlike HTTPS.")
            } else {
                let host = f.count > 1 ? f[1].value : "{D}"
                st = Story("{S} asked \(host) for \(words.count > 1 ? String(words[1]) : "a page") — not encrypted",
                           "Plain HTTP: anyone on your network could read this. With HTTPS this same request would be locked.")
            }
            L[5] = OSILayer(osi: 6, summary: "Not encrypted — anyone on the path can read this")
            return
        }
        // SSH
        if port == 22 {
            if text.hasPrefix("SSH-") {
                L[6] = OSILayer(osi: 7, proto: "SSH", summary: "Hello: \(firstLine)", range: r)
                st = Story("{S} said hello and named its SSH version", "SSH is how you log in to another computer's terminal, safely.")
            } else {
                L[5] = OSILayer(osi: 6, proto: "SSH encryption", summary: "Encrypted by SSH")
                L[6] = OSILayer(osi: 7, proto: "SSH", summary: "Remote terminal — hidden by encryption", range: r)
                st = Story(flow: "{S} sent {N} of encrypted terminal traffic to {D}", data.count, "SSH keeps remote-login keystrokes and output locked.")
                st.encrypted = true
            }
            return
        }
        // SSDP and other plain text
        if port == 1900 {
            L[6] = OSILayer(osi: 7, proto: "SSDP", summary: firstLine.isEmpty ? "Device discovery" : firstLine, range: r)
            st = text.hasPrefix("M-SEARCH")
                ? Story("{S} asked nearby TVs, speakers and routers to say who they are", "SSDP is how smart devices find each other on a home network.")
                : Story("{S} announced itself to nearby devices", "SSDP is how smart devices find each other on a home network.")
            return
        }
        if [67, 68].contains(port) {
            var s = "Asks for or hands out an IP address"
            if data.count > 240, Array(data[236..<240]) == [99, 130, 83, 99] {
                var i = 240
                while i + 2 < data.count, data[i] != 255 {
                    if data[i] == 53 { s = ["", "Discover — anyone have an IP for me?", "Offer — you can have this IP", "Request — I'll take it", "", "ACK — it's yours"][min(5, Int(data[i + 2]))] }
                    i += 2 + Int(data[i + 1])
                }
            }
            L[6] = OSILayer(osi: 7, proto: "DHCP", summary: s, range: r)
            st = Story("{S}: “\(s.components(separatedBy: " — ").last ?? s)”", "DHCP is how a device gets its IP address when it joins a network.")
            return
        }
        if let service {
            let encrypted = ["HTTPS", "IMAPS", "SMTPS", "Apple Push", "DNS over TLS", "WireGuard", "IPsec"].contains(service)
            if encrypted, t == "TCP" || service == "WireGuard" || service == "IPsec" {
                L[5] = OSILayer(osi: 6, proto: service == "WireGuard" || service == "IPsec" ? service : "TLS", summary: "Encrypted bytes (continued)")
            }
            L[6] = OSILayer(osi: 7, proto: service, summary: "\(data.count) bytes of \(service) data", range: r)
            st = service == "NTP" ? Story("{S} asked {D} what time it is", "NTP keeps your Mac's clock exact.")
                : Story(flow: "{S} sent {N} of \(service) data to {D}", data.count, encrypted ? "Encrypted — only the two ends can read it." : "")
            st.encrypted = encrypted
        } else {
            L[6] = OSILayer(osi: 7, proto: "Data", summary: "\(data.count) bytes for port \(port)", range: r)
            st = Story(flow: "{S} sent {N} to {D} (port \(port))", data.count, "")
        }
    }

    // MARK: helpers

    struct Story {
        var text = "", why = "", group = ""
        var encrypted = false
        var learned: [(ip: String, name: String)] = []
        init(_ text: String = "", _ why: String = "") { self.text = text; self.why = why }
        /// A repeatable "sent N bytes" line; runs of these collapse into one row.
        init(flow: String, _ n: Int, _ why: String) {
            text = flow.replacingOccurrences(of: "{N}", with: PacketDecoder.sizeWords(n)); group = flow; self.why = why
        }
        init(group: String, _ why: String) { text = group; self.group = group; self.why = why }
    }

    static func icmpStory(v6: Bool, type: Int) -> Story {
        switch (v6, type) {
        case (false, 8), (true, 128): return Story("{S} pinged {D}: “Are you there?”", "Ping checks if a computer can be reached, and how long the round trip takes.")
        case (false, 0), (true, 129): return Story("{S} answered the ping: “Yes, I'm here”", "The time between ping and reply is your latency.")
        case (false, 3), (true, 1): return Story("{S} told {D}: “I can't deliver that”", "A router or computer says a packet could not reach where it was going.")
        case (false, 11), (true, 3): return Story("{S} told {D}: “Your packet ran out of hops”", "Its TTL hit zero. Traceroute uses this trick on purpose to map the path.")
        case (true, 135): return Story("{S} asked: “Who has this IPv6 address?”", "IPv6's version of ARP — finding a neighbour's hardware address.")
        case (true, 136): return Story("{S} answered: “That IPv6 address is me”", "IPv6's version of an ARP reply.")
        case (true, 133): return Story("{S} asked: “Is there a router here?”", "A device joining an IPv6 network looks for its router.")
        case (true, 134): return Story("{S} announced: “I'm the router here”", "Routers tell devices how to get onto the internet.")
        default: return Story("{S} sent a control message to {D}", "ICMP carries network status messages, not app data.")
        }
    }

    static let portWords: [Int: String] = [
        22: "remote login", 25: "email", 53: "DNS", 80: "websites", 123: "time", 443: "secure websites", 445: "file sharing",
        587: "email", 993: "email", 5223: "Apple notifications", 5900: "screen sharing", 7000: "AirPlay", 8080: "websites",
        8443: "secure websites", 11434: "Ollama",
    ]

    static func portPhrase(_ p: Int) -> String { portWords[p].map { "port \(p) — \($0)" } ?? "port \(p)" }

    static func sizeWords(_ n: Int) -> String {
        n < 1000 ? "\(n) bytes" : n < 1_000_000 ? String(format: "%.1f KB", Double(n) / 1000) : String(format: "%.1f MB", Double(n) / 1e6)
    }

    /// Friendly name for a Bonjour service like "_airplay._tcp.local".
    static func serviceName(_ q: String) -> String? {
        let m = ["_airplay": "AirPlay", "_raop": "AirPlay speakers", "_googlecast": "Chromecast", "_spotify-connect": "Spotify Connect",
                 "_companion-link": "Apple device pairing", "_ipp": "printing", "_ipps": "printing", "_printer": "printing",
                 "_smb": "file sharing", "_afpovertcp": "file sharing", "_hap": "HomeKit", "_homekit": "HomeKit", "_sleep-proxy": "Sleep Proxy",
                 "_device-info": "device info", "_rdlink": "Apple remote link", "_ssh": "remote login", "_sftp-ssh": "file transfer",
                 "_matter": "Matter smart home", "_meshcop": "Thread smart home", "_airdrop": "AirDrop"]
        guard let key = q.split(separator: ".").first(where: { $0.hasPrefix("_") && !["_tcp", "_udp", "_sub"].contains($0) }) else { return nil }
        return m[String(key)] ?? String(key.dropFirst())
    }

    static let knownPorts: [Int: String] = [
        20: "FTP", 21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 123: "NTP", 137: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IPsec", 548: "AFP", 587: "SMTP", 853: "DNS over TLS", 993: "IMAPS",
        1900: "SSDP", 3000: "Dev server", 3478: "STUN", 4500: "IPsec", 5223: "Apple Push", 5353: "mDNS", 5355: "LLMNR", 5900: "Screen Sharing",
        7000: "AirPlay", 8080: "HTTP", 8443: "HTTPS", 11434: "Ollama", 51820: "WireGuard",
    ]

    static func portLabel(_ p: Int) -> String { knownPorts[p].map { "\(p) (\($0))" } ?? (p >= 49152 ? "\(p) (temporary)" : "\(p)") }

    static func etherName(_ t: Int) -> String {
        [0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "VLAN", 0x88CC: "LLDP"][t] ?? String(format: "0x%04x", t)
    }

    static func ipProtoName(_ p: Int) -> String { [1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 58: "ICMPv6", 132: "SCTP"][p] ?? "protocol \(p)" }

    static func tcpFlags(_ f: UInt8) -> String {
        [(0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG")]
            .filter { f & $0.0 != 0 }.map(\.1).joined(separator: " ")
    }

    static func icmpName(v6: Bool, type: Int, code: Int) -> (String, String) {
        let name = v6 ? "ICMPv6" : "ICMP"
        let m: [Int: String] = v6
            ? [1: "Can't reach destination", 3: "Time exceeded", 128: "Ping request", 129: "Ping reply", 133: "Looking for a router",
               134: "Router here", 135: "Who has this IPv6 address?", 136: "I have that IPv6 address", 143: "Multicast report"]
            : [0: "Ping reply", 3: "Can't reach destination", 5: "Redirect", 8: "Ping request", 11: "Time exceeded (traceroute hop)"]
        return (name, m[type] ?? "\(name) type \(type)")
    }

    static func shortName(_ s: String) -> String {
        if s.hasPrefix("IPv4 · ") || s.hasPrefix("IPv6 · ") { return String(s.dropFirst(7)) }
        if s.hasPrefix("TCP · ") { return "TCP" }
        return s
    }

    static func ip4(_ b: [UInt8], _ i: Int) -> String { i + 3 < b.count ? "\(b[i]).\(b[i + 1]).\(b[i + 2]).\(b[i + 3])" : "?" }

    static func ip6(_ b: [UInt8], _ i: Int) -> String {
        guard i + 15 < b.count else { return "?" }
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { $0.copyBytes(from: b[i..<i + 16]) }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        return inet_ntop(AF_INET6, &addr, &buf, socklen_t(buf.count)).map { String(cString: $0) } ?? "?"
    }

    static func dns(_ d: [UInt8]) -> (summary: String, fields: [Field], response: Bool, qname: String, answers: [String])? {
        guard d.count >= 12 else { return nil }
        func u16(_ i: Int) -> Int { i + 1 < d.count ? Int(d[i]) << 8 | Int(d[i + 1]) : 0 }
        func name(_ start: Int) -> (String, Int) {
            var parts: [String] = [], i = start, end = -1, hops = 0
            while i < d.count, d[i] != 0, hops < 20 {
                if d[i] & 0xC0 == 0xC0 {
                    if end < 0 { end = i + 2 }
                    i = (Int(d[i]) & 0x3F) << 8 | Int(i + 1 < d.count ? d[i + 1] : 0); hops += 1; continue
                }
                let len = Int(d[i])
                guard i + 1 + len <= d.count else { break }
                parts.append(String(decoding: d[i + 1..<i + 1 + len], as: UTF8.self)); i += 1 + len
            }
            return (parts.joined(separator: "."), end >= 0 ? end : i + 1)
        }
        let types = [1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"]
        let isResponse = d[2] & 0x80 != 0
        let qd = u16(4), an = u16(6)
        var i = 12
        var qname = "", qtype = ""
        if qd > 0 {
            let (nm, next) = name(i); qname = nm; qtype = types[u16(next)] ?? "type \(u16(next))"; i = next + 4
        }
        var f = [Field("Kind", isResponse ? "answer" : "question"), Field("Asks for", "\(qtype) \(qname)")]
        var answers: [String] = []
        for _ in 0..<min(an, 8) {
            let (_, next) = name(i)
            guard next + 10 <= d.count else { break }
            let t = u16(next), len = u16(next + 8), rd = next + 10
            if t == 1, len == 4 { answers.append(ip4(d, rd)) }
            else if t == 28, len == 16 { answers.append(ip6(d, rd)) }
            else if t == 5 || t == 12 { answers.append(name(rd).0) }
            i = rd + len
        }
        if !answers.isEmpty { f.append(Field("Answer", answers.joined(separator: ", "))) }
        let summary = isResponse
            ? (answers.isEmpty ? "Answer for \(qname)" : "\(qname) → \(answers.joined(separator: ", "))")
            : qtype == "A" ? "What is the IPv4 address of \(qname)?"
            : qtype == "AAAA" ? "What is the IPv6 address of \(qname)?"
            : qtype == "PTR" ? (qname.contains("._tcp") || qname.contains("._udp") ? "Who offers \(qname)?" : "Which name has \(qname)?")
            : "Asks for the \(qtype) record of \(qname)"
        return (summary, f, isResponse, qname, answers)
    }

    static func clientHello(_ d: [UInt8]) -> (sni: String?, alpn: String?)? {
        var i = 5 + 4 + 2 + 32
        guard i < d.count else { return nil }
        i += 1 + Int(d[i])
        guard i + 2 <= d.count else { return nil }
        i += 2 + (Int(d[i]) << 8 | Int(d[i + 1]))
        guard i < d.count else { return nil }
        i += 1 + Int(d[i])
        guard i + 2 <= d.count else { return nil }
        let extEnd = min(d.count, i + 2 + (Int(d[i]) << 8 | Int(d[i + 1])))
        i += 2
        var sni: String?, alpn: String?
        while i + 4 <= extEnd {
            let type = Int(d[i]) << 8 | Int(d[i + 1]), len = Int(d[i + 2]) << 8 | Int(d[i + 3])
            let body = i + 4
            if type == 0, body + 5 <= extEnd {
                let l = Int(d[body + 3]) << 8 | Int(d[body + 4])
                if body + 5 + l <= extEnd { sni = String(decoding: d[body + 5..<body + 5 + l], as: UTF8.self) }
            } else if type == 16, body + 3 <= extEnd {
                let l = Int(d[body + 2])
                if body + 3 + l <= extEnd { alpn = String(decoding: d[body + 3..<body + 3 + l], as: UTF8.self) }
            }
            i = body + len
        }
        return (sni, alpn)
    }
}

// MARK: capture

/// Runs `tcpdump -w -` (or reads a capture file through it) and decodes the pcap stream.
/// Decoded packets queue up off the main thread and reach the UI four times a second.
final class PacketCapture: ObservableObject {
    enum State: Equatable { case idle, running, paused, needsPermission, failed(String), file(String), demo }

    @Published var packets: [Packet] = []
    @Published var state: State = .idle
    @Published var iface = PacketCapture.defaultInterface()
    @Published var rate: Double = 0
    @Published var total = 0
    @Published var counts: [String: Int] = [:]
    @Published var conversations: [String: Conversation] = [:]
    @Published var lockedBytes = 0     // app data that was encrypted
    @Published var readableBytes = 0   // app data anyone on the path could read

    /// Everything between this Mac and one other end for one service.
    struct Conversation: Identifiable {
        let id: String
        var remoteIP: String
        var name: String
        var service: String
        var app = ""
        var appPath = ""
        var top = 1
        var packets = 0
        var bytesIn = 0, bytesOut = 0
        var encrypted = false, readable = false
        var first: Date, last: Date
    }

    static let keep = 3000
    private var proc: Process?
    private var buf: [UInt8] = []
    private var pending: [Packet] = []
    private let lock = NSLock()
    private var flush: Timer?
    private var demoTimer: Timer?
    private var nextID = 1
    private var linkType: UInt32 = 1
    private var swapped = false, nano = false, gotHeader = false
    private var stderrText = ""
    private var source = ""
    private var names: [String: String] = [:]   // IP → name learned from DNS answers and TLS hellos
    private var localIPs = Set<String>()
    private var gateway = ""
    private var ports: [Int: (name: String, path: String)] = [:]   // local port → app, from lsof
    private var portsAt = Date.distantPast

    var interfaces: [String] {
        var out: [String] = []
        var ifa: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifa) == 0 else { return [iface] }
        defer { freeifaddrs(ifa) }
        var p = ifa
        while let i = p {
            let name = String(cString: i.pointee.ifa_name)
            if i.pointee.ifa_flags & UInt32(IFF_UP) != 0, !out.contains(name),
               ["en", "lo", "utun", "bridge"].contains(where: { name.hasPrefix($0) }) { out.append(name) }
            p = i.pointee.ifa_next
        }
        return out.sorted { ($0 == iface ? 0 : 1, $0) < ($1 == iface ? 0 : 1, $1) }
    }

    static func defaultInterface() -> String {
        let out = shell("/sbin/route", ["-n", "get", "default"])
        return out.split(separator: "\n").first { $0.contains("interface:") }?
            .split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? "en0"
    }

    /// True when ChmodBPF set /dev/bpf* to group access_bpf, so adding the user to that group is enough.
    var canGrant: Bool {
        guard let g = getgrnam("access_bpf") else { return false }
        var st = stat()
        return stat("/dev/bpf0", &st) == 0 && st.st_gid == g.pointee.gr_gid
    }

    func start() {
        stopProcess()
        refreshContext()
        source = iface
        run(["-i", iface, "-p", "-U", "-n", "-s", "2048", "-w", "-"], live: true)
    }

    func open(_ url: URL) {
        stopProcess()
        clear()
        source = "file"
        run(["-r", url.path, "-w", "-"], live: false, name: url.lastPathComponent)
    }

    func pause() { stopProcess(); if state == .running { state = .paused } }

    func clear() {
        lock.lock(); pending.removeAll(); lock.unlock()
        packets = []; total = 0; counts = [:]; rate = 0
        conversations = [:]; lockedBytes = 0; readableBytes = 0
    }

    /// Adds the user to access_bpf after the system asks for an admin password.
    func grant(done: @escaping (Bool) -> Void) {
        let user = NSUserName()
        guard user.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil else { return done(false) }
        let src = "do shell script \"/usr/sbin/dseditgroup -o edit -a \(user) -t user access_bpf\" with administrator privileges"
        var err: NSDictionary?
        NSAppleScript(source: src)?.executeAndReturnError(&err)
        done(err == nil)
    }

    func loadDemo(animated: Bool = true) {
        stopProcess()
        clear()
        state = .demo
        source = "en0"
        localIPs = ["192.168.1.23", "2001:db8::23"]; gateway = "192.168.1.1"; names = [:]
        let safari = (name: "Safari", path: "/Applications/Safari.app/Contents/MacOS/Safari")
        ports = [52344: safari, 61200: safari, 52350: (name: "curl", path: "/usr/bin/curl")]
        let frames = Self.demoFrames.map { hex in stride(from: 0, to: hex.count, by: 2).map { i -> UInt8 in
            let s = hex.index(hex.startIndex, offsetBy: i)
            return UInt8(hex[s..<hex.index(s, offsetBy: 2)], radix: 16) ?? 0
        } }
        let t0 = Date()
        func make(_ k: Int) -> Packet {
            let fr = frames[k % frames.count]
            defer { nextID += 1 }
            return PacketDecoder.decode(id: nextID, time: t0.addingTimeInterval(Double(k) * 0.35), wireLength: fr.count, bytes: fr, linkType: 1, iface: "en0")
        }
        if !animated {
            frames.indices.forEach { enqueue(make($0)) }
            drain()
            return
        }
        var k = 0
        demoTimer = Timer.scheduledTimer(withTimeInterval: 0.35, repeats: true) { [weak self] _ in
            guard let self else { return }
            self.enqueue(make(k)); k += 1
        }
        startFlush()
    }

    private func run(_ args: [String], live: Bool, name: String = "") {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/tcpdump")
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        buf = []; gotHeader = false; stderrText = ""
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { h.readabilityHandler = nil; return }
            self?.consume(d)
        }
        err.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard !d.isEmpty else { h.readabilityHandler = nil; return }
            self?.stderrText += String(decoding: d, as: UTF8.self)
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                guard let self, self.proc === proc else { return }
                self.proc = nil
                self.drain()
                let e = self.stderrText
                if e.contains("permission") || e.contains("Permission denied") { self.state = .needsPermission }
                else if live, proc.terminationReason != .uncaughtSignal, proc.terminationStatus != 0 {
                    self.state = .failed(e.split(separator: "\n").last.map(String.init) ?? "tcpdump stopped")
                } else if !live { self.state = .file(name) }
            }
        }
        do {
            try p.run()
            proc = p
            state = live ? .running : .file(name)
            startFlush()
        } catch {
            state = .failed(error.localizedDescription)
        }
    }

    private func stopProcess() {
        demoTimer?.invalidate(); demoTimer = nil
        if let p = proc { proc = nil; p.terminate() }
    }

    private func startFlush() {
        guard flush == nil else { return }
        flush = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { [weak self] _ in self?.drain() }
    }

    private func enqueue(_ p: Packet) {
        lock.lock()
        pending.append(p)
        if pending.count > Self.keep { pending.removeFirst(pending.count - Self.keep) }
        lock.unlock()
    }

    private func drain() {
        lock.lock(); let batch = pending; pending.removeAll(); lock.unlock()
        rate = rate * 0.6 + Double(batch.count) * 4 * 0.4
        guard !batch.isEmpty else { return }
        total += batch.count
        if state == .running, Date().timeIntervalSince(portsAt) > 3 {
            portsAt = Date()
            DispatchQueue.global(qos: .utility).async { [weak self] in
                let m = Self.portApps()
                DispatchQueue.main.async { self?.ports = m }
            }
        }
        let done = batch.map(finish)
        for p in done { counts[p.proto, default: 0] += 1; tally(p) }
        packets.append(contentsOf: done)
        if packets.count > Self.keep { packets.removeFirst(packets.count - Self.keep) }
    }

    /// pcap stream: 24-byte global header, then 16-byte record header + bytes per packet.
    private func consume(_ d: Data) {
        buf.append(contentsOf: d)
        var i = 0
        func r32(_ at: Int) -> UInt32 {
            let v = UInt32(buf[at]) | UInt32(buf[at + 1]) << 8 | UInt32(buf[at + 2]) << 16 | UInt32(buf[at + 3]) << 24
            return swapped ? v.byteSwapped : v
        }
        if !gotHeader {
            guard buf.count >= 24 else { return }
            let magic = UInt32(buf[0]) | UInt32(buf[1]) << 8 | UInt32(buf[2]) << 16 | UInt32(buf[3]) << 24
            swapped = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1
            nano = magic == 0xa1b23c4d || magic == 0x4d3cb2a1
            linkType = r32(20) & 0x0FFFFFFF
            gotHeader = true; i = 24
        }
        while buf.count - i >= 16 {
            let sec = r32(i), frac = r32(i + 4), incl = Int(r32(i + 8)), orig = Int(r32(i + 12))
            guard incl < 1 << 18 else { buf.removeAll(); return }
            guard buf.count - i - 16 >= incl else { break }
            let bytes = Array(buf[i + 16..<i + 16 + incl])
            let t = Date(timeIntervalSince1970: Double(sec) + Double(frac) / (nano ? 1e9 : 1e6))
            let id = nextID; nextID += 1
            enqueue(PacketDecoder.decode(id: id, time: t, wireLength: orig, bytes: bytes, linkType: linkType, iface: source == "file" ? "file" : source))
            i += 16 + incl
        }
        if i > 0 { buf.removeFirst(i) }
    }

    private func tally(_ p: Packet) {
        if p.appBytes > 0 { if p.encrypted { lockedBytes += p.appBytes } else { readableBytes += p.appBytes } }
        let remote = p.sent == false ? p.srcIP : p.dstIP
        guard !remote.isEmpty else { return }
        let rport = p.sent == false ? p.sport : p.dport
        let service = p.proto == "HTTP/3" ? "HTTP/3" : PacketDecoder.knownPorts[rport] ?? p.proto
        let key = remote + "|" + service
        var c = conversations[key] ?? Conversation(id: key, remoteIP: remote, name: "", service: service, first: p.time, last: p.time)
        c.name = friendly(remote)
        if !p.app.isEmpty { c.app = p.app; c.appPath = p.appPath }
        c.top = max(c.top, p.top)
        c.packets += 1
        if p.sent == false { c.bytesIn += p.wireLength } else { c.bytesOut += p.wireLength }
        if p.appBytes > 0 { if p.encrypted { c.encrypted = true } else { c.readable = true } }
        c.last = p.time
        conversations[key] = c
    }

    /// Writes the packets in memory as a classic .pcap file (opens in Wireshark).
    func save(to url: URL) throws {
        var d = Data()
        func le32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { d.append(contentsOf: $0) } }
        func le16(_ v: UInt16) { withUnsafeBytes(of: v.littleEndian) { d.append(contentsOf: $0) } }
        le32(0xa1b2c3d4); le16(2); le16(4); le32(0); le32(0); le32(65535); le32(packets.first?.link ?? 1)
        for p in packets {
            let t = p.time.timeIntervalSince1970
            le32(UInt32(t)); le32(UInt32((t - floor(t)) * 1e6)); le32(UInt32(p.bytes.count)); le32(UInt32(p.wireLength))
            d.append(contentsOf: p.bytes)
        }
        try d.write(to: url)
    }

    /// Local port → app name for this user's sockets (lsof can't see other users' processes without root).
    static func portApps() -> [Int: (name: String, path: String)] {
        var m: [Int: (name: String, path: String)] = [:]
        var cmd = "", path = "", pid: Int32 = 0
        for line in shell("/usr/sbin/lsof", ["-nP", "+c", "0", "-iTCP", "-iUDP", "-F", "pcn"]).split(separator: "\n") {
            if line.hasPrefix("p") { pid = Int32(line.dropFirst()) ?? 0 }
            else if line.hasPrefix("c") {
                var name = String(line.dropFirst())
                var buf = [CChar](repeating: 0, count: 4096)
                path = proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 ? String(cString: buf) : ""
                // Some CLIs install as ".../tool/versions/1.2.3": name them after the folder instead.
                if name.range(of: "^[0-9.]+$", options: .regularExpression) != nil, !path.isEmpty {
                    let parts = path.split(separator: "/").map(String.init)
                    name = parts.dropLast().last { !["versions", "bin", "libexec", "current"].contains($0) } ?? name
                }
                cmd = prettyApp(name)
            }
            else if line.hasPrefix("n") {
                let local = line.dropFirst().components(separatedBy: "->")[0]
                if let port = Int(local.split(separator: ":").last ?? ""), port > 0 { m[port] = (cmd, path) }
            }
        }
        return m
    }

    static func prettyApp(_ c: String) -> String {
        let known = ["com.apple.WebKit.Networking": "Safari", "com.apple.Safari": "Safari", "Google Chrome": "Chrome", "Microsoft Edge": "Edge",
                     "Brave Browser": "Brave", "firefox": "Firefox", "Arc": "Arc", "Code Helper": "VS Code", "Cursor Helper": "Cursor",
                     "Slack": "Slack", "Discord": "Discord", "Spotify": "Spotify", "zoom.us": "Zoom", "node": "Node.js", "python3": "Python",
                     "Python": "Python", "ollama": "Ollama", "Claude": "Claude", "claude": "Claude Code", "Telegram": "Telegram", "WhatsApp": "WhatsApp"]
        if let v = known[c] { return v }
        if let hit = known.first(where: { c.hasPrefix($0.key) }) { return hit.value }
        if let r = c.range(of: " Helper") { return String(c[..<r.lowerBound]) }
        return c
    }

    /// Fills in who's who: "your Mac", "your router", names learned earlier, and the finished story.
    private func finish(_ p: Packet) -> Packet {
        var p = p
        for l in p.learned where !l.ip.isEmpty { names[l.ip] = l.name }
        p.srcName = friendly(p.srcIP); p.dstName = friendly(p.dstIP)
        p.sent = localIPs.contains(p.srcIP) ? true : localIPs.contains(p.dstIP) ? false : nil
        if let local = p.sent.map({ $0 ? p.sport : p.dport }), let app = ports[local] {
            p.app = app.name; p.appPath = app.path
            if p.sent == true { p.srcName = "\(app.name) on your Mac" } else { p.dstName = "\(app.name) on your Mac" }
        }
        var text = p.story
        if text.hasPrefix("{S}") { text = cap(p.srcName) + text.dropFirst(3) }
        p.story = text.replacingOccurrences(of: "{S}", with: p.srcName).replacingOccurrences(of: "{D}", with: p.dstName)
        return p
    }

    /// Capitalise "your Mac" at the start of a sentence, but never a domain like "example.com".
    private func cap(_ s: String) -> String {
        ["your", "a", "the", "everyone", "nearby"].contains(String(s.split(separator: " ").first ?? "")) ? s.prefix(1).uppercased() + s.dropFirst() : s
    }

    func friendly(_ ip: String) -> String {
        if ip.isEmpty { return "a device" }
        if localIPs.contains(ip) { return "your Mac" }
        if ip == gateway { return "your router" }
        if let n = names[ip] { return n }
        if ip == "broadcast" || ip == "255.255.255.255" { return "everyone on your network" }
        if ip == "0.0.0.0" || ip == "::" { return "a device with no address yet" }
        if ip == "224.0.0.251" || ip == "ff02::fb" { return "nearby devices (Bonjour)" }
        if ip == "239.255.255.250" || ip == "ff02::c" { return "nearby smart devices" }
        if ip.hasPrefix("ff") || (Int(ip.split(separator: ".").first ?? "") ?? 0) >= 224 { return "a group of nearby devices" }
        let o = ip.split(separator: ".").compactMap { Int($0) }
        let lan = ip.hasPrefix("fe80") || ip.hasPrefix("fd") || (o.count == 4 && (o[0] == 10 || (o[0] == 192 && o[1] == 168) || (o[0] == 172 && (16...31).contains(o[1])) || o[0] == 127))
        return lan ? "a device on your network (\(ip))" : "the server \(ip)"
    }

    private func refreshContext() {
        var ips = Set<String>()
        var ifa: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&ifa) == 0 {
            var p = ifa
            while let i = p {
                if let a = i.pointee.ifa_addr {
                    var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    let len = socklen_t(a.pointee.sa_family == UInt8(AF_INET6) ? MemoryLayout<sockaddr_in6>.size : MemoryLayout<sockaddr_in>.size)
                    if [UInt8(AF_INET), UInt8(AF_INET6)].contains(a.pointee.sa_family),
                       getnameinfo(a, len, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                        ips.insert(String(cString: host).components(separatedBy: "%").first ?? "")
                    }
                }
                p = i.pointee.ifa_next
            }
            freeifaddrs(ifa)
        }
        localIPs = ips
        gateway = Self.shell("/sbin/route", ["-n", "get", "default"]).split(separator: "\n")
            .first { $0.contains("gateway:") }?.split(separator: ":").last?.trimmingCharacters(in: .whitespaces) ?? ""
    }

    private static func shell(_ path: String, _ args: [String]) -> String {
        let p = Process(), out = Pipe()
        p.executableURL = URL(fileURLWithPath: path); p.arguments = args; p.standardOutput = out; p.standardError = Pipe()
        guard (try? p.run()) != nil else { return "" }
        p.waitUntilExit()
        return String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    }

    /// A short made-up browsing session (ARP, DNS, TCP handshake, TLS, HTTP, ping, QUIC, mDNS) for when capture is off.
    static let demoFrames: [String] = [
        "ffffffffffff3a1c5e00a101080600010800060400013a1c5e00a101c0a80117000000000000c0a80101000000000000000000000000000000000000",
        "8e2f0b00c0023a1c5e00a1010800450000391c46400040119b05c0a80117c0a80101cfdb0035002500003f2a01000001000000000000076578616d706c6503636f6d0000010001",
        "3a1c5e00a1018e2f0b00c0020800450000491c46400040119af5c0a80101c0a801170035cfdb003500003f2a81800001000100000000076578616d706c6503636f6d0000010001c00c000100010000012c00045db8d70e",
        "8e2f0b00c0023a1c5e00a1010800450000341c464000400627f8c0a801175db8d70ecc7801bb000003e8000000008002ffff00000000020405b40103030601010402",
        "3a1c5e00a1018e2f0b00c0020800450000341c46400038062ff85db8d70ec0a8011701bbcc7800001b58000003e98012ffff00000000020405b40103030601010402",
        "8e2f0b00c0023a1c5e00a1010800450000281c46400040062804c0a801175db8d70ecc7801bb000003e900001b595010ffff00000000",
        "8e2f0b00c0023a1c5e00a1010800450000ad1c4640004006277fc0a801175db8d70ecc7801bb000003e900001b595018ffff0000000016030100800100007c0303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00061301130213030100002d00000010000e00000b6578616d706c652e636f6d0010000e000c02683208687474702f312e31002b0003020304",
        "3a1c5e00a1018e2f0b00c00208004500008d1c46400038062f9f5db8d70ec0a8011701bbcc78000023f00000046e5018ffff0000000017030300600b30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c6186abd0f51a3f6489aed3f81d42678cb1d6fb20456a8fb4d9fe23486d92b7dc01264b7095badf04294e7398bde2072c51769bc0e50a2f54799ec3e80d32577ca1c6",
        "3a1c5e00a1018e2f0b00c0020800450004dd1c46400038062b4f5db8d70ec0a8011701bbcc78000024550000046e5010ffff0000000017030304b0073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d42",
        "3a1c5e00a1018e2f0b00c0020800450004dd1c46400038062b4f5db8d70ec0a8011701bbcc780000290a0000046e5010ffff0000000017030304b0073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d42",
        "3a1c5e00a1018e2f0b00c0020800450004dd1c46400038062b4f5db8d70ec0a8011701bbcc7800002dbf0000046e5010ffff0000000017030304b0073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d42",
        "3a1c5e00a1018e2f0b00c0020800450004dd1c46400038062b4f5db8d70ec0a8011701bbcc78000032740000046e5010ffff0000000017030304b0073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d4277ace1164b80b5ea1f5489bef3285d92c7fc31669bd0053a6fa4d90e4378ade2174c81b6eb20558abff4295e93c8fd32679cd1063b70a5da0f4479aee3184d82b7ec21568bc0f52a5f94c9fe33689dd2073c71a6db10457aafe4194e83b8ed22578cc1f62b6095caff34699ed3083d72a7dc11467bb0e51a4f84b9ee23588dc2f72c6196cb00356a9fd4093e73a8dd12477cb1e61b5085baef24598ec3f82d6297cc01366ba0d50a3f74a9de13487db2e71c5186bbf0255a8fc4f92e6398cd02376ca1d60b4075aadf14497eb3e81d5287bcf1265b90c5fa2f6499ce03386da2d70c4176abe0154a7fb4e91e5388bdf2275c91c6fb30659acf04396ea3d80d42",
        "8e2f0b00c0023a1c5e00a1010800450000281c46400040062804c0a801175db8d70ecc7801bb0000046e000037295010ffff00000000",
        "8e2f0b00c0023a1c5e00a10108004500007c1c464000400627b0c0a801175db8d70ecc7e00500000138800001f405018ffff00000000474554202f696e6465782e68746d6c20485454502f312e310d0a486f73743a206578616d706c652e636f6d0d0a557365722d4167656e743a206375726c2f382e372e310d0a4163636570743a202a2f2a0d0a0d0a",
        "8e2f0b00c0023a1c5e00a10108004500004c1c46400040015aaac0a80117010101010800b3911a2b0001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
        "8e2f0b00c0023a1c5e00a10186dd60000000006a114020010db800000000000000000000002326062800021fcb07682080daaf6b8b2cef1001bb006a0000c300000001080001020304050607000044d0000d1a2734414e5b6875828f9ca9b6c3d0ddeaf704111e2b3845525f6c798693a0adbac7d4e1eefb0815222f3c495663707d8a97a4b1becbd8e5f2ff0c192633404d5a6774818e9ba8b5c2cfdce9f603",
        "01005e0000fb3a1c5e00a1010800450000411c464000ff11bcaac0a80117e00000fb14e914e9002d0000000000000001000000000000085f616972706c6179045f746370056c6f63616c00000c0001",
        "8e2f0b00c0023a1c5e00a1010800450000281c46400040062804c0a801175db8d70ecc7801bb0000046e000037295011ffff00000000",
    ]
}
