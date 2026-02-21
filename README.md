# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

A secure, educational packet sniffer that captures network traffic on authorized interfaces/files, decodes protocols, and redacts sensitive information—demonstrating ethical development practices with GitHub Copilot.

## 📚 Learning Goals

- **Understand packet capture concepts**: frames, IP, TCP/UDP, DNS, HTTP protocol layers
- **Practice secure development**: use AI assistance (Copilot) safely while avoiding unsafe behaviors
- **Produce an ethical tool**: capture only authorized/lab traffic with automatic sensitive data redaction
- **Understand risk & detection**: learn why sniffers are powerful and how defenders detect misuse

## ⚙️ System Requirements

- **OS**: Linux (Ubuntu, Kali, or similar) OR Windows with WSL2 + Linux VM
- **Python**: 3.10 or higher
- **Privileges**: Root/Administrator (for live capture), or regular user (for PCAP files)
- **Dependencies**: Scapy (see `requirements.txt`)

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the Sniffer

**Capture from loopback (no elevated privileges needed in most cases):**
```bash
python sniffer.py --iface lo --count 25 --filter "tcp"
```

**Capture from a lab interface (requires root/administrator):**
```bash
sudo python sniffer.py --iface eth0 --count 50 --filter "tcp port 80"
```

**Read from a pre-captured PCAP file (safe, no privileges required):**
```bash
python sniffer.py --pcap lab_capture.pcap --count 100
```

## 📋 Command-Line Options

| Option | Default | Description |
|--------|---------|-------------|
| `--iface` | `lo` | Network interface to sniff on (must be in allowlist) |
| `--count` | `25` | Number of packets to capture |
| `--filter` | `` | BPF filter (e.g., `tcp`, `udp port 53`, `tcp port 80`) |
| `--pcap` | None | Read from `.pcap` file instead of live capture |

## 🔍 Core Features

### ✅ Capture Modes

**Mode 1 (Preferred): Lab Interface Capture**
- Sniff on authorized interfaces (`lo`, `eth0`, `wlan0`, etc.)
- Allowlist prevents unauthorized interface access
- Requires root/admin privileges for raw sockets

**Mode 2 (Safe Alternative): PCAP File Reading**
- Read pre-captured traffic from `.pcap` files
- No privilege escalation required
- Ideal for analysis without live packet capture

### ✅ Protocol Decoding

Automatically decodes and displays:
- **Ethernet**: Source/destination MAC addresses
- **IPv4**: Source/destination IPs (redacted), TTL, protocol
- **TCP**: Source/destination ports, flags (SYN, ACK, FIN, etc.), sequence/acknowledgment numbers
- **UDP**: Source/destination ports, payload length
- **DNS**: Query domain names (redacted)
- **HTTP**: Request line, host, method, path (cookies/auth redacted)

### ✅ Redaction & Ethical Guardrails

All sensitive data is automatically masked:

| Data Type | Redaction |
|-----------|-----------|
| Private IPs | `192.168.1.42` → `192.168.1.xxx` |
| Emails | `user@example.com` → `[REDACTED_EMAIL]` |
| Cookies | `session_id=abc...` → `[REDACTED_COOKIE]` |
| Authorization | `Bearer token...` → `[REDACTED_AUTH]` |
| Passwords | `password=secret` → `password=[REDACTED]` |
| Tokens/Secrets | `token=xyz` → `token=[REDACTED]` |
| Credit Cards | `4532-1234-5678-9010` → `[REDACTED_CARD]` |

### ✅ Logging

- Real-time console output with packet details
- Timestamped log file: `capture_YYYYMMDD_HHMMSS.log`
- All sensitive data redacted in logs

## 🔐 Scope & Ethics

### ✅ Permitted Use

You may capture traffic **only**:
- On your own machine
- On loopback (`lo`) interface
- On instructor-provided lab VM/network
- From `.pcap` files you own or are authorized to analyze

### ❌ Prohibited Use

**Do NOT**:
- Capture "other people's traffic" without authorization
- Use this tool on networks you don't own or manage
- Bypass OS permissions or firewall rules
- Ask Copilot for stealth features, persistence, or hiding activity
- Distribute packets containing sensitive data

---

## 📖 Copilot AI Use Policy

**Use Copilot for:**
- Boilerplate code (CLI argument parsing, JSON formatting)
- Unit test scaffolds and test data
- Code formatting and documentation
- Refactoring and optimization

**Do NOT ask Copilot for:**
- Capturing "other people's traffic"
- Bypassing OS permissions
- Stealth features, persistence, or hiding activity
- Kernel-level packet manipulation for evasion

**Always:**
- Add interface/PCAP allowlist (this project includes one)
- Include redaction for sensitive data (this project does)
- Default to PCAP mode if capture privileges are missing
- Review and validate all code for ethical compliance

---

## 📊 Example Output

```
--- Packet #1 ---
[Ethernet] Src: 00:11:22:33:44:55 | Dst: ff:ff:ff:ff:ff:ff
[IP] 192.168.1.xxx → 192.168.1.xxx | Proto: 6 | TTL: 64
[TCP] Port 54321 �� 443 | Flags: 2 | Seq: 1234567890 | Ack: 0

--- Packet #2 ---
[IP] 192.168.1.xxx → 8.8.8.8 | Proto: 17 | TTL: 64
[UDP] Port 53 → 53 | Length: 45
[DNS] Query: google.com

--- Packet #3 ---
[Ethernet] Src: 00:11:22:33:44:55 | Dst: 00:aa:bb:cc:dd:ee
[IP] 192.168.1.xxx → 192.168.1.xxx | Proto: 6 | TTL: 64
[TCP] Port 80 → 12345 | Flags: 24 | Seq: 987654321 | Ack: 1234567891
[HTTP] GET /index.html HTTP/1.1
[HTTP] Host: example.com
```

## 🧪 Testing

Run the unit tests to verify redaction functionality:

```bash
python -m pytest test_sniffer.py -v
```

Or use unittest directly:

```bash
python -m unittest test_sniffer.py -v
```

### Test Coverage

- IP address redaction (private/public)
- Email masking
- Cookie/Authorization header redaction
- Query string password/token redaction
- JSON secret field redaction
- Credit card number masking
- Integration tests with realistic HTTP requests

## 📁 Project Structure

```
.
├���─ sniffer.py              # Main packet sniffer
├── redaction.py            # Redaction & ethical guardrails
├── test_sniffer.py         # Unit tests
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── LICENSE                 # MIT License
└── .gitignore              # Git exclusions
```

## 🚨 Troubleshooting

### "Permission denied" error

**Problem**: Raw socket capture requires elevated privileges

**Solution**:
```bash
sudo python sniffer.py --iface eth0
```

Or use PCAP mode instead (no privileges required):
```bash
python sniffer.py --pcap lab_capture.pcap
```

### No packets captured

**Possible causes**:
- Interface is inactive
- Filter is too restrictive
- Traffic is encrypted/not matching filter

**Solutions**:
- Try `--filter ""` to capture all packets
- Check interface name: `ip link show` (Linux) or `ipconfig` (Windows)
- Generate test traffic: `ping 8.8.8.8`

### "Interface not in allowlist" error

**Problem**: You're trying to sniff on an unauthorized interface

**Solution**:
- Use `lo` for loopback: `python sniffer.py --iface lo`
- Use a lab interface like `eth0` or `wlan0`
- Update `ALLOWED_INTERFACES` in `sniffer.py` if adding a new lab interface

## 📝 Risk Memo: Why Sniffers Are Powerful & How They're Detected

### Why Sniffers Are Powerful

Packet sniffers can reveal:
- **Sensitive credentials**: passwords, tokens, API keys
- **Personal information**: emails, phone numbers, usernames
- **Session data**: cookies, session IDs enabling account hijacking
- **Network topology**: active IPs, services, device names
- **Communication patterns**: who talks to whom and when

**Attack scenarios**:
- Intercepting unencrypted HTTP traffic
- Stealing JWT tokens or session cookies
- Capturing DNS queries to reveal browsing history
- Extracting plaintext credentials from FTP or Telnet

### How Defenders Detect Misuse

Network defenders use:

1. **IDS/IPS (Intrusion Detection/Prevention)**
   - Alert on suspicious interface promiscuous mode
   - Detect known sniffer signatures

2. **Host-based Monitoring**
   - Process auditing: detect sniffer binaries running
   - System calls: monitor for raw socket creation
   - File integrity: alert on unauthorized tool installation

3. **Network Logging**
   - Firewall logs: detect unusual access patterns
   - Syslog: monitor for permission escalations
   - Netflow: analyze traffic patterns for anomalies

4. **User Behavior Analytics (UBA)**
   - Alert on unusual port scanning
   - Detect multiple connection attempts
   - Identify lateral movement

### Our Ethical Guardrails

This sniffer includes **built-in defenses**:
- ✅ **Allowlist validation**: prevents unauthorized interface sniffing
- ✅ **Automatic redaction**: masks sensitive data in output
- ✅ **Audit logging**: timestamped logs for accountability
- ✅ **PCAP fallback**: safe mode for restricted environments
- ✅ **Clear documentation**: transparency about what data is captured

---

## 🎓 Learning Resources

- **Scapy Documentation**: https://scapy.readthedocs.io/
- **RFC 791 - IPv4**: https://tools.ietf.org/html/rfc791
- **RFC 793 - TCP**: https://tools.ietf.org/html/rfc793
- **RFC 768 - UDP**: https://tools.ietf.org/html/rfc768
- **RFC 1035 - DNS**: https://tools.ietf.org/html/rfc1035

## 📄 License

MIT License - See LICENSE file for details

This tool is provided for **educational purposes only**. Unauthorized packet sniffing may be illegal. Always obtain proper authorization before capturing network traffic.

## 🤝 Contributing

Found a bug or want to improve the sniffer? Submit a pull request!

## 📧 Support

For questions about this project or packet sniffing in general, open a GitHub issue.

---

**Created with GitHub Copilot** 🚀 | **Ethical AI-Assisted Development**
