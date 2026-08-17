# NetWARRIOR — Async Network Security Testing Suite

> **LEGAL NOTICE: For authorized penetration testing, security research, and educational use only.
> Running this tool against systems you do not own or have explicit written permission to test is illegal.
> See [DISCLAIMER.md](DISCLAIMER.md) before use.**

---

## What It Is

NetWARRIOR is a Python-based async network security testing platform built for authorized
penetration testers, red teamers, and security researchers. It provides a unified terminal
interface for network stress testing, reconnaissance, vulnerability assessment, and web
application testing.

Designed as a learning resource for understanding how network attacks work — and how to
defend against them.

---

## Features

### Attack Vectors (40+)   
| Category       |                                             Vectors                                                          |
|----------------|--------------------------------------------------------------------------------------------------------------|
| Flood          | SYN, UDP, ICMP, ACK, RST, XMAS, NULL, FIN, Zero-Window, MAC, Smurf, LAND, SCTP INIT, Teardrop, Ping of Death |
| Amplification  | DNS, NTP, SNMP, Memcached, SSDP, Chargen                                                                     |
| Application    | Slowloris, HTTP flood, RUDY, Slow Read, HTTP/2 rapid reset, WebSocket flood                                  |
| Layer 2 / Net  | ARP poison, VLAN double-tag, CDP/LLDP/STP flood                                                              |
| IPv6           | RA flood, NA flood, NS flood                                                                                 |
| WiFi           | Deauth, Beacon flood                                                                                         |
| Misc           | GRE spoof, PCAP replay, LLMNR/NBNS/mDNS poison, DHCP starvation                                              |

### Reconnaissance
- Async TCP port scanner (concurrent, semaphore-gated)
- OS fingerprinting via TTL + banner grab
- ARP/ICMP network topology mapping
- DNS lookup, reverse DNS, zone transfer attempts
- Banner-based vulnerability detection

### Penetration Testing
- SSH / FTP brute force (streaming wordlist, async)
- HTTP Basic auth brute force
- SQL injection, XSS, LFI, SSRF, command injection probes
- SSH interactive shell

### Monitoring
- Live traffic monitor (packet capture)
- Bandwidth meter
- Active connection table
- Passive credential capture (authorized network audits)

### Other
- Cloud provider IP detection (AWS/Azure/GCP)
- HTML session report generation
- Phishing simulation server (authorized red team exercises only)
- Reverse shell payload generation
- Persistence payload generation

---

## Architecture

```
netwarrior.py            — single-file, self-contained
│
├── Core
│   ├── Config           — Pydantic-style settings, TOML persistence
│   ├── NetworkContext   — Auto-detect IP, interface, gateway, DNS
│   ├── AttackState      — Thread-safe per-attack metrics
│   ├── AttackRegistry   — Lifecycle manager for all running attacks
│   ├── LogBus           — Structured log ring buffer (deque, 500 entries)
│   ├── RateLimiter      — Token bucket, async-safe
│   └── AttackEngine     — Async send loop, executor-bridged scapy
│
├── Attacks              — All 40+ attack implementations
├── Recon                — Port scan, fingerprint, DNS, vuln scan
├── Pentest              — Brute force, web vuln probes
├── PostExploit          — Payload generators
├── Report               — HTML report
└── UI                   — Adaptive Rich TUI
```

**Async-first.** `asyncio` + `uvloop` for all I/O. Blocking calls (scapy, paramiko) are
wrapped in `loop.run_in_executor()` so the event loop never freezes.

**Adaptive UI.** Detects terminal width at render time. Wide terminals (100+ cols) get a
two-column attack menu and live stats sidebar. Narrow terminals stack single-column.
Auto-selects `box.ROUNDED` on modern terminals, `box.ASCII` on legacy Windows CMD.

---

## Requirements

- Python 3.11+
- Linux (full feature set) or Windows (most features, some raw socket ops require Npcap)
- Root / Administrator for raw packet operations

```
rich>=13.0.0
scapy>=2.5.0
psutil>=5.9.0
paramiko>=3.0.0
dnspython>=2.2.0
aiohttp>=3.9.0
uvloop>=0.19.0
tomli>=2.0.0
tomli_w>=1.0.0
```

---

## Installation

```bash
git clone https://github.com/dev-joshua-py/NetWARRIOR.git
cd netwarrior
pip install -r requirements.txt

# Linux — root required for raw packet injection
sudo python3 netwarrior.py

# Windows — run as Administrator, Npcap must be installed
# https://npcap.com
python netwarrior.py
```

The tool auto-checks dependencies on launch and offers to install any that are missing.

---

## Usage

```
┌─ Navigation ──────────────────────────────────────────────────┐
│  [1] ATTACKS   [2] RECON   [3] PENTEST   [4] REPORT   [5] CMD │
└───────────────────────────────────────────────────────────────┘

Commands (type directly, press Enter):

  attack syn 192.168.1.1 80 30 1000    SYN flood: target port duration pps
  attack udp 10.0.0.1 53 60 5000       UDP flood
  attack slowloris 10.0.0.1 80 60      Slowloris on port 80

  scan 192.168.1.1                     Port scan
  scan 192.168.1.0/24                  Network discovery
  fingerprint 10.0.0.1                 OS + banner grab
  vuln 10.0.0.1                        Vulnerability check

  sshbrute 10.0.0.1 root rockyou.txt   SSH brute force
  sql http://10.0.0.1/page id          SQL injection probe

  list                                 Active attacks
  stop                                 Stop all
  status                               Packet stats
  q                                    Quit
```

---

## Tested On

| Platform              | Terminal              | Status  |
|-----------------------|-----------------------|---------|
| Ubuntu 22.04+         | GNOME Terminal        | Full    |
| Kali Linux            | xterm / Terminator    | Full    |
| Debian 12             | xfce4-terminal        | Full    |
| Windows 11            | Windows Terminal      | Full    |
| Windows 10            | CMD (legacy)          | Partial |
| macOS 14              | iTerm2                | Full    |

---

## Similar Projects

NetWARRIOR is inspired by and builds on concepts from:
- [Scapy](https://scapy.net) — packet crafting
- [hping3](https://github.com/antirez/hping) — network testing
- [Metasploit](https://github.com/rapid7/metasploit-framework) — penetration testing
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQL injection testing

---

## License

MIT — see [LICENSE](LICENSE)

---

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md). Use responsibly. Only on systems you own or have
explicit written authorization to test.
