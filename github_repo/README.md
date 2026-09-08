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

### Attack Vectors

The full list, and the arguments each one takes, is in the in-app **ATTACK menu**
(`1`), which is generated from the same catalog the `attack` command dispatches
from — the two can't drift apart.

| Category      | Vectors                                                                                             |
|---------------|----------------------------------------------------------------------------------------------------|
| Flood         | SYN, UDP, ICMP, ACK, RST, XMAS, NULL, FIN, Zero-Window, MAC, Smurf, LAND, SCTP INIT, Teardrop, PoD, GRE |
| Reflection    | DNS, NTP, SNMP, Memcached, SSDP, CHARGEN                                                             |
| Application   | Slowloris, HTTP flood, RUDY, Slow Read, HTTP/2 rapid reset, WebSocket flood                          |
| Layer 2       | ARP poison, VLAN double-tag, CDP/LLDP/STP flood, DHCP starvation                                     |
| IPv6 ND       | RA flood, NA flood, NS flood                                                                         |
| Name poison   | LLMNR, NBT-NS, mDNS                                                                                  |
| Wireless      | Deauth, Beacon flood, WPA handshake capture                                                          |
| Recon/replay  | SSDP discovery, RADIUS PoD, cloud-IP lookup, HTTP throughput, PCAP replay                            |
| Monitoring    | Passive credential sniff, traffic monitor, bandwidth meter, connection table                        |
| Ext. tools    | `nmap`, `sqlmap` wrappers                                                                            |
| Social        | Credential-harvest web server                                                                       |

### Reconnaissance
- Async TCP port scanner (concurrent, semaphore-gated)
- OS fingerprinting via TTL + concurrent banner grab
- ARP/ICMP topology mapping (batched, not host-by-host)
- DNS lookup, reverse DNS, zone transfer attempts
- Banner-based vulnerability detection

### Penetration Testing
- SSH / FTP brute force (streaming wordlist, async)
- HTTP Basic auth brute force
- `sshexec` — run a single command over SSH with recovered credentials
- SQL injection, reflected XSS, LFI, SSRF, command injection probes
  (signature-based, not naive substring matching)

### Monitoring
- Live traffic monitor (packet capture)
- Bandwidth meter
- Active connection table
- Passive credential capture (authorized network audits)

### Other
- Cloud provider IP detection (AWS / Azure / GCP / …)
- HTML session report (`report save`)
- Phishing simulation server (authorized red team exercises only)
- `payload revshell` / `payload persist` one-liner generators

---

## Architecture

```
netwarrior.py            — single-file, self-contained
│
├── Core
│   ├── Config           — settings + TOML persistence, safe-mode / pps guard rails
│   ├── NetworkContext   — Auto-detect IP, interface, gateway, DNS
│   ├── AttackState      — Thread-safe per-attack metrics
│   ├── AttackRegistry   — Lifecycle manager, retains session history
│   ├── LogBus           — Structured log ring buffer (deque, 500 entries)
│   ├── RateLimiter      — Token bucket, async-safe
│   └── AttackEngine     — Batched async send loop, executor-bridged scapy
│
├── Attacks              — All 40+ attack implementations
├── Recon                — Port scan, fingerprint, DNS, vuln scan
├── Pentest              — Brute force, web vuln probes
├── PostExploit          — Payload generators (`payload` command)
├── Report               — HTML session report (`report save`)
└── UI                   — Adaptive Rich TUI
```

**Async-first.** `asyncio` (plus `uvloop` on Linux/macOS) for all I/O. Blocking calls
(scapy sends, `sniff`, paramiko) run in `loop.run_in_executor()`, and packet sends are
dispatched in small batches, so the event loop — and the `stop` command — stay
responsive even at high packet rates. Attacks run as background tasks; launching one
never blocks the UI, and `stop` ends running attacks without shutting the engine down.

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
tomli>=2.0.0             ; python_version < "3.11"
tomli_w>=1.0.0
uvloop>=0.19.0           ; sys_platform != "win32"
```

`tomli` is only needed on Python 3.10 and below — 3.11+ uses the standard-library
`tomllib`. `uvloop` is Linux/macOS only; on Windows the tool runs on the default
event loop.

---

## Installation

```bash
git clone https://github.com/dev-joshua-py/NetWARRIOR.git
cd NetWARRIOR/github_repo
pip install -r requirements.txt

# Linux — root required for raw packet injection
sudo python3 netwarrior.py

# Windows — run as Administrator, Npcap must be installed (https://npcap.com)
python netwarrior.py
```

On launch the tool checks for missing dependencies and prints an install command
if any are absent.

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

  payload revshell 10.0.0.1 4444       Generate a reverse-shell one-liner
  list                                 Active attacks
  stop                                 Stop all running attacks
  status                               Packet / traffic stats
  report save                          Write an HTML session report
  q                                    Quit
```

`pps` is capped at `max_pps` (default 10000) from the config file. Set `safe_mode = true`
in `~/.config/netwarrior/config.toml` (or `%APPDATA%\netwarrior\config.toml` on Windows)
to block attacks aimed at loopback, multicast, or broadcast addresses.

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
