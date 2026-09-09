# NetWARRIOR — Async Network Security Testing Suite

> **LEGAL NOTICE: For authorized penetration testing, security research, and educational use only.
> Running this tool against systems you do not own or have explicit written permission to test is illegal.
> See [DISCLAIMER.md](DISCLAIMER.md) before use.**

---

## What It Is

NetWARRIOR is a Python-based async network security testing platform built for authorized
penetration testers, red teamers, and security researchers. It provides a unified interface —
a terminal UI **and** an optional desktop GUI — for network stress testing, reconnaissance,
vulnerability assessment, and web application testing.

Designed as a learning resource for understanding how network attacks work — and how to
defend against them. Every technique in the tool is paired with detection and
mitigation guidance in **[DEFENSE.md](DEFENSE.md)**, plus a ready-to-load Suricata
ruleset in [`detection/netwarrior.rules`](detection/netwarrior.rules).

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
└── UI                   — Adaptive Rich TUI (dispatches every command)

netwarrior_gui.py        — Tk desktop front-end (optional)
└── AsyncCore            — Runs the engine on a background asyncio loop and
                           drives the same UI._process_command dispatcher, so
                           the GUI and CLI share one code path and can't diverge
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
pip install -r requirements.txt        # or:  pip install .

# Linux — root required for raw packet injection
sudo python3 netwarrior.py             # or, after `pip install .`:  sudo netwarrior

# Windows — run as Administrator, Npcap must be installed (https://npcap.com)
python netwarrior.py
```

On launch the tool checks for missing dependencies and prints an install command
if any are absent. **The first interactive run prints the legal notice and asks
you to type `I HAVE AUTHORIZATION` before it will start** (recorded in the config
file; pass `--yes` to skip in automation).

### Graphical interface (GUI)

Prefer a desktop window to the terminal? Launch the Tk GUI:

```bash
python netwarrior_gui.py          # or, after `pip install .`:  netwarrior-gui
```

It takes the **same flags** as the CLI (`--safe`, `--scope`, `--iface`, `--yes`,
`--no-audit`) and is a thin shell over the exact same engine — it drives the same
command dispatcher the terminal UI uses, so every attack, recon/pentest probe,
payload generator, report and **every guard rail** (safe-mode, scope allowlist,
authorization gate, audit trail, pps clamp) behaves identically. The window gives
you:

- an **Attacks** tab with the full catalog grouped and colour-coded by category
  (generated from `ATTACK_CATALOG`, so it can never drift from the CLI), plus
  target/port/duration/pps fields and a Launch button;
- **Recon**, **Pentest** and **Payloads** tabs with forms for every command;
- a **Settings** tab (safe-mode, scope, interface, `max_pps`, …) that writes the
  same `config.toml`;
- live **stats**, an **active-attacks** table, a scrolling **log**, and an
  **Output** console with a `>>` box that accepts *any* CLI command verbatim;
- a **STOP ALL** button and a **SAFE MODE** toggle in the header.

Tk ships with CPython, so the GUI needs no extra packages beyond the CLI's
dependencies. On first run it shows the same authorization gate as a modal dialog.

### Command-line options

```
netwarrior [--safe] [--scope CIDR ...] [--iface NAME] [--yes] [--no-audit]
```

| Flag            | Effect                                                                   |
|-----------------|-------------------------------------------------------------------------|
| `--safe`        | Force `safe_mode`: no source spoofing, reserved/loopback targets blocked |
| `--scope CIDR`  | Refuse any target outside these networks (repeatable)                    |
| `--iface NAME`  | Interface for packet injection                                           |
| `--yes`         | Skip the first-run authorization prompt                                  |
| `--no-audit`    | Do not append to `<output_dir>/audit.log`                                |

Every attack launch, brute-force run and `sshexec` is appended to
`reports/audit.log` as one JSON line (operator, UTC timestamp, target, params —
never passwords) for engagement records.

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

  sshexec 10.0.0.1 root pw 'id'        Run a command over SSH
  payload revshell 10.0.0.1 4444       Generate a reverse-shell one-liner
  list                                 Active attacks
  stop                                 Stop all running attacks
  status                               Packet / traffic stats
  report save                          Write an HTML session report
  q                                    Quit
```

`pps` is capped at `max_pps` (default 10000). Config lives in
`~/.config/netwarrior/config.toml` (or `%APPDATA%\netwarrior\config.toml` on
Windows) — `safe_mode`, `scope` (a list of CIDRs), `spoof_source`, `interface`,
`output_dir`, `audit_log` and more. In `safe_mode` the engine also rewrites
forged source addresses back to your own, so floods stay attributable and
reflection vectors just bounce back to you.

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

## Defending against it

See **[DEFENSE.md](DEFENSE.md)** — for every attack category: what it looks like
on the wire, how to detect it (commands, log patterns, NetFlow signatures), and
how to mitigate it (kernel sysctls, `iptables`/switch config, reverse-proxy
timeouts, WIDS, egress filtering). [`detection/netwarrior.rules`](detection/netwarrior.rules)
is a Suricata ruleset tuned to this tool's exact payloads.

---

## Development

```bash
pip install -e ".[dev]"      # from github_repo/
ruff check .                  # lint
python -m pyflakes netwarrior.py
pytest -q                     # 137 tests, no packets leave the machine
```

`tests/` mocks scapy's senders and sniffer, so the suite runs unprivileged and
offline. CI (`.github/workflows/ci.yml`) runs ruff + pyflakes + pytest on Python
3.11–3.13. The `attack` command and the ATTACK menu are both generated from
`ATTACK_CATALOG` — add a vector there once and both pick it up.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## Similar Projects

NetWARRIOR is inspired by and builds on concepts from:
- [Scapy](https://scapy.net) — packet crafting
- [hping3](https://github.com/antirez/hping) — network testing
- [Metasploit](https://github.com/rapid7/metasploit-framework) — penetration testing
- [sqlmap](https://github.com/sqlmapproject/sqlmap) — SQL injection testing

---

## Author

NetWARRIOR is designed, built, and maintained by **[dev-joshua-py](https://github.com/dev-joshua-py)**.

This is an original project — architecture, attack catalog, safety-rail design,
terminal UI, and the desktop GUI are all my own work. If you fork it, learn from
it, or build on top of it, that's exactly what the MIT license below is for —
just keep the copyright notice intact and don't pass this off as your own
from-scratch work. See the **ATTRIBUTION** clause in [LICENSE](LICENSE) for
what that means in practice.

Found this useful? A star on the repo or a mention if you build on it is
always appreciated.

---

## License

MIT — see [LICENSE](LICENSE)

---

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md). Use responsibly. Only on systems you own or have
explicit written authorization to test.
