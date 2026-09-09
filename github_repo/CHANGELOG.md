# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

---

## [0.4.0] — 2026-09-09

### Added
- **Desktop GUI** (`netwarrior_gui.py`) — a Tkinter front-end for everyone who
  prefers a window to a terminal. It runs the real engine on a background
  asyncio event loop and drives the same command dispatcher the terminal UI
  uses, so the CLI and the GUI can never drift apart: identical attacks,
  identical safety rails (safe-mode, scope allowlist, authorization gate,
  audit log, pps clamp), identical output.
  - **Attacks** tab: the full catalog, grouped and colour-coded by category,
    generated straight from `ATTACK_CATALOG`
  - **Recon**, **Pentest**, **Payloads** tabs with a form for every command
  - **Settings** tab that reads/writes the same `config.toml`
  - Live stats header, an active-attacks table, a scrolling log, and an
    Output console with a `>>` box that accepts any CLI command verbatim
  - `STOP ALL` button and a `SAFE MODE` toggle in the header
  - `netwarrior-gui` console entry point (registered in `pyproject.toml`)
- 9 new tests (`tests/test_gui.py`) covering the async bridge, safety-rail
  enforcement, catalog wiring, output-markup rendering, and a real Tk widget
  smoke test that self-skips on headless CI.

### Fixed
- GUI: removed a dead flag (`nb_focus_console`) left over from an earlier
  layout that was set but never read.
- GUI: the log panel matched "already displayed" entries by value equality,
  which could silently skip a line if two log messages had identical text and
  timestamp. Now matched by object identity, which `LogBus` guarantees is
  stable and unique.

---

## [0.3.0]

### Added
- `DEFENSE.md` — detection and mitigation guidance for every attack category
  (wire signatures, log patterns, NetFlow signatures, sysctls, `iptables` /
  switch config, WIDS, egress filtering).
- `detection/netwarrior.rules` — a Suricata ruleset tuned to this tool's exact
  payloads.

### Fixed
- Recon, brute-force, and network-detection bug-fix sweep.

---

## [0.2.0]

### Added
- Packaging (`pyproject.toml`), a pytest suite (`tests/`), and CI
  (`.github/workflows/ci.yml`) running ruff + pyflakes + pytest on
  Python 3.11–3.13.
- Safety rails: `scope` CIDR allowlist, `safe_mode` source de-spoofing,
  append-only JSON-lines audit log, first-run authorization gate
  (`I HAVE AUTHORIZATION`).

### Changed
- Unified the attack catalog (`ATTACK_CATALOG`) so the `attack` command and
  the interactive ATTACK menu are generated from one source and can't drift
  apart; dropped dead stub code.

---

## [0.1.0]

### Added
- Async-first architecture: `asyncio` end to end, blocking calls (scapy
  sends, `sniff`, paramiko) bridged through `loop.run_in_executor`, packet
  sends dispatched in batches so the event loop and the `stop` command stay
  responsive even at high packet rates.
- Cross-platform `uvloop` install (Linux/macOS only; default loop on Windows).

### Fixed
- Packet-construction bugs and dead code from the initial release.

---

## [0.0.1] — Initial release

- First public release of NetWARRIOR: the adaptive Rich terminal UI, the full
  attack catalog (floods, reflection/amplification, application-layer,
  layer 2, IPv6 ND, name-resolution poisoning, wireless), recon (port scan,
  fingerprint, DNS, vuln scan), pentest (SSH/FTP/HTTP-basic brute force, web
  vulnerability probes), post-exploitation payload generators, and HTML
  session reporting.
