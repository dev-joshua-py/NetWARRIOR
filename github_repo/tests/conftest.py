"""Shared fixtures. No real packets leave the machine: scapy's senders and
sniffer are replaced with in-memory fakes for the whole test session."""
import pathlib
import sys
import warnings

import pytest

warnings.simplefilter("ignore")
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import netwarrior as nw  # noqa: E402


@pytest.fixture(autouse=True)
def fake_wire(monkeypatch):
    """Capture every packet instead of transmitting it."""
    box = {"sent": []}

    def _send(x, *a, **k):
        box["sent"].extend(x if isinstance(x, list) else [x])

    monkeypatch.setattr(nw, "send", _send)
    monkeypatch.setattr(nw, "sendp", _send)
    monkeypatch.setattr(nw, "sniff", lambda *a, **k: [])
    return box["sent"]


@pytest.fixture
def net():
    n = nw.NetworkContext.__new__(nw.NetworkContext)
    n.ip, n.mac = "10.9.9.9", "aa:bb:cc:dd:ee:ff"
    n.gateway, n.interface = "10.9.9.1", "eth0"
    n.netmask, n.dns_servers = "255.255.255.0", ["8.8.8.8"]
    return n


@pytest.fixture
def config(tmp_path):
    c = nw.Config.__new__(nw.Config)
    for name, (_, default) in nw.Config._FIELDS.items():
        setattr(c, name, list(default) if isinstance(default, list) else default)
    c._path = tmp_path / "config.toml"
    c.output_dir = tmp_path / "reports"
    return c


class Rig:
    """Engine + attacks bundle. Build inside a running loop via ``build_rig``."""
    def __init__(self, config, net):
        self.nw = nw
        self.config = config
        self.net = net
        self.registry = nw.AttackRegistry()
        self.log = nw.LogBus()
        self.engine = nw.AttackEngine(config, self.registry, self.log, net)
        self.attacks = nw.Attacks(self.engine, self.registry, self.log, net)
        self.recon = nw.Recon(config, net, self.log)
        self.pentest = nw.Pentest(config, self.log)
        self.audit = nw.AuditLog(config)


@pytest.fixture
def build_rig(config, net):
    """Return a factory so the Rig is constructed inside the test's event loop."""
    def _factory(**overrides):
        for k, v in overrides.items():
            setattr(config, k, v)
        return Rig(config, net)
    return _factory
