import json

import netwarrior as nw


def test_scope_allowlist(config):
    config.scope = ["10.9.0.0/16"]
    assert config.check_target("10.9.5.5") is None
    assert "out of scope" in config.check_target("8.8.8.8")


def test_safe_mode_blocks_reserved(config):
    config.safe_mode = True
    assert "loopback" in config.check_target("127.0.0.1")
    assert "multicast" in config.check_target("224.0.0.1")
    assert "broadcast" in config.check_target("10.0.0.255")
    assert config.check_target("8.8.8.8") is None


def test_effective_spoof_gated_by_safe_mode(config):
    assert config.effective_spoof is True
    config.safe_mode = True
    assert config.effective_spoof is False


async def test_safe_mode_despoofs_packets(build_rig, fake_wire):
    rig = build_rig(safe_mode=True)
    await rig.attacks.syn_flood("10.0.0.9", 80, duration=0.4, pps=400)
    srcs = {p[nw.IP].src for p in fake_wire if p.haslayer(nw.IP)}
    assert srcs == {rig.net.ip}


async def test_reflection_source_is_neutralised_in_safe_mode(build_rig, fake_wire):
    rig = build_rig(safe_mode=True)
    await rig.attacks.dns_amp("10.0.0.9", duration=0.4, pps=300)
    assert all(p[nw.IP].src == rig.net.ip for p in fake_wire if p.haslayer(nw.IP))


async def test_spoofing_works_when_not_in_safe_mode(build_rig, fake_wire):
    rig = build_rig()
    await rig.attacks.syn_flood("10.0.0.9", 80, duration=0.4, pps=500)
    srcs = {p[nw.IP].src for p in fake_wire if p.haslayer(nw.IP)}
    assert len(srcs) > 5


def test_audit_log_writes_json_without_secrets(config):
    al = nw.AuditLog(config)
    al.record("attack", type="syn", target="10.9.5.5", pps=1000)
    al.record("sshexec", target="10.9.5.6", user="root", command="id")
    lines = (config.output_dir / "audit.log").read_text().strip().splitlines()
    assert len(lines) == 2
    e0 = json.loads(lines[0])
    assert e0["action"] == "attack" and e0["target"] == "10.9.5.5"
    assert "operator" in e0 and "ts" in e0
    assert "password" not in lines[1]


def test_audit_log_can_be_disabled(config):
    config.audit_log = False
    nw.AuditLog(config).record("attack", type="udp", target="x")
    assert not (config.output_dir / "audit.log").exists()


def test_cli_parsing():
    ns = nw._parse_args(["--safe", "--scope", "10.0.0.0/8",
                         "--scope", "192.168.0.0/16", "-y", "--iface", "wlan0"])
    assert ns.safe and ns.yes and ns.iface == "wlan0"
    assert ns.scope == ["10.0.0.0/8", "192.168.0.0/16"]


def test_authorization_gate(config):
    config.authorized = False
    config.require_ack = True
    assert nw._authorize(config, assume_yes=True) is True
    assert config.authorized is True
