"""Every packet-crafting attack must build valid packets and send them with
zero errors (catches wrong scapy field names, over-size payloads, etc.)."""
import pytest

PACKET_ATTACKS = [
    ("syn_flood",        lambda a: a.syn_flood("10.0.0.9", 80, 0.3, 500)),
    ("udp_flood",        lambda a: a.udp_flood("10.0.0.9", 80, 0.3, 500)),
    ("icmp_flood",       lambda a: a.icmp_flood("10.0.0.9", duration=0.3, pps=500)),
    ("tcp_ack_flood",    lambda a: a.tcp_ack_flood("10.0.0.9", 80, 0.3, 500)),
    ("tcp_rst_flood",    lambda a: a.tcp_rst_flood("10.0.0.9", 80, 0.3, 500)),
    ("tcp_xmas_flood",   lambda a: a.tcp_xmas_flood("10.0.0.9", 80, 0.3, 500)),
    ("tcp_null_flood",   lambda a: a.tcp_null_flood("10.0.0.9", 80, 0.3, 500)),
    ("tcp_fin_flood",    lambda a: a.tcp_fin_flood("10.0.0.9", 80, 0.3, 500)),
    ("tcp_zero_window",  lambda a: a.tcp_zero_window("10.0.0.9", 80, 0.3, 500)),
    ("mac_flood",        lambda a: a.mac_flood("10.0.0.9", duration=0.3, pps=500)),
    ("smurf",            lambda a: a.smurf("10.0.0.9", duration=0.3, pps=500)),
    ("land",             lambda a: a.land("10.0.0.9", 80, 0.3, 500)),
    ("sctp_init_flood",  lambda a: a.sctp_init_flood("10.0.0.9", 80, 0.3, 500)),
    ("teardrop",         lambda a: a.teardrop("10.0.0.9", duration=0.3, pps=200)),
    ("ping_of_death",    lambda a: a.ping_of_death("10.0.0.9", duration=0.3, pps=40)),
    ("gre_ip_spoof",     lambda a: a.gre_ip_spoof("10.0.0.9", duration=0.3, pps=400)),
    ("dns_amp",          lambda a: a.dns_amp("10.0.0.9", duration=0.3, pps=400)),
    ("ntp_amp",          lambda a: a.ntp_amp("10.0.0.9", duration=0.3, pps=400)),
    ("snmp_amp",         lambda a: a.snmp_amp("10.0.0.9", duration=0.3, pps=400)),
    ("memcached_amp",    lambda a: a.memcached_amp("10.0.0.9", duration=0.3, pps=400)),
    ("ssdp_amp",         lambda a: a.ssdp_amp("10.0.0.9", duration=0.3, pps=400)),
    ("chargen_amp",      lambda a: a.chargen_amp("10.0.0.9", duration=0.3, pps=400)),
    ("ssdp_discovery",   lambda a: a.ssdp_discovery(duration=0.3)),
    ("radius_pod",       lambda a: a.radius_pod(duration=0.3)),
    ("vlan_double_tag",  lambda a: a.vlan_double_tag("10.0.0.9", duration=0.3, pps=400)),
    ("l2_cdp",           lambda a: a.l2_protocol_flood("cdp", duration=0.3, pps=400)),
    ("l2_lldp",          lambda a: a.l2_protocol_flood("lldp", duration=0.3, pps=400)),
    ("l2_stp",           lambda a: a.l2_protocol_flood("stp", duration=0.3, pps=400)),
    ("ipv6_ra_flood",    lambda a: a.ipv6_ra_flood("fe80::1", duration=0.3, pps=400)),
    ("ipv6_na_flood",    lambda a: a.ipv6_na_flood("fe80::1", duration=0.3, pps=400)),
    ("ipv6_ns_flood",    lambda a: a.ipv6_ns_flood("fe80::1", duration=0.3, pps=400)),
    ("deauth",           lambda a: a.deauth("aa:bb:cc:00:11:22", duration=0.3, pps=100)),
    ("beacon_flood",     lambda a: a.beacon_flood(duration=0.3, pps=100)),
    ("llmnr_poison",     lambda a: a.llmnr_poison("10.0.0.9", duration=0.3)),
    ("nbns_poison",      lambda a: a.nbns_poison("10.0.0.9", duration=0.3)),
    ("mdns_poison",      lambda a: a.mdns_poison("10.0.0.9", duration=0.3)),
    ("dhcp_starvation",  lambda a: a.dhcp_starvation(duration=0.3, pps=50)),
]


@pytest.mark.parametrize("name,call", PACKET_ATTACKS, ids=[n for n, _ in PACKET_ATTACKS])
async def test_packet_attack_sends_cleanly(name, call, build_rig, fake_wire):
    rig = build_rig()
    st = await call(rig.attacks)
    assert not st.running
    assert st.packets_sent > 0, f"{name} sent nothing"
    assert st.errors == 0, f"{name} raised on {st.errors} packet(s)"
    assert len(fake_wire) >= st.packets_sent


async def test_replay_pcap_missing_file(build_rig):
    rig = build_rig()
    st = await rig.attacks.replay_pcap("/nope/does-not-exist.pcap", duration=1)
    assert not st.running and st.errors == 0
