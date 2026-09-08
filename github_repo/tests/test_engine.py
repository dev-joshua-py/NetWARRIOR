import asyncio
import time


async def test_send_loop_is_non_blocking_and_counts(build_rig, fake_wire):
    rig = build_rig()
    t0 = time.monotonic()
    st = await rig.attacks.syn_flood("10.0.0.9", 80, duration=1, pps=1000)
    dt = time.monotonic() - t0
    assert 0.7 < dt < 2.5
    assert st.packets_sent > 0 and st.bytes_sent > 0
    assert not st.running
    assert len(fake_wire) == st.packets_sent


async def test_pps_is_clamped_to_max(build_rig):
    rig = build_rig(max_pps=2000)
    st = await rig.attacks.udp_flood("10.0.0.9", 53, duration=1, pps=10 ** 9)
    rate = st.packets_sent / max(st.duration, 0.01)
    assert rate < rig.config.max_pps * 4


async def test_stop_all_is_cooperative_and_fast(build_rig):
    rig = build_rig()
    task = asyncio.create_task(rig.attacks.icmp_flood("10.0.0.9", duration=30, pps=500))
    await asyncio.sleep(0.25)
    assert rig.registry.active()
    t0 = time.monotonic()
    rig.registry.stop_all()
    await task
    assert time.monotonic() - t0 < 1.0
    assert not rig.registry.active()


async def test_registry_keeps_history_and_dedups_names(build_rig):
    rig = build_rig()
    a, b, c = (rig.registry.create("x") for _ in range(3))
    assert [s.name for s in (a, b, c)] == ["x", "x#2", "x#3"]
    assert len(rig.registry.snapshot()) == 3


async def test_rerun_same_attack_actually_sends(build_rig, fake_wire):
    """Regression: a de-duplicated name must not point send_loop at a stale run."""
    rig = build_rig()
    await rig.attacks.syn_flood("10.0.0.9", 80, duration=0.4, pps=400)
    fake_wire.clear()
    st2 = await rig.attacks.syn_flood("10.0.0.9", 80, duration=0.4, pps=400)
    assert st2.packets_sent > 0 and len(fake_wire) > 0


async def test_generator_error_ends_attack_without_crash(build_rig):
    rig = build_rig()
    async def broken():
        st = rig.registry.create("broken")
        def gen():
            raise RuntimeError("bad field")
            yield  # pragma: no cover
        await rig.engine.send_loop(gen(), 5, 100, st)
        return st
    st = await broken()
    assert not st.running and st.errors >= 1
