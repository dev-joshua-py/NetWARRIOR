"""Tests for the GUI front-end (``netwarrior_gui``).

These never touch the screen for the logic paths: ``AsyncCore`` is the same
engine the CLI drives, so we exercise it headlessly and assert the command
dispatch, safety rails and catalog wiring behave identically. A single optional
smoke test builds the real Tk widgets and is skipped where no display exists
(e.g. CI), so the suite stays green on headless Linux.
"""
import threading
import time

import pytest

nwg = pytest.importorskip("netwarrior_gui")
import netwarrior as nw  # noqa: E402


# ── pure helpers ──────────────────────────────────────────────────────────────
def test_render_output_strips_known_tags_and_classifies():
    assert nwg.render_output("[green]done[/]") == ("done", "ok")
    assert nwg.render_output("[red]nope[/]") == ("nope", "err")
    assert nwg.render_output("[yellow]hmm[/]") == ("hmm", "warn")
    assert nwg.render_output("") == ("", "plain")
    # bracketed *data* (a port list) must survive untouched
    clean, level = nwg.render_output("[green]Open ports on x: [80, 443][/]")
    assert clean == "Open ports on x: [80, 443]"
    assert level == "ok"


def test_catalog_wiring_matches_engine():
    # every menu entry the GUI shows resolves to a real spec
    for spec in nw.ATTACK_CATALOG:
        assert nw.ATTACK_BY_KEY[spec.key] is spec
    # redirect (own-command) keys never collide with catalog keys
    assert not (set(nw.ATTACK_REDIRECT) & set(nw.ATTACK_BY_KEY))
    # every catalog category has a colour the GUI can render
    for spec in nw.ATTACK_CATALOG:
        assert nwg._cat_color(spec.category)


# ── AsyncCore bridge (headless, no Tk) ────────────────────────────────────────
def _run(core, cmd, timeout=25):
    result = {}
    ev = threading.Event()

    def done(out):
        result["out"] = out
        ev.set()

    core.run_command(cmd, done)
    assert ev.wait(timeout), f"command timed out: {cmd}"
    return result["out"]


@pytest.fixture
def core(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "_config_path", lambda: tmp_path / "config.toml")
    c = nwg.AsyncCore(["--yes", "--safe"])
    c.config.output_dir = tmp_path / "reports"
    c.config.audit_log = False
    c.start()
    try:
        yield c
    finally:
        c.shutdown()


def test_core_starts_and_reports_status(core):
    assert core.ui is not None
    out = _run(core, "status")
    assert "Packets:" in out and "Active:" in out


def test_core_list_empty(core):
    assert "No active attacks" in _run(core, "list")


def test_core_payload_generation(core):
    out = _run(core, "payload revshell 10.0.0.1 4444 bash")
    assert "10.0.0.1" in out and "4444" in out


def test_safe_mode_blocks_loopback(core):
    out = _run(core, "attack syn 127.0.0.1 80 1 100")
    assert "loopback" in out.lower()
    # a blocked attack must not create a registry entry
    assert core.registry.active() == []


def test_attack_launch_and_stop(core):
    out = _run(core, "attack syn 93.184.216.34 80 1 50")
    assert "launched" in out.lower()
    # it registered as an attack
    assert any("syn" in a for a in {s.name for s in core.registry.snapshot()})
    stop_out = _run(core, "stop")
    assert "stop" in stop_out.lower()


def test_out_of_scope_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(nw, "_config_path", lambda: tmp_path / "config.toml")
    c = nwg.AsyncCore(["--yes", "--scope", "10.0.0.0/8"])
    c.config.output_dir = tmp_path / "reports"
    c.config.audit_log = False
    c.start()
    try:
        out = _run(c, "attack syn 8.8.8.8 80 1 50")
        assert "out of scope" in out.lower()
    finally:
        c.shutdown()


# ── optional Tk widget smoke test (skips without a display) ───────────────────
def test_gui_builds_and_runs_command(core):
    tk = pytest.importorskip("tkinter")
    try:
        root = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available for Tk")
    root.withdraw()
    try:
        app = nwg.NetWarriorGUI(root, core)
        app.submit("status")
        # let real time pass so the worker thread finishes and the after()-driven
        # pump/refresh callbacks actually fire
        for _ in range(100):
            root.update()
            time.sleep(0.03)
            if "Packets:" in app.console.get("1.0", "end"):
                break
        assert "Packets:" in app.console.get("1.0", "end")
        # header stat vars populated by the refresh tick
        assert app.stat_vars["ip"].get() not in ("", "—")
    finally:
        root.destroy()
