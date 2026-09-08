from rich.console import Console

import netwarrior as nw


async def test_html_report_generates_and_escapes(build_rig):
    rig = build_rig()
    await rig.attacks.syn_flood("10.0.0.9", 80, duration=0.3, pps=300)
    rig.registry.snapshot()[0].add_finding({"note": "<script>x</script>"})
    rig.log.add("line one")
    html = nw.Report.generate_html(rig.registry, rig.log, rig.net)
    assert "<!doctype html>" in html.lower()
    assert "syn_10.0.0.9_80" in html
    assert "<script>x</script>" not in html  # escaped
    assert "&lt;script&gt;" in html
    path = nw.Report.save(rig.config, rig.registry, rig.log, rig.net)
    assert path and path.endswith(".html")


async def test_ui_renders_every_mode(build_rig, monkeypatch):
    ui = nw.UI(*_ui_args(build_rig()))
    for w in (140, 110, 90, 70):
        con = Console(file=open(__import__("os").devnull, "w"), width=w, height=60)
        for mode in ("menu", "attack", "recon", "pentest", "report", "command"):
            ui.mode = mode
            con.print(ui._render())


def _ui_args(rig):
    return (rig.config, rig.net, rig.registry, rig.log, rig.engine, rig.audit)
