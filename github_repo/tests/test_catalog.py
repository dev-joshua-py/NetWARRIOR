import inspect

import pytest

import netwarrior as nw


def test_catalog_and_menu_share_one_source():
    keys = [s.key for s in nw.ATTACK_CATALOG]
    assert len(keys) == len(set(keys)), "duplicate attack keys"
    assert nw.ATTACK_BY_KEY.keys() == set(keys)
    # every category has a colour and a menu label
    ui = nw.UI
    for cat in {s.category for s in nw.ATTACK_CATALOG}:
        assert cat in nw.ATTACK_CATEGORY_COLOR
        assert cat in ui._CAT_LABEL
        assert cat in ui._CAT_ORDER


@pytest.mark.parametrize("spec", nw.ATTACK_CATALOG, ids=lambda s: s.key)
async def test_every_catalog_entry_builds(spec, build_rig):
    rig = build_rig()
    ui = nw.UI.__new__(nw.UI)
    ui.attacks, ui.config = rig.attacks, rig.config
    coro, needs = nw.UI._build_attack(ui, spec.key, "10.0.0.9", 80, 1, 100)
    assert inspect.iscoroutine(coro)
    assert needs == spec.needs_target
    coro.close()


async def test_redirect_and_unknown(build_rig):
    rig = build_rig()
    ui = nw.UI.__new__(nw.UI)
    ui.attacks, ui.config = rig.attacks, rig.config
    with pytest.raises(ValueError):
        nw.UI._build_attack(ui, "ssrf", "x", 80, 1, 100)
    with pytest.raises(KeyError):
        nw.UI._build_attack(ui, "does-not-exist", "x", 80, 1, 100)
