"""Issue #6556 — the config read path must report what actually runs.

Exercised rather than grepped: the checks this replaces stayed green under the
very inversions they existed to forbid.
"""

import importlib.util
import sys
import types
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).parents[2]


def _stub(name, **attrs):
    module = types.ModuleType(name)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


@pytest.fixture(scope="module")
def plugin_config_values():
    """Load the API module with just enough of pylon and flask to import."""
    spec = importlib.util.spec_from_file_location(
        "config_validation",
        PLUGIN_ROOT / "utils" / "config_validation.py",
    )
    config_validation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_validation)

    decorators = _stub("auth.decorators", check_api=lambda *a, **k: (lambda f: f))
    saved = dict(sys.modules)
    sys.modules.update({
        "flask": _stub("flask", request=_stub("request"), g=None),
        "pylon": _stub("pylon"),
        "pylon.core": _stub("pylon.core"),
        "pylon.core.tools": _stub("pylon.core.tools", log=_stub("log")),
        "tools": _stub(
            "tools",
            auth=_stub("auth", decorators=decorators),
            api_tools=_stub("api_tools", APIModeHandler=object, APIBase=object),
            register_openapi=lambda *a, **k: (lambda f: f),
        ),
    })
    sys.modules["pylon.core.tools"].log = _stub(
        "log", info=lambda *a, **k: None, warning=lambda *a, **k: None,
        error=lambda *a, **k: None, exception=lambda *a, **k: None,
    )
    try:
        package = _stub("cfgpkg")
        package.__path__ = []
        sys.modules["cfgpkg"] = package
        sys.modules["cfgpkg.plugin_config_schemas"] = _stub(
            "cfgpkg.plugin_config_schemas", SECTION_DEFINITIONS={},
        )
        sys.modules["cfgpkg.config_validation"] = config_validation

        source = (PLUGIN_ROOT / "api" / "v2" / "plugin_config_values.py").read_text()
        source = source.replace(
            "from .plugin_config_schemas import SECTION_DEFINITIONS",
            "from cfgpkg.plugin_config_schemas import SECTION_DEFINITIONS",
        ).replace(
            "from ...utils.config_validation import (",
            "from cfgpkg.config_validation import (",
        )
        module = types.ModuleType("plugin_config_values")
        exec(compile(source, "plugin_config_values.py", "exec"), module.__dict__)
        yield module
    finally:
        sys.modules.clear()
        sys.modules.update(saved)


CRON_PROP = {
    "type": "string", "format": "cron", "default": "* * * * *",
    "path": "scheduler.index_scheduling.cron", "section": "runtime",
}


def _runtimes(stored):
    return {
        "pylon-main": {
            "timestamp": 1 << 40,
            "runtime_info": [{
                "name": "elitea_core",
                "admin_schema": {"properties": {"index_scheduling_cron": CRON_PROP}},
                "config": {"scheduler": {"index_scheduling": {"cron": stored}}},
            }],
        },
    }


def test_a_usable_value_is_reported_as_stored(plugin_config_values):
    values, meta = plugin_config_values.collect_section_entries(
        _runtimes("*/15 * * * *"), "runtime", include_meta=True,
    )
    assert values["index_scheduling_cron"] == "*/15 * * * *"
    assert "value_invalid" not in meta["index_scheduling_cron"]


def test_an_unusable_value_is_reported_as_what_runs(plugin_config_values):
    """Showing the stored text would put Configuration and System Scheduling
    permanently at odds."""
    values, meta = plugin_config_values.collect_section_entries(
        _runtimes("9 *"), "runtime", include_meta=True,
    )
    assert values["index_scheduling_cron"] == "* * * * *"
    assert meta["index_scheduling_cron"]["value_invalid"] is True
    assert meta["index_scheduling_cron"]["stored_value"] == "9 *"


def test_a_usable_value_carries_no_invalid_badge(plugin_config_values):
    """Inverted, every section shows a permanent banner."""
    _, meta = plugin_config_values.collect_section_entries(
        _runtimes("* * * * *"), "runtime", include_meta=True,
    )
    assert meta["index_scheduling_cron"].get("value_invalid") is None


BOOL_PROP = {
    "type": "boolean", "strict_type": True, "default": True,
    "path": "scheduler.index_scheduling.enabled", "section": "runtime",
}


def _bool_runtimes(stored):
    return {
        "pylon-main": {
            "timestamp": 1 << 40,
            "runtime_info": [{
                "name": "elitea_core",
                "admin_schema": {"properties": {"index_scheduling_enabled": BOOL_PROP}},
                "config": {"scheduler": {"index_scheduling": {"enabled": stored}}},
                "config_data": "scheduler:\n  index_scheduling:\n    enabled: 0\n",
            }],
        },
    }


def _put(plugin_config_values, runtimes, values):
    """Drive AdminAPI.put and report whether it wrote anything."""
    import flask
    flask.request.get_json = lambda: {"values": values}

    fired = []
    api = plugin_config_values.AdminAPI()
    api.module = _stub(
        "module",
        remote_runtimes=runtimes,
        context=_stub("context", event_manager=_stub(
            "event_manager",
            fire_event=lambda name, payload: fired.append((name, payload)),
        )),
    )
    api.put("runtime")
    return fired


def test_turning_off_a_switch_stored_as_zero_actually_writes(plugin_config_values):
    """False == 0, so comparing against the stored value skips the write and
    answers "saved" while the schedule keeps firing."""
    fired = _put(
        plugin_config_values, _bool_runtimes(0), {"index_scheduling_enabled": False},
    )
    assert fired, "the save was skipped as unchanged"


def test_an_unchanged_usable_value_is_still_skipped(plugin_config_values):
    """The skip is what keeps a save from rewriting every untouched field."""
    fired = _put(
        plugin_config_values, _runtimes("*/15 * * * *"),
        {"index_scheduling_cron": "*/15 * * * *"},
    )
    assert not fired


def test_a_switch_stored_as_one_is_flagged_for_repair(plugin_config_values):
    """1 == True in Python, so comparing the stored value against the
    substituted one offers no repair for the single input that needs it: the
    screen agrees with what runs, and the literal stays until some unrelated
    save of the section happens to rewrite it."""
    _, meta = plugin_config_values.collect_section_entries(
        _bool_runtimes(1), "runtime", include_meta=True,
    )
    assert meta["index_scheduling_enabled"]["value_invalid"] is True
    assert meta["index_scheduling_enabled"]["stored_value"] == 1


def test_a_switch_stored_as_zero_is_still_flagged(plugin_config_values):
    _, meta = plugin_config_values.collect_section_entries(
        _bool_runtimes(0), "runtime", include_meta=True,
    )
    assert meta["index_scheduling_enabled"]["value_invalid"] is True


def test_nothing_stored_is_not_something_to_repair(plugin_config_values):
    """Screen and consumer both fall back to the default, so they already
    agree -- badging it asks the operator to save something with no effect."""
    _, meta = plugin_config_values.collect_section_entries(
        _runtimes(None), "runtime", include_meta=True,
    )
    assert meta["index_scheduling_cron"].get("value_invalid") is None


def test_saving_the_default_over_nothing_stored_is_a_no_op(plugin_config_values):
    """Treated as unusable, an absent value bypasses the unchanged-check and
    every save of the section rewrites every untouched field."""
    fired = _put(
        plugin_config_values, _runtimes(None),
        {"index_scheduling_cron": "* * * * *"},
    )
    assert not fired


CRON_PROP_NO_DEFAULT = {
    "type": "string", "format": "cron",
    "path": "scheduler.index_scheduling.cron", "section": "runtime",
}


def test_a_cron_field_without_a_default_still_reports_something_savable(
        plugin_config_values,
):
    """The default is what an unusable value is reported as; where the field
    declares none, reporting it hands the form a null its own validator
    rejects, so every save of the section fails on a field the operator never
    touched."""
    runtimes = _runtimes("9 *")
    schema = runtimes["pylon-main"]["runtime_info"][0]["admin_schema"]
    schema["properties"]["index_scheduling_cron"] = CRON_PROP_NO_DEFAULT
    values, meta = plugin_config_values.collect_section_entries(
        runtimes, "runtime", include_meta=True,
    )
    assert values["index_scheduling_cron"] == "9 *"
    assert meta["index_scheduling_cron"]["value_invalid"] is True
