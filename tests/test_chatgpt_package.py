"""Tests for the ChatGPT plugin package builder (plugins/chatgpt/build_package.py).

Each test works on a copy of the package in a temporary directory, so the
real manifest (and its review placeholders) is never modified. Schema
downloads are skipped with --offline; the other checks still run.
"""

import importlib.util
import json
import shutil
import zipfile
from pathlib import Path

import pytest

PACKAGE_DIR = Path(__file__).resolve().parent.parent / "plugins" / "chatgpt"


@pytest.fixture
def builder(tmp_path, monkeypatch):
    copy = tmp_path / "chatgpt"
    shutil.copytree(PACKAGE_DIR, copy, ignore=shutil.ignore_patterns("dist", "__pycache__"))
    spec = importlib.util.spec_from_file_location("build_package_under_test", copy / "build_package.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "HERE", copy)
    return module


def _edit_plugin(builder, change):
    path = builder.HERE / "plugin.json"
    plugin = json.loads(path.read_text(encoding="utf-8"))
    change(plugin)
    path.write_text(json.dumps(plugin, indent=2), encoding="utf-8")


def _fill_placeholders(builder):
    def change(plugin):
        plugin["extensions"]["com.openai"]["review"]["demo_recording_url"] = "https://example.com/demo.mp4"
    _edit_plugin(builder, change)


def test_placeholders_exit_3_and_build_nothing(builder, capsys):
    assert builder.main(["--offline"]) == builder.EXIT_PLACEHOLDERS == 3
    assert "unresolved placeholders" in capsys.readouterr().err
    assert not (builder.HERE / "dist").exists()


def test_allow_placeholders_builds_a_dry_run(builder):
    assert builder.main(["--offline", "--allow-placeholders"]) == 0
    assert list((builder.HERE / "dist").glob("*.zip"))


def test_complete_package_builds_reproducible_zip(builder, capsys):
    _fill_placeholders(builder)
    assert builder.main(["--offline"]) == 0
    version = json.loads((builder.HERE / "plugin.json").read_text())["version"]
    target = builder.HERE / "dist" / f"pycashflow-chatgpt-{version}.zip"
    first = target.read_bytes()
    out = capsys.readouterr().out
    assert out.splitlines()[-1].startswith("sha256 ")

    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
    assert names == sorted(names)
    assert {"plugin.json", "mcp.json", "assets/icon.png", "assets/logo.png",
            "skills/get-started/SKILL.md"} == set(names)
    assert not any(name.endswith(".py") or name.startswith("dist/") for name in names)

    assert builder.main(["--offline"]) == 0
    assert target.read_bytes() == first


def test_invalid_package_exits_1_even_with_placeholders(builder, capsys):
    def change(plugin):
        plugin["extensions"]["com.openai"]["interface"]["supportURL"] = "http://example.com/support"
    _edit_plugin(builder, change)
    assert builder.main(["--offline"]) == builder.EXIT_INVALID == 1
    err = capsys.readouterr().err
    assert "supportURL must be an https URL" in err
    assert not (builder.HERE / "dist").exists()


def test_listing_urls_point_at_public_pages():
    plugin = json.loads((PACKAGE_DIR / "plugin.json").read_text(encoding="utf-8"))
    interface = plugin["extensions"]["com.openai"]["interface"]
    assert interface["supportURL"] == "https://www.pycashflow.com/support"
    assert interface["privacyPolicyURL"] == "https://www.pycashflow.com/privacy"
    assert interface["termsOfServiceURL"] == "https://www.pycashflow.com/terms"
