#!/usr/bin/env python3
"""Validate and package the PyCashFlow ChatGPT plugin (Agent Plugins format).

Usage:
    python plugins/chatgpt/build_package.py [--mcp-url URL] [--allow-placeholders]
                                            [--schema-dir DIR] [--offline]

Writes ``plugins/chatgpt/dist/pycashflow-chatgpt-<version>.zip`` (git-ignored)
and prints its SHA-256. The archive is reproducible: entries are sorted and
use fixed timestamps and permissions, so the same inputs give the same bytes.

Checks performed before packaging:
* plugin.json / mcp.json against the published Agent Plugins 1.0.0 JSON
  Schemas (downloaded unless --offline or --schema-dir is given)
* listing limits from OpenAI's submission docs (display/short name <= 30,
  long description <= 4000, developer name <= 80, HTTPS listing URLs)
* exactly one streamable-http MCP server over HTTPS ending in /mcp, without
  headers or credentials
* five positive and three negative review test cases
* referenced assets exist, are square, 48..4096 px, <= 5 MiB
* no ``REPLACE`` placeholders unless --allow-placeholders (for dry runs)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_URLS = {
    "plugin": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
    "mcp": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
}
FIXED_DATE = (1980, 1, 1, 0, 0, 0)
LIMITS = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
URL_FIELDS = ("websiteURL", "supportURL", "privacyPolicyURL", "termsOfServiceURL")


class PackageError(Exception):
    pass


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PackageError(f"{path.name}: {exc}") from exc


def load_schemas(schema_dir: Path | None, offline: bool) -> dict | None:
    if schema_dir:
        return {k: load_json(schema_dir / f"{k}.schema.json") for k in SCHEMA_URLS}
    if offline:
        return None
    schemas = {}
    for key, url in SCHEMA_URLS.items():
        with urllib.request.urlopen(url, timeout=20) as resp:  # noqa: S310 - fixed https URL
            schemas[key] = json.loads(resp.read().decode("utf-8"))
    return schemas


def validate_schemas(plugin: dict, mcp: dict, schemas: dict | None, problems: list[str]) -> None:
    if schemas is None:
        print("warning: schema validation skipped (--offline)", file=sys.stderr)
        return
    import jsonschema

    for name, doc in (("plugin", plugin), ("mcp", mcp)):
        validator = jsonschema.Draft202012Validator(schemas[name])
        for error in sorted(validator.iter_errors(doc), key=str):
            problems.append(f"{name}.json schema: {error.message} at {list(error.absolute_path)}")


def validate_listing(plugin: dict, problems: list[str]) -> tuple[list[str], dict]:
    openai = plugin.get("extensions", {}).get("com.openai", {})
    interface = openai.get("interface", {})
    for field, limit in LIMITS.items():
        value = interface.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"interface.{field} is required")
        elif len(value) > limit:
            problems.append(f"interface.{field} is {len(value)} chars (max {limit})")
    for field in URL_FIELDS:
        if not str(interface.get(field, "")).startswith("https://"):
            problems.append(f"interface.{field} must be an https URL")
    assets = [interface.get("composerIcon"), interface.get("logo")]
    skill = openai.get("onboardingSkill")
    review = openai.get("review", {})
    if len(review.get("positive_test_cases", [])) != 5:
        problems.append("review needs exactly 5 positive_test_cases")
    if len(review.get("negative_test_cases", [])) != 3:
        problems.append("review needs exactly 3 negative_test_cases")
    for case in review.get("positive_test_cases", []):
        for key in ("description", "prompt", "tools_triggered", "expected_behavior"):
            if not case.get(key):
                problems.append(f"positive test case missing {key}: {case.get('description')!r}")
    for case in review.get("negative_test_cases", []):
        for key in ("description", "prompt"):
            if not case.get(key):
                problems.append(f"negative test case missing {key}")
    files = [a for a in assets if a] + ([skill] if skill else [])
    return files, review


def validate_mcp(mcp: dict, problems: list[str]) -> None:
    servers = mcp.get("mcpServers", {})
    if len(servers) != 1:
        problems.append("mcp.json must declare exactly one server")
        return
    (server,) = servers.values()
    url = server.get("url", "")
    if server.get("type") != "streamable-http":
        problems.append("the MCP server must use type streamable-http")
    if not url.startswith("https://") or not url.rstrip("/").endswith("/mcp"):
        problems.append("the MCP server url must be https://<host>/mcp")
    if server.get("headers"):
        problems.append("mcp.json must not contain headers or credentials")
    if "clientSecret" in json.dumps(mcp):
        problems.append("mcp.json must not contain clientSecret")


def validate_assets(paths: list[str], problems: list[str]) -> None:
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow ships with the app (qrcode[pil])
        Image = None
    for rel in paths:
        if not rel.startswith("./"):
            problems.append(f"{rel}: manifest paths must start with ./")
            continue
        path = HERE / rel[2:]
        if not path.is_file():
            problems.append(f"{rel}: file not found")
            continue
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
            if path.stat().st_size > 5 * 1024 * 1024:
                problems.append(f"{rel}: larger than 5 MiB")
            if Image is not None:
                with Image.open(path) as image:
                    width, height = image.size
                if width != height or width < 48 or width > 4096:
                    problems.append(f"{rel}: must be square, 48-4096 px (got {width}x{height})")


def find_placeholders(*docs) -> list[str]:
    text = json.dumps(docs)
    return sorted({token for token in text.replace('"', " ").split() if "REPLACE" in token})


def build_zip(files: list[str], version: str) -> Path:
    dist = HERE / "dist"
    dist.mkdir(exist_ok=True)
    target = dist / f"pycashflow-chatgpt-{version}.zip"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for rel in sorted(set(files)):
            info = zipfile.ZipInfo(rel, date_time=FIXED_DATE)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (HERE / rel).read_bytes())
    return target


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mcp-url", help="Override the MCP server URL written into the package")
    parser.add_argument("--allow-placeholders", action="store_true", help="Permit REPLACE_* values (dry run)")
    parser.add_argument("--schema-dir", type=Path, help="Directory with plugin/mcp .schema.json files")
    parser.add_argument("--offline", action="store_true", help="Skip JSON Schema validation")
    args = parser.parse_args(argv)

    plugin = load_json(HERE / "plugin.json")
    mcp = load_json(HERE / "mcp.json")
    if args.mcp_url:
        (name,) = mcp["mcpServers"]
        mcp["mcpServers"][name]["url"] = args.mcp_url

    problems: list[str] = []
    validate_schemas(plugin, mcp, load_schemas(args.schema_dir, args.offline), problems)
    referenced, _review = validate_listing(plugin, problems)
    validate_mcp(mcp, problems)
    validate_assets(referenced, problems)
    placeholders = find_placeholders(plugin, mcp)
    if placeholders and not args.allow_placeholders:
        problems.append(f"unresolved placeholders: {', '.join(placeholders)}")
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    files = ["plugin.json", "mcp.json", *(p[2:] for p in referenced)]
    staged_mcp = HERE / "mcp.json"
    original = staged_mcp.read_text(encoding="utf-8")
    try:
        if args.mcp_url:
            staged_mcp.write_text(json.dumps(mcp, indent=2) + "\n", encoding="utf-8")
        target = build_zip(files, plugin.get("version", "0.0.0"))
    finally:
        staged_mcp.write_text(original, encoding="utf-8")
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    print(f"built {target.relative_to(HERE.parent.parent)}")
    print(f"sha256 {digest}")
    if placeholders:
        print(f"warning: package contains placeholders {placeholders}; do not submit it", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
