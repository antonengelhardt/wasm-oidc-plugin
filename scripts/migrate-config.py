#!/usr/bin/env python3
"""Migrate wasm-oidc-plugin config from single-provider to multi-provider format.

Accepts either:
  - a bare plugin configuration YAML, or
  - a full Envoy / ConfigMap YAML with the plugin config in a `value: |` block

Usage:
  python3 scripts/migrate-config.py input.yaml > output.yaml
  python3 scripts/migrate-config.py input.yaml -o output.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from copy import deepcopy
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - runtime dependency check
    raise SystemExit(
        "PyYAML is required. Install it with: pip install pyyaml"
    ) from exc

PROVIDER_FIELDS = (
    "config_endpoint",
    "upstream_cluster",
    "authority",
    "redirect_uri",
    "client_id",
    "scope",
    "claims",
    "client_secret",
    "audience",
)

# Placeholder that parses as url::Url; replace with a real provider logo URL.
DEFAULT_PROVIDER_IMAGE = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E"


def _represent_str(dumper: yaml.Dumper, data: str) -> yaml.Node:
    """Dump multiline strings as literal block scalars (`|`) instead of quoted `\\n`."""
    if "\n" in data:
        # Block scalars should end with a newline for clean round-trips.
        if not data.endswith("\n"):
            data = f"{data}\n"
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


yaml.SafeDumper.add_representer(str, _represent_str)


def dump_yaml(data: Any) -> str:
    return yaml.safe_dump(
        data,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=1000,
    )


def _provider_name(config: dict[str, Any]) -> str:
    authority = config.get("authority")
    if isinstance(authority, str) and authority:
        return authority.split(".")[0]
    return "default"


def _normalize_claims(claims: Any) -> dict[str, Any]:
    """Convert legacy claims (JSON string or mapping) into a dict for serde_json::Map."""
    if claims is None:
        return {}

    if isinstance(claims, dict):
        return claims

    if isinstance(claims, str):
        stripped = claims.strip()
        if not stripped:
            return {}
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise SystemExit(
                f"Failed to parse legacy `claims` JSON string: {exc}"
            ) from exc
        if not isinstance(parsed, dict):
            raise SystemExit(
                "Legacy `claims` JSON must decode to an object/mapping."
            )
        return parsed

    raise SystemExit(
        f"Unsupported `claims` type {type(claims).__name__}; expected mapping or JSON string."
    )


def migrate_config(config: dict[str, Any]) -> dict[str, Any]:
    migrated = deepcopy(config)

    if "open_id_configs" in migrated:
        return migrated

    # Empty YAML keys with only comments load as null; the plugin expects lists.
    for list_field in ("exclude_hosts", "exclude_paths", "exclude_urls"):
        if migrated.get(list_field) is None:
            migrated[list_field] = []

    provider: dict[str, Any] = {"name": _provider_name(migrated)}
    for field in PROVIDER_FIELDS:
        if field in migrated:
            provider[field] = migrated.pop(field)

    if "claims" in provider:
        provider["claims"] = _normalize_claims(provider["claims"])
    else:
        provider["claims"] = {}

    if "image" not in provider or not provider["image"]:
        provider["image"] = DEFAULT_PROVIDER_IMAGE

    if "upstream_cluster" not in provider or not provider["upstream_cluster"]:
        # Match the plugin's runtime legacy conversion default.
        provider["upstream_cluster"] = "oidc"

    if "ticking_interval_in_ms" not in migrated:
        migrated["ticking_interval_in_ms"] = 500

    if "logout_path" not in migrated:
        migrated["logout_path"] = "/logout"

    migrated["open_id_configs"] = [provider]
    return migrated


def _looks_like_plugin_config(doc: dict[str, Any]) -> bool:
    return "open_id_configs" in doc or "config_endpoint" in doc


def _looks_like_plugin_yaml(text: str) -> bool:
    return "config_endpoint:" in text or "open_id_configs:" in text


def migrate_document(doc: Any) -> Any:
    """Migrate a bare plugin config or an Envoy/ConfigMap document containing one."""
    if isinstance(doc, dict):
        if _looks_like_plugin_config(doc):
            return migrate_config(doc)

        migrated: dict[str, Any] = {}
        for key, value in doc.items():
            if (
                key == "value"
                and isinstance(value, str)
                and _looks_like_plugin_yaml(value)
            ):
                plugin = yaml.safe_load(value)
                if not isinstance(plugin, dict):
                    raise SystemExit(
                        "Plugin `value` block must be a YAML mapping."
                    )
                # Keep trailing newline so Envoy literal blocks stay tidy.
                migrated[key] = dump_yaml(migrate_config(plugin))
            else:
                migrated[key] = migrate_document(value)
        return migrated

    if isinstance(doc, list):
        return [migrate_document(item) for item in doc]

    return doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input",
        help="Path to a legacy plugin config or full Envoy/ConfigMap YAML",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write migrated YAML to this file instead of stdout",
    )
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        document = yaml.safe_load(handle)

    if not isinstance(document, dict):
        raise SystemExit("Input YAML must be a mapping at the top level.")

    migrated = migrate_document(document)
    output = dump_yaml(migrated)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
