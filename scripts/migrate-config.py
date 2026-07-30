#!/usr/bin/env python3
"""Migrate wasm-oidc-plugin config from single-provider to multi-provider format.

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

    if "ticking_interval_in_ms" not in migrated:
        migrated["ticking_interval_in_ms"] = 500

    if "logout_path" not in migrated:
        migrated["logout_path"] = "/logout"

    migrated["open_id_configs"] = [provider]
    return migrated


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Path to the legacy plugin configuration YAML")
    parser.add_argument(
        "-o",
        "--output",
        help="Write migrated YAML to this file instead of stdout",
    )
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as handle:
        config = yaml.safe_load(handle)

    if not isinstance(config, dict):
        raise SystemExit("Input YAML must be a mapping at the top level.")

    migrated = migrate_config(config)
    output = yaml.safe_dump(migrated, sort_keys=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(output)
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
