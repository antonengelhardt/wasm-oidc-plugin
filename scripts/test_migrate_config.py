#!/usr/bin/env python3
"""Tests for scripts/migrate-config.py."""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT_PATH = Path(__file__).with_name("migrate-config.py")
SPEC = importlib.util.spec_from_file_location("migrate_config", SCRIPT_PATH)
assert SPEC and SPEC.loader
migrate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migrate)

LEGACY_CONFIG = {
    "config_endpoint": "https://accounts.google.com/.well-known/openid-configuration",
    "reload_interval_in_h": 1,
    "exclude_hosts": [],
    "exclude_paths": [],
    "exclude_urls": [],
    "cookie_name": "oidcSession",
    "filter_plugin_cookies": True,
    "cookie_duration": 86400,
    "token_validation": True,
    "aes_key": "example-key",
    "authority": "accounts.google.com",
    "redirect_uri": "http://localhost:10000/oidc/callback",
    "client_id": "wasm-oidc-plugin",
    "scope": "openid profile email",
    "claims": '{"id_token":{"groups":null,"username":null}}',
    "client_secret": "redacted",
    "audience": "wasm-oidc-plugin",
}

ALREADY_MIGRATED_CONFIG = {
    "cookie_name": "oidcSession",
    "logout_path": "/custom-logout",
    "ticking_interval_in_ms": 250,
    "open_id_configs": [
        {
            "name": "Google",
            "image": "https://example.com/logo.png",
            "config_endpoint": "https://accounts.google.com/.well-known/openid-configuration",
            "upstream_cluster": "google",
            "authority": "accounts.google.com",
            "redirect_uri": "http://localhost:10000/oidc/callback",
            "client_id": "wasm-oidc-plugin",
            "scope": "openid profile email",
            "claims": {"id_token": {"groups": None, "username": None}},
            "client_secret": "redacted",
            "audience": "wasm-oidc-plugin",
        }
    ],
}


class ProviderNameTests(unittest.TestCase):
    def test_uses_first_authority_label(self) -> None:
        self.assertEqual(
            migrate._provider_name({"authority": "accounts.google.com"}),
            "accounts",
        )

    def test_falls_back_to_default_without_authority(self) -> None:
        self.assertEqual(migrate._provider_name({}), "default")


class NormalizeClaimsTests(unittest.TestCase):
    def test_parses_json_string_into_mapping(self) -> None:
        self.assertEqual(
            migrate._normalize_claims(
                '{"id_token":{"groups":null,"username":null}}'
            ),
            {"id_token": {"groups": None, "username": None}},
        )

    def test_preserves_mapping(self) -> None:
        claims = {"id_token": {"groups": None}}
        self.assertEqual(migrate._normalize_claims(claims), claims)

    def test_rejects_invalid_json_string(self) -> None:
        with self.assertRaises(SystemExit):
            migrate._normalize_claims("{not-json")


class MigrateConfigTests(unittest.TestCase):
    def test_migrates_legacy_single_provider_config(self) -> None:
        migrated = migrate.migrate_config(LEGACY_CONFIG)

        self.assertIn("open_id_configs", migrated)
        self.assertEqual(len(migrated["open_id_configs"]), 1)

        provider = migrated["open_id_configs"][0]
        self.assertEqual(provider["name"], "accounts")
        self.assertEqual(provider["image"], migrate.DEFAULT_PROVIDER_IMAGE)
        self.assertTrue(provider["image"].startswith(("http://", "https://", "data:")))
        self.assertEqual(
            provider["claims"],
            {"id_token": {"groups": None, "username": None}},
        )
        self.assertIsInstance(provider["claims"], dict)
        self.assertEqual(
            provider["config_endpoint"],
            LEGACY_CONFIG["config_endpoint"],
        )
        self.assertEqual(provider["authority"], LEGACY_CONFIG["authority"])
        self.assertEqual(provider["client_id"], LEGACY_CONFIG["client_id"])

        self.assertNotIn("config_endpoint", migrated)
        self.assertNotIn("authority", migrated)
        self.assertNotIn("client_id", migrated)

        self.assertEqual(migrated["cookie_name"], LEGACY_CONFIG["cookie_name"])
        self.assertEqual(migrated["logout_path"], "/logout")
        self.assertEqual(migrated["ticking_interval_in_ms"], 500)

    def test_preserves_existing_logout_and_tick_settings(self) -> None:
        config = {
            **LEGACY_CONFIG,
            "logout_path": "/signout",
            "ticking_interval_in_ms": 1000,
        }

        migrated = migrate.migrate_config(config)

        self.assertEqual(migrated["logout_path"], "/signout")
        self.assertEqual(migrated["ticking_interval_in_ms"], 1000)

    def test_leaves_already_migrated_config_unchanged(self) -> None:
        migrated = migrate.migrate_config(ALREADY_MIGRATED_CONFIG)

        self.assertEqual(migrated, ALREADY_MIGRATED_CONFIG)

    def test_does_not_mutate_input_config(self) -> None:
        original = {**LEGACY_CONFIG}
        migrate.migrate_config(original)
        self.assertEqual(original, LEGACY_CONFIG)

    def test_defaults_claims_to_empty_mapping_when_missing(self) -> None:
        config = {k: v for k, v in LEGACY_CONFIG.items() if k != "claims"}
        migrated = migrate.migrate_config(config)
        self.assertEqual(migrated["open_id_configs"][0]["claims"], {})


class MainCliTests(unittest.TestCase):
    def test_writes_migrated_yaml_to_stdout(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write(
                "authority: accounts.google.com\n"
                "config_endpoint: https://example.com/.well-known/openid-configuration\n"
                "upstream_cluster: google\n"
                'claims: \'{"id_token":{"groups":null}}\'\n'
            )
            input_path = handle.name

        stdout = io.StringIO()
        with patch.object(sys, "argv", ["migrate-config.py", input_path]):
            with patch.object(sys, "stdout", stdout):
                self.assertEqual(migrate.main(), 0)

        output = stdout.getvalue()
        self.assertIn("open_id_configs:", output)
        self.assertIn("name: accounts", output)
        self.assertIn("logout_path: /logout", output)
        self.assertIn("id_token:", output)
        self.assertIn("data:image/svg+xml", output)
        self.assertNotIn('claims: \'{"id_token"', output)

        Path(input_path).unlink()

    def test_writes_migrated_yaml_to_output_file(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("authority: auth.example.com\nclient_id: demo\n")
            input_path = handle.name

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "migrated.yaml"
            argv = [
                "migrate-config.py",
                input_path,
                "-o",
                str(output_path),
            ]
            with patch.object(sys, "argv", argv):
                self.assertEqual(migrate.main(), 0)

            content = output_path.read_text(encoding="utf-8")
            self.assertIn("open_id_configs:", content)
            self.assertIn("name: auth", content)
            self.assertIn("client_id: demo", content)
            self.assertIn("claims: {}", content)
            self.assertIn("data:image/svg+xml", content)

        Path(input_path).unlink()

    def test_rejects_non_mapping_yaml(self) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("- just\n- a\n- list\n")
            input_path = handle.name

        with patch.object(sys, "argv", ["migrate-config.py", input_path]):
            with self.assertRaises(SystemExit) as ctx:
                migrate.main()

        self.assertIn("mapping", str(ctx.exception))

        Path(input_path).unlink()


if __name__ == "__main__":
    unittest.main()
