import copy
import logging
import runpy
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
import yaml
from jsonschema import ValidationError, validate

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
# Keep test diagnostics out of the real service log.
_logs = tempfile.TemporaryDirectory()
with patch("platformdirs.user_log_dir", return_value=_logs.name):
    from thu_network_autoauth import (
        config,
        id_api,
        log,
        main,
        ocr,
        secret,
        session,
        usereg_api,
        webvpn,
    )

logging.getLogger("thu-network-autoauth").setLevel(logging.CRITICAL)


def tearDownModule():
    logging.shutdown()
    _logs.cleanup()


CONFIG = {
    "account": "test",
    "secret": {"service_name": "test"},
    "devices": ["192.0.2.1", "192.0.2.2"],
    "config": {
        "requests_timeout": 2,
        "monitor_interval": 60,
        "allow_webvpn": True,
        "allow_force_attempt": True,
        "force_attempt_interval": 600,
    },
}


def response(html="", status=200, url="https://usereg.tsinghua.edu.cn/login"):
    resp = requests.Response()
    resp.status_code = status
    resp._content = html.encode()
    resp._content_consumed = True
    resp.url = url
    return resp


def login_page(token="token", captcha="captcha"):
    # Deliberately vary attribute order and use single quotes.
    return response(f"""<input value='key' id='public'>
        <img src='{captcha}' id='loginform-verifycode-image'>
        <meta content='csrf' name='csrf-param'>
        <meta content='{token}' name='csrf-token'>""")


class ResilienceTests(unittest.TestCase):
    def tearDown(self):
        webvpn.reset_location_cache()
        session.reset_session()

    def test_get_retries_timeout_and_preserves_timeout(self):
        good = response()
        with (
            patch.object(
                requests.Session, "request", side_effect=[requests.Timeout(), good]
            ) as request,
            patch.object(session.time, "sleep") as sleep,
        ):
            result = session.SessionWithTimeout().get("https://example.test", timeout=7)
        self.assertIs(result, good)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.kwargs["timeout"], 7)
        sleep.assert_called_once_with(0.5)

    def test_post_is_never_replayed(self):
        with patch.object(
            requests.Session, "request", side_effect=requests.Timeout()
        ) as request:
            with self.assertRaises(requests.Timeout):
                session.SessionWithTimeout().post("https://example.test", timeout=2)
        self.assertEqual(request.call_count, 1)

    def test_requests_use_configured_timeout(self):
        with (
            patch.object(session, "load_config", return_value=CONFIG),
            patch.object(
                requests.Session, "request", return_value=response()
            ) as request,
        ):
            session.SessionWithTimeout().get("https://example.test")
        self.assertEqual(request.call_args.kwargs["timeout"], 2)

    def test_none_timeout_cannot_disable_service_request_deadline(self):
        with (
            patch.object(session, "load_config", return_value=CONFIG),
            patch.object(
                requests.Session, "request", return_value=response()
            ) as request,
        ):
            session.SessionWithTimeout().get("https://example.test", timeout=None)
        self.assertEqual(request.call_args.kwargs["timeout"], 2)

    def test_get_status_retries_are_bounded(self):
        with (
            patch.object(
                requests.Session,
                "request",
                side_effect=[response(status=503) for _ in range(3)],
            ) as request,
            patch.object(session.time, "sleep"),
        ):
            self.assertEqual(
                session.SessionWithTimeout()
                .get("https://example.test", timeout=2)
                .status_code,
                503,
            )
        self.assertEqual(request.call_count, 3)

    def test_get_timeout_retries_are_bounded(self):
        with (
            patch.object(
                requests.Session, "request", side_effect=requests.Timeout()
            ) as request,
            patch.object(session.time, "sleep"),
        ):
            with self.assertRaises(requests.Timeout):
                session.SessionWithTimeout().get("https://example.test", timeout=2)
        self.assertEqual(request.call_count, 3)

    def test_reset_discards_old_session(self):
        old = Mock()
        session.session = old
        session.reset_session()
        old.close.assert_called_once()
        self.assertIsNone(session.session)
        self.assertIsNot(session.get_session(), old)

    def test_failed_vpn_discovery_is_not_cached(self):
        client = Mock()
        client.get.side_effect = requests.Timeout()
        with (
            patch.object(webvpn, "load_config", return_value=CONFIG),
            patch.object(webvpn, "get_session", return_value=client),
            patch.object(
                webvpn,
                "get_webvpn_url",
                side_effect=[
                    RuntimeError("login failed"),
                    "https://vpn.test/https/key/",
                ],
            ) as vpn,
        ):
            with self.assertRaises(RuntimeError):
                webvpn.get_available_location(usereg_api.DEFAULT_LOCATION)
            self.assertFalse(webvpn.last_check)
            self.assertEqual(
                webvpn.get_available_location(usereg_api.DEFAULT_LOCATION),
                "https://vpn.test/https/key/",
            )
        self.assertEqual(vpn.call_count, 2)

    def test_http_error_triggers_vpn(self):
        client = Mock()
        client.get.return_value = response(status=503)
        with (
            patch.object(webvpn, "load_config", return_value=CONFIG),
            patch.object(webvpn, "get_session", return_value=client),
            patch.object(
                webvpn, "get_webvpn_url", return_value="https://vpn.test/https/key/"
            ) as vpn,
        ):
            webvpn.get_available_location(usereg_api.DEFAULT_LOCATION)
        vpn.assert_called_once_with("usereg.tsinghua.edu.cn")

    def test_disabling_vpn_ignores_cached_route(self):
        settings = copy.deepcopy(CONFIG)
        settings["config"]["allow_webvpn"] = False
        webvpn.last_check["usereg.tsinghua.edu.cn"] = 1e20
        webvpn.last_location["usereg.tsinghua.edu.cn"] = "https://vpn.test/"
        with patch.object(webvpn, "load_config", return_value=settings):
            self.assertEqual(
                webvpn.get_available_location(usereg_api.DEFAULT_LOCATION),
                usereg_api.DEFAULT_LOCATION,
            )

    def test_login_uses_one_page_and_refreshes_unreadable_captcha(self):
        client = Mock()
        client.get.side_effect = [
            login_page("old", "old.png"),
            login_page("new", "new.png"),
        ]
        client.post.return_value = response()
        cipher = Mock()
        cipher.encrypt.return_value = b"encrypted"
        with (
            patch.object(usereg_api, "load_config", return_value=CONFIG),
            patch.object(usereg_api, "get_session", return_value=client),
            patch.object(
                usereg_api,
                "get_available_location",
                return_value=usereg_api.DEFAULT_LOCATION,
            ),
            patch.object(usereg_api, "get_password", return_value="test"),
            patch.object(usereg_api, "check_login", side_effect=[False, True]),
            patch.object(usereg_api.RSA, "importKey"),
            patch.object(usereg_api.PKCS1_v1_5, "new", return_value=cipher),
            patch.object(
                usereg_api,
                "run_ocr",
                side_effect=[ocr.CaptchaRecognitionError(), "1234"],
            ) as recognize,
        ):
            usereg_api.login()
        self.assertEqual(client.get.call_count, 2)
        self.assertEqual(client.post.call_args.kwargs["data"]["csrf"], "new")
        self.assertEqual(
            recognize.call_args.args[0], usereg_api.DEFAULT_LOCATION + "new.png"
        )
        self.assertEqual(client.post.call_count, 1)

    def test_login_rejects_unrelated_http_200(self):
        client = Mock()
        client.get.return_value = response("maintenance")
        with patch.object(
            usereg_api,
            "get_available_location",
            return_value=usereg_api.DEFAULT_LOCATION,
        ):
            self.assertFalse(usereg_api.check_login(client))

    def test_captcha_refreshes_are_bounded(self):
        client = Mock()
        client.get.return_value = login_page()
        with (
            patch.object(usereg_api, "load_config", return_value=CONFIG),
            patch.object(usereg_api, "get_session", return_value=client),
            patch.object(
                usereg_api,
                "get_available_location",
                return_value=usereg_api.DEFAULT_LOCATION,
            ),
            patch.object(usereg_api, "check_login", return_value=False),
            patch.object(
                usereg_api, "run_ocr", side_effect=ocr.CaptchaRecognitionError()
            ),
        ):
            with self.assertRaises(ocr.CaptchaRecognitionError):
                usereg_api.login()
        self.assertEqual(client.get.call_count, 3)
        client.post.assert_not_called()

    def test_login_race_accepts_actual_home_page(self):
        client = Mock()
        client.get.return_value = response('<div class="query-online"></div>')
        with (
            patch.object(usereg_api, "load_config", return_value=CONFIG),
            patch.object(usereg_api, "get_session", return_value=client),
            patch.object(
                usereg_api,
                "get_available_location",
                return_value=usereg_api.DEFAULT_LOCATION,
            ),
            patch.object(usereg_api, "check_login", return_value=False),
        ):
            usereg_api.login()
        client.post.assert_not_called()

    def test_certification_requires_online_confirmation(self):
        client = Mock()
        client.get.return_value = login_page()
        client.post.return_value = response("login page")
        with (
            patch.object(usereg_api, "login"),
            patch.object(usereg_api, "get_session", return_value=client),
            patch.object(
                usereg_api,
                "get_available_location",
                return_value=usereg_api.DEFAULT_LOCATION,
            ),
            patch.object(usereg_api, "get_password", return_value="test"),
            patch.object(usereg_api, "get_online_ips", side_effect=[[], ["192.0.2.1"]]),
        ):
            self.assertFalse(usereg_api.send_certification("192.0.2.1"))
            self.assertTrue(usereg_api.send_certification("192.0.2.1"))

    def test_one_device_failure_does_not_skip_next(self):
        with (
            patch.object(main.usereg_api, "get_online_ips", return_value=[]),
            patch.object(
                main.usereg_api,
                "send_certification",
                side_effect=[requests.Timeout(), True],
            ) as certify,
        ):
            _, failed = main.monitor_cycle(CONFIG, None)
        self.assertTrue(failed)
        self.assertEqual(certify.call_count, 2)

    def test_online_devices_do_not_need_ping(self):
        with (
            patch.object(
                main.usereg_api, "get_online_ips", return_value=CONFIG["devices"]
            ),
            patch.object(main, "check_ip_available") as ping,
        ):
            main.monitor_cycle(CONFIG, None)
        ping.assert_not_called()

    def test_startup_error_retries_then_recovers(self):
        with (
            patch.object(
                main.Config,
                "load_config",
                side_effect=[RuntimeError("bad config"), CONFIG],
            ),
            patch.object(main.secret, "get_password"),
            patch.object(main.secret, "get_fingerprint"),
            patch.object(main, "monitor_cycle", return_value=(None, False)) as cycle,
            patch.object(main, "reset_session") as reset,
            patch.object(
                main.time, "sleep", side_effect=[None, KeyboardInterrupt()]
            ) as sleep,
        ):
            with self.assertRaises(KeyboardInterrupt):
                main.run_service()
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [60, 60])
        cycle.assert_called_once()
        self.assertGreaterEqual(reset.call_count, 2)

    def test_backoff_is_capped_and_resets_after_recovery(self):
        results = [RuntimeError("offline")] * 5 + [(None, False)]
        with (
            patch.object(main.Config, "load_config", return_value=CONFIG),
            patch.object(main.secret, "get_password"),
            patch.object(main.secret, "get_fingerprint"),
            patch.object(main, "monitor_cycle", side_effect=results),
            patch.object(main, "reset_session"),
            patch.object(
                main.time, "sleep", side_effect=[None] * 5 + [KeyboardInterrupt()]
            ) as sleep,
        ):
            with self.assertRaises(KeyboardInterrupt):
                main.run_service()
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [60, 120, 240, 300, 300, 60],
        )

    def test_nonpositive_intervals_are_rejected(self):
        for field in ("requests_timeout", "monitor_interval", "force_attempt_interval"):
            for invalid in (0, -1):
                settings = copy.deepcopy(CONFIG)
                settings["config"][field] = invalid
                with (
                    self.subTest(field=field, value=invalid),
                    self.assertRaises(ValidationError),
                ):
                    validate(settings, config.config_schema)

    def test_configuration_changes_apply_next_cycle(self):
        changed = copy.deepcopy(CONFIG)
        changed["config"]["monitor_interval"] = 90
        with (
            patch.object(main.Config, "load_config", side_effect=[CONFIG, changed]),
            patch.object(main.secret, "get_password"),
            patch.object(main.secret, "get_fingerprint"),
            patch.object(main, "monitor_cycle", return_value=(None, False)) as cycle,
            patch.object(main, "reset_session") as reset,
            patch.object(
                main.time, "sleep", side_effect=[None, KeyboardInterrupt()]
            ) as sleep,
        ):
            with self.assertRaises(KeyboardInterrupt):
                main.run_service()
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [60, 90])
        self.assertEqual(cycle.call_args.args[0], changed)
        self.assertEqual(reset.call_count, 2)

    def test_file_logging_failure_keeps_console(self):
        logger = Mock()
        with (
            patch("os.makedirs", side_effect=PermissionError("read only")),
            patch("logging.getLogger", return_value=logger),
        ):
            namespace = runpy.run_path(str(Path(main.__file__).with_name("log.py")))
        logger.addHandler.assert_called_once_with(namespace["console"])
        logger.warning.assert_called_once()


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "config.yaml"
        self.path_patch = patch.object(config, "config_path", str(self.path))
        self.path_patch.start()
        config._cached_config = None
        config._cached_signature = None

    def tearDown(self):
        self.path_patch.stop()
        config._cached_config = None
        config._cached_signature = None
        self.directory.cleanup()

    def write(self, settings):
        self.path.write_text(yaml.safe_dump(settings), encoding="utf-8")

    def test_legacy_password_alias_preserves_storage_name_without_rewriting(self):
        settings = copy.deepcopy(CONFIG)
        settings["password"] = settings.pop("secret")
        self.write(settings)
        original = self.path.read_bytes()
        loaded = config.load_config()
        self.assertEqual(loaded["secret"]["service_name"], "test")
        self.assertEqual(self.path.read_bytes(), original)

    def test_canonical_secret_takes_precedence(self):
        settings = copy.deepcopy(CONFIG)
        settings["password"] = {"service_name": "legacy"}
        self.write(settings)
        self.assertEqual(config.load_config()["secret"]["service_name"], "test")

    def test_cache_avoids_reparsing_and_returns_independent_values(self):
        self.write(CONFIG)
        with patch.object(config.yaml, "safe_load", wraps=yaml.safe_load) as parse:
            first = config.load_config()
            first["devices"].clear()
            second = config.load_config()
        self.assertEqual(parse.call_count, 1)
        self.assertEqual(second["devices"], CONFIG["devices"])

    def test_atomic_replacement_invalidates_cache(self):
        config.save_config(CONFIG)
        config.load_config()
        changed = copy.deepcopy(CONFIG)
        changed["account"] = "next"
        config.save_config(changed)
        self.assertEqual(config.load_config()["account"], "next")

    def test_failed_save_preserves_original_and_cleans_temporary_file(self):
        self.write(CONFIG)
        original = self.path.read_bytes()
        with patch.object(config.os, "replace", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                config.save_config(CONFIG)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(Path(self.directory.name).iterdir()), [self.path])

    def test_invalid_configuration_is_never_saved(self):
        self.write(CONFIG)
        original = self.path.read_bytes()
        with self.assertRaises(ValidationError):
            config.save_config({})
        self.assertEqual(self.path.read_bytes(), original)

    def test_empty_invalid_file_can_be_repaired(self):
        self.path.write_text("", encoding="utf-8")
        self.assertEqual(config.load_config(allow_unvalid=True), {})
        with self.assertRaises(ValueError):
            config.load_config()

    def test_invalid_edit_does_not_return_stale_cached_configuration(self):
        self.write(CONFIG)
        config.load_config()
        self.write({})
        with self.assertRaises(ValueError):
            config.load_config()

    def test_cancelled_wizard_leaves_file_unchanged(self):
        self.write(CONFIG)
        original = self.path.read_bytes()
        with patch.object(
            config.questionary, "text", return_value=Mock(ask=Mock(return_value=None))
        ):
            config.init_config()
        self.assertEqual(self.path.read_bytes(), original)

    def test_wizard_preserves_unknown_fields(self):
        settings = copy.deepcopy(CONFIG)
        settings["extension"] = {"enabled": True}
        settings["secret"]["custom"] = "keep"
        settings["config"]["custom"] = 42
        settings["config"]["force_attempt_interval"] = 900
        settings["password"] = {"service_name": "legacy", "custom": "legacy-keep"}
        self.write(settings)
        answers = iter(["new-account", "new-service", "192.0.2.3", "", "5", "90"])
        with (
            patch.object(
                config.questionary,
                "text",
                side_effect=lambda *a, **k: Mock(ask=Mock(return_value=next(answers))),
            ),
            patch.object(
                config.questionary,
                "confirm",
                return_value=Mock(ask=Mock(return_value=False)),
            ),
        ):
            config.init_config()
        saved = yaml.safe_load(self.path.read_text(encoding="utf-8"))
        self.assertEqual(saved["extension"], settings["extension"])
        self.assertEqual(saved["config"]["custom"], 42)
        self.assertEqual(saved["config"]["force_attempt_interval"], 900)
        self.assertEqual(
            saved["secret"], {"service_name": "new-service", "custom": "keep"}
        )
        self.assertEqual(
            saved["password"], {"service_name": "new-service", "custom": "legacy-keep"}
        )

    def test_ipv4_validation_does_not_raise_on_bad_input(self):
        for address in ("abc.def.ghi.jkl", "256.1.1.1", "1.2.3", "::1"):
            self.assertFalse(config.valid_ipv4(address))
        self.assertTrue(config.valid_ipv4("192.0.2.1"))
        self.assertTrue(config.valid_ipv4(""))

    def test_cancelled_or_empty_password_is_not_stored(self):
        for answer in (None, ""):
            with (
                patch.object(secret, "load_config", return_value=CONFIG),
                patch.object(
                    secret.questionary,
                    "password",
                    return_value=Mock(ask=Mock(return_value=answer)),
                ),
                patch.object(secret.keyring, "set_password") as store,
            ):
                secret.set_password()
            store.assert_not_called()

    def test_cancelled_or_empty_fingerprint_is_not_stored(self):
        for answer in (None, "", " "):
            with (
                patch.object(secret, "load_config", return_value=CONFIG),
                patch.object(
                    secret.questionary,
                    "text",
                    return_value=Mock(ask=Mock(return_value=answer)),
                ),
                patch.object(secret.keyring, "set_password") as store,
            ):
                secret.set_fingerprint()
            store.assert_not_called()


class AuthenticationAndLoggingTests(unittest.TestCase):
    def test_callback_secrets_are_redacted_in_message_and_traceback(self):
        try:
            raise requests.Timeout(
                "https://id.tsinghua.edu.cn/callback?code=secret-code&token=secret-token"
            )
        except requests.Timeout:
            record = logging.LogRecord(
                "test",
                logging.ERROR,
                "test.py",
                1,
                "Failed: password=secret-password",
                (),
                sys.exc_info(),
            )
        rendered = log.RedactingFormatter("%(message)s").format(record)
        for value in ("secret-code", "secret-token", "secret-password"):
            self.assertNotIn(value, rendered)
        self.assertIn("Timeout", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_console_hides_traceback_but_redacts_message(self):
        record = logging.LogRecord(
            "test",
            logging.ERROR,
            "test.py",
            1,
            "fingerPrint=secret-fingerprint",
            (),
            None,
        )
        self.assertNotIn(
            "secret-fingerprint", log.NoExceptionFormatter().format(record)
        )

    def test_webvpn_rejects_malformed_parameters_without_logging_values(self):
        client = Mock()
        for data in (
            [],
            {"wrdvpnKey": 123, "wrdvpnIV": "secret-iv"},
            {"wrdvpnKey": "secret-key", "wrdvpnIV": "secret-iv"},
        ):
            client.get.return_value.json.return_value = data
            with self.assertRaises(RuntimeError) as error:
                webvpn.get_wrdvpn_keys(client)
            self.assertNotIn("secret-key", str(error.exception))
            self.assertNotIn("secret-iv", str(error.exception))

    def test_webvpn_accepts_valid_aes_parameters(self):
        client = Mock()
        client.get.return_value.json.return_value = {
            "wrdvpnKey": "k" * 16,
            "wrdvpnIV": "i" * 16,
        }
        self.assertEqual(webvpn.get_wrdvpn_keys(client), (b"k" * 16, b"i" * 16))

    def test_identity_key_parsing_handles_attribute_order(self):
        self.assertEqual(
            id_api.get_public_key("<span class='key' id='sm2publicKey'> key </span>"),
            "key",
        )

    def test_missing_fingerprint_is_not_accepted_as_success(self):
        client = Mock()
        client.get.return_value.json.return_value = {
            "result": "success",
            "object": None,
        }
        with self.assertRaises(RuntimeError):
            id_api.get_finger_print_3(client)

    def test_expired_unauthorized_session_can_relogin(self):
        client = Mock()
        client.get.return_value = response(status=401)
        with patch.object(
            usereg_api,
            "get_available_location",
            return_value=usereg_api.DEFAULT_LOCATION,
        ):
            self.assertFalse(usereg_api.check_login(client))
        self.assertFalse(id_api.check_login(client))

    def test_authentication_rejects_external_redirect(self):
        client = Mock()
        client.get.return_value = response(url=id_api.LOGIN_PAGE)
        client.post.return_value = response(
            "window.location.replace('https://tsinghua.edu.cn.evil.test/')",
            url=id_api.CHECK_SINGLE_API,
        )
        with (
            patch.object(id_api, "login"),
            patch.object(id_api, "get_session", return_value=client),
            patch.object(id_api, "get_fingerprint", return_value="test"),
            patch.object(id_api, "get_finger_print_3", return_value="test"),
        ):
            with self.assertRaises(RuntimeError):
                id_api.auth_page("https://webvpn.tsinghua.edu.cn/")
        self.assertEqual(client.get.call_count, 1)


if __name__ == "__main__":
    unittest.main()
