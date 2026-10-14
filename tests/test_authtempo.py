import contextlib
import csv
import datetime
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rich.console import Console

import authtempo_core as authtempo


class QuietUI:
    def __init__(self):
        self.console = Console(file=io.StringIO(), force_terminal=False)

    def feed_line(self, *_args):
        pass

    def increment_conn_fails(self):
        pass

    def update_success(self, *_args):
        pass

    def update_admin(self, *_args):
        pass

    def update_password_change(self, *_args):
        pass

    def update_lockout(self, *_args):
        pass

    def update_error(self, *_args):
        pass

    def set_abort(self, *_args):
        pass

    def alert(self, *_args):
        pass


def fake_process(lines, return_code=0, running=False):
    proc = Mock()
    proc.stdout = iter(lines)
    proc.wait.return_value = return_code
    proc.poll.return_value = None if running else return_code
    return proc


class SprayWindowTests(unittest.TestCase):
    def test_custom_window_after_close_opens_next_day(self):
        window = authtempo.SprayWindow("09:00-17:00")
        now = datetime.datetime(2026, 10, 13, 18, 0)
        self.assertEqual(window.seconds_until_open(now), 15 * 60 * 60)

    def test_invalid_windows_are_rejected(self):
        for value in ("bad", "25:00-26:00", "09:00-09:00"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    authtempo.SprayWindow(value)


class EngineTests(unittest.TestCase):
    def test_kerbrute_success_ignores_timestamp_and_ansi_color(self):
        line = (
            "\x1b[32m2026/10/13 09:42:53 >  "
            "[+] VALID LOGIN: alice@LAB:Password1!\x1b[0m"
        )
        line_type, data = authtempo.classify_line(authtempo.Engine("kerbrute"), line)
        self.assertEqual(line_type, authtempo.LineType.SUCCESS)
        self.assertEqual(data, "alice@LAB:Password1!")

    def test_nonexistent_accounts_are_distinct_from_bad_passwords(self):
        nxc_type, nxc_user = authtempo.classify_line(
            authtempo.Engine("nxc", "smb"),
            "SMB 127.0.0.1 445 DC [-] LAB\\missing:Bad! STATUS_NO_SUCH_USER",
            expected_secret="Bad!",
        )
        kerb_type, kerb_user = authtempo.classify_line(
            authtempo.Engine("kerbrute"),
            "2026/10/13 > [!] missing@LAB:Bad! - User does not exist",
            expected_secret="Bad!",
        )
        self.assertEqual((nxc_type, nxc_user), (authtempo.LineType.NONEXISTENT, "missing"))
        self.assertEqual((kerb_type, kerb_user), (authtempo.LineType.NONEXISTENT, "missing@LAB"))

    def test_secret_text_cannot_forge_a_safety_or_admin_marker(self):
        lockout_words = "locked out data 775"
        failure = (
            "LDAP 127.0.0.1 389 DC [-] LAB\\alice:"
            f"{lockout_words} STATUS_LOGON_FAILURE"
        )
        line_type, user = authtempo.classify_line(
            authtempo.Engine("nxc", "ldap"),
            failure,
            expected_secret=lockout_words,
        )
        self.assertEqual((line_type, user), (authtempo.LineType.AUTHFAIL, "alice"))

        admin_words = "Secret (Pwn3d!)"
        success = f"SMB 127.0.0.1 445 DC [+] LAB\\alice:{admin_words}"
        line_type, data = authtempo.classify_line(
            authtempo.Engine("nxc", "smb"),
            success,
            expected_secret=admin_words,
        )
        self.assertEqual(line_type, authtempo.LineType.SUCCESS)
        self.assertEqual(data, f"alice:{admin_words}")

        revoked_words = "KDC_ERR_CLIENT_REVOKED"
        kerbrute_success = (
            "2026/10/13 > [+] VALID LOGIN: "
            f"alice@LAB:{revoked_words}"
        )
        line_type, data = authtempo.classify_line(
            authtempo.Engine("kerbrute"),
            kerbrute_success,
            expected_secret=revoked_words,
        )
        self.assertEqual(line_type, authtempo.LineType.SUCCESS)
        self.assertEqual(data, f"alice@LAB:{revoked_words}")

        expired_words = "STATUS_PASSWORD_EXPIRED"
        nxc_failure = (
            "SMB 127.0.0.1 445 DC [-] LAB\\alice:"
            f"{expired_words} STATUS_LOGON_FAILURE"
        )
        line_type, user = authtempo.classify_line(
            authtempo.Engine("nxc", "smb"),
            nxc_failure,
            expected_secret=expired_words,
        )
        self.assertEqual((line_type, user), (authtempo.LineType.AUTHFAIL, "alice"))

    def test_kerbrute_zero_exit_network_error_is_not_clean(self):
        network_line = (
            "\x1b[31m2026/10/13 09:42:53 >  "
            "[!] alice@LAB:Password1! - NETWORK ERROR - "
            "Can't talk to KDC. Aborting...\x1b[0m\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, kerbrute_binary="/fake/kerbrute",
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.stdout = iter([network_line])
            proc.wait.return_value = 0

            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                result = authtempo.spray_one_password(
                    authtempo.Engine("kerbrute"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "connection-errors")
            self.assertEqual(result.conn_fails, 1)

    def test_kerbrute_command_always_enables_safe_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, kerbrute_binary="/fake/kerbrute",
            )
            state = authtempo.State(tmp, cfg)
            proc = fake_process([
                "2026/10/13 09:42:53 >  [!] alice@LAB:Password1! - KDC_ERR_PREAUTH_FAILED\n",
                "2026/10/13 09:42:53 >  Done! Tested 1 logins (0 successes) in 0.010 seconds\n",
            ])

            with patch.object(authtempo.subprocess, "Popen", return_value=proc) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("kerbrute"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertTrue(result.clean_finish)
            command = popen.call_args.args[0]
            self.assertIn("--safe", command)
            self.assertIn("-v", command)
            self.assertEqual(command[command.index("--threads") + 1], "1")
            self.assertLess(command.index("--"), len(command) - 2)

    def test_kerbrute_quarantines_one_locked_user_and_continues(self):
        lockout_line = (
            "2026/10/13 09:42:53 >  [!] alice@LAB - USER LOCKED OUT\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice", "bob"], passwords=["Password1!"],
                log_dir=tmp, kerbrute_binary="/fake/kerbrute",
            )
            state = authtempo.State(tmp, cfg)
            locked_proc = fake_process([lockout_line], return_code=1)
            healthy_proc = fake_process([
                "2026/10/13 09:42:54 >  [!] bob@LAB:Password1! - KDC_ERR_PREAUTH_FAILED\n",
                "2026/10/13 09:42:54 >  Done! Tested 1 logins (0 successes) in 0.002 seconds\n",
            ])

            with patch.object(
                authtempo.subprocess,
                "Popen",
                side_effect=[locked_proc, healthy_proc],
            ) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("kerbrute"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertFalse(result.aborted)
            self.assertTrue(result.clean_finish)
            self.assertEqual(result.lockouts, {"alice"})
            self.assertEqual(state.locked_users, {"alice"})
            self.assertEqual(state.active_lockouts, {"alice"})
            self.assertEqual(popen.call_count, 2)
            locked_proc.terminate.assert_not_called()

    def test_nxc_ignores_retired_cumulative_threshold_for_isolated_lockout(self):
        lockout_line = (
            "SMB 127.0.0.1 445 DC [-] LAB\\alice:Password1! "
            "STATUS_ACCOUNT_LOCKED_OUT\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice", "bob"], passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc", lockout_threshold=1,
            )
            state = authtempo.State(tmp, cfg)
            locked_proc = fake_process([lockout_line])
            healthy_proc = fake_process([
                "SMB 127.0.0.1 445 DC [-] LAB\\bob:Password1! STATUS_LOGON_FAILURE\n"
            ])

            with patch.object(
                authtempo.subprocess,
                "Popen",
                side_effect=[locked_proc, healthy_proc],
            ) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertFalse(result.aborted)
            self.assertTrue(result.clean_finish)
            self.assertEqual(state.lockout_count, 1)
            self.assertEqual(popen.call_count, 2)
            locked_proc.terminate.assert_not_called()

    def test_nxc_allows_exactly_three_lockouts_in_one_spray(self):
        users = ["alice", "bob", "carol"]
        lockout_lines = [
            f"SMB 127.0.0.1 445 DC [-] LAB\\{user}:Password1! "
            "STATUS_ACCOUNT_LOCKED_OUT\n"
            for user in users
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=users, passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc", lockout_threshold=99,
            )
            state = authtempo.State(tmp, cfg)
            processes = [fake_process([line]) for line in lockout_lines]

            with patch.object(authtempo.subprocess, "Popen", side_effect=processes) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertEqual(cfg.lockout_burst, 4)
            self.assertFalse(result.aborted)
            self.assertTrue(result.clean_finish)
            self.assertEqual(result.lockout_count, 3)
            self.assertEqual(popen.call_count, 3)
            for proc in processes:
                proc.terminate.assert_not_called()

    def test_nxc_pauses_on_fifth_consecutive_lockout(self):
        users = ["alice", "bob", "carol", "dave", "erin", "frank"]
        lockout_lines = [
            f"SMB 127.0.0.1 445 DC [-] LAB\\{user}:Password1! "
            "STATUS_ACCOUNT_LOCKED_OUT\n"
            for user in users[:5]
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=users, passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc", lockout_threshold=99,
            )
            state = authtempo.State(tmp, cfg)
            processes = [fake_process([line]) for line in lockout_lines]

            with patch.object(authtempo.subprocess, "Popen", side_effect=processes) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "consecutive-lockouts")
            self.assertEqual(result.lockout_count, 5)
            self.assertEqual(state.lockout_count, 5)
            self.assertEqual(state.max_consecutive_lockouts, 5)
            self.assertEqual(popen.call_count, 5)

    def test_nonzero_engine_exit_triggers_failover_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc",
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.stdout = iter(["unclassified tool error\n"])
            proc.wait.return_value = 1

            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "exit-code-1")
            self.assertFalse(result.clean_finish)

    def test_connection_error_triggers_failover_even_on_zero_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc",
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.stdout = iter(["connection refused\n"])
            proc.wait.return_value = 0

            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "connection-errors")

    def test_nxc_zero_exit_without_auth_results_triggers_failover(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc",
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.stdout = iter([])
            proc.wait.return_value = 0

            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "no-auth-results")

    def test_smb_command_uses_the_requested_domain(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "EXAMPLE", "127.0.0.1",
                users=["alice"], passwords=["Password1!"],
                log_dir=tmp, nxc_binary="/fake/nxc",
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.stdout = iter([r"SMB 127.0.0.1 445 DC [-] EXAMPLE\alice:Password1! STATUS_LOGON_FAILURE\n"])
            proc.wait.return_value = 0

            with patch.object(authtempo.subprocess, "Popen", return_value=proc) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertFalse(result.aborted)
            command = popen.call_args.args[0]
            self.assertIn("-d", command)
            self.assertEqual(command[command.index("-d") + 1], "EXAMPLE")
            self.assertIn("--threads", command)
            self.assertEqual(command[command.index("--threads") + 1], "1")

    def test_smb_preflight_requires_smb_not_only_kerberos(self):
        cfg = authtempo.Config(
            "users", "passwords", "LAB", "127.0.0.1",
            tool="nxc", protocol="smb",
        )

        with patch.object(authtempo.socket, "create_connection", side_effect=OSError):
            ok, detail = authtempo.preflight(cfg, QuietUI())

        self.assertFalse(ok)
        self.assertIn("[445]", detail)

    def test_preflight_domain_check_uses_whole_tokens(self):
        cfg = authtempo.Config(
            "users",
            "passwords",
            "LAB",
            "127.0.0.1",
            tool="nxc",
            protocol="ldap",
            nxc_binary="/fake/nxc",
        )
        socket_handle = Mock()
        bad_probe = Mock(returncode=0)
        bad_probe.communicate.return_value = ("domain: LABEL\n", "")
        with patch.object(authtempo.socket, "create_connection", return_value=socket_handle), \
                patch.object(authtempo.subprocess, "Popen", return_value=bad_probe):
            ok, _detail = authtempo.preflight(cfg, QuietUI())
        self.assertFalse(ok)

        good_probe = Mock(returncode=0)
        good_probe.communicate.return_value = ("domain: LAB\n", "")
        with patch.object(authtempo.socket, "create_connection", return_value=socket_handle), \
                patch.object(authtempo.subprocess, "Popen", return_value=good_probe):
            ok, _detail = authtempo.preflight(cfg, QuietUI())
        self.assertTrue(ok)

    def test_rejected_cached_realm_falls_back_to_other_candidates(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "bad.example", "127.0.0.1",
                users=["alice"], passwords=["Password1!"], log_dir=tmp,
                kerbrute_binary="/fake/kerbrute",
                realm_candidates=["bad.example", "good.example"],
            )
            state = authtempo.State(tmp, cfg)
            state.working_realm = "bad.example"
            wrong = authtempo.RoundResult(aborted=True, abort_reason="wrong-realm")
            clean = authtempo.RoundResult(
                clean_finish=True,
                reconciled_complete=True,
                dispatches=1,
            )

            with patch.object(
                authtempo, "spray_one_password", side_effect=[wrong, clean]
            ) as spray:
                result = authtempo.spray_kerbrute_with_realm_retry(
                    authtempo.Engine("kerbrute"), cfg, "Password1!", QuietUI(), state,
                )

            self.assertIs(result, clean)
            self.assertEqual([call.args[-1] for call in spray.call_args_list],
                             ["bad.example", "good.example"])
            self.assertEqual(state.working_realm, "good.example")

    def test_user_enumeration_requires_a_reconciled_summary(self):
        cfg = authtempo.Config(
            "users",
            "passwords",
            "LAB",
            "127.0.0.1",
            users=["alice", "bob"],
            passwords=["Password1!"],
            kerbrute_binary="/fake/kerbrute",
        )
        proc = fake_process([
            "2026/10/13 > [+] VALID USERNAME: alice@LAB\n",
            "2026/10/13 > Done! Tested 1 usernames (1 valid) in 0.1 seconds\n",
        ])
        console = Console(file=io.StringIO(), force_terminal=False)
        with patch.object(authtempo.subprocess, "Popen", return_value=proc):
            with self.assertRaisesRegex(RuntimeError, "did not reconcile"):
                authtempo.enumerate_valid_users(cfg, QuietUI(), console)

    def test_user_enumeration_quarantines_revocation_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
                kerbrute_binary="/fake/kerbrute",
            )
            state = authtempo.State(tmp, cfg)
            proc = fake_process([
                "2026/10/13 > [+] VALID USERNAME WITH ERROR: alice@LAB "
                "(KDC_ERR_CLIENT_REVOKED)\n",
                "2026/10/13 > Done! Tested 1 usernames (1 valid) in 0.1 seconds\n",
            ])
            console = Console(file=io.StringIO(), force_terminal=False)

            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                valid_users = authtempo.enumerate_valid_users(
                    cfg,
                    QuietUI(),
                    console,
                    state,
                )

            self.assertEqual(valid_users, ["alice"])
            self.assertEqual(state.lockout_count, 1)
            self.assertEqual(state.locked_users, set())
            self.assertEqual(
                state.quarantine_reason("alice"),
                "ambiguous_lockout_signal",
            )
            self.assertEqual(
                state.lockout_signals[0]["stage"],
                "identity_enumeration",
            )


class LockoutPolicyTests(unittest.TestCase):
    def make_config(self, output, users, history=None, **overrides):
        values = {
            "users": users,
            "passwords": ["Bad!", "Good!"],
            "log_dir": str(output),
            "nxc_binary": "/fake/nxc",
            "lockout_burst": 99,
            "history_path": str(history) if history else None,
        }
        values.update(overrides)
        return authtempo.Config(
            "users",
            "passwords",
            "LAB",
            "127.0.0.1",
            **values,
        )

    def test_nonexistent_is_neutral_but_healthy_auth_result_resets_streak(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = ["alice", "bob", "missing", "carol"]
            state = authtempo.State(tmp, self.make_config(tmp, users))

            state.observe_pair_outcome("alice", "lockout")
            state.observe_pair_outcome("bob", "lockout")
            state.observe_pair_outcome("missing", "nonexistent")
            self.assertEqual(state.consecutive_lockout_count, 2)

            state.observe_pair_outcome("carol", "auth_failure")
            self.assertEqual(state.consecutive_lockout_count, 0)
            self.assertEqual(state.max_consecutive_lockouts, 2)

    def test_campaign_growth_requires_more_than_half_and_at_least_five_new_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "shared-history.json"
            users = [f"user{i:02d}" for i in range(30)]
            first = authtempo.State(
                str(root / "run-one"),
                self.make_config(root / "run-one", users, history),
            )
            for user in users[:15]:
                first.add_lockout(user, secret="Bad!")
            first.close()

            second = authtempo.State(
                str(root / "run-two"),
                self.make_config(root / "run-two", users, history),
            )
            self.assertEqual(second.campaign_baseline_count, 15)
            for user in users[15:22]:
                second.add_lockout(user, secret="Bad!")
                self.assertFalse(second.campaign_growth_stop)
            second.add_lockout(users[22], secret="Bad!")
            self.assertTrue(second.campaign_growth_stop)
            self.assertEqual(second.campaign_total_lockouts, 23)

    def test_scattered_lockouts_across_runs_only_warn(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            history = root / "shared-history.json"
            users = [f"user{i}" for i in range(10)]
            for index in range(4):
                output = root / f"run-{index}"
                state = authtempo.State(
                    str(output),
                    self.make_config(output, users, history),
                )
                state.add_lockout(users[index], secret="Bad!")
                self.assertFalse(state.campaign_growth_stop)
                state.close()

    def test_ldap_recheck_uses_computed_bit_and_preserves_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["reader", "alice"])
            state = authtempo.State(tmp, cfg)
            state.add_cred("reader", "Good!", engine="nxc:ldap")
            state.add_lockout("alice", secret="Bad!", engine="kerbrute")
            state.observe_pair_outcome("alice", "lockout")

            output = """
            sAMAccountName alice
            lockoutTime 134364191687395468
            msDS-User-Account-Control-Computed 0
            """
            completed = subprocess.CompletedProcess([], 0, stdout=output)
            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo.subprocess, "run", return_value=completed) as run:
                cleared, still_locked = authtempo.recheck_active_lockouts(
                    cfg, state, console
                )

            self.assertEqual((cleared, still_locked), (1, 0))
            self.assertEqual(state.active_lockouts, set())
            self.assertEqual(state.locked_users, {"alice"})
            self.assertNotIn("confirmed_lockout", state.quarantine_reasons("alice"))
            self.assertEqual(state.consecutive_lockout_count, 0)
            command = run.call_args.args[0]
            self.assertIn("--query", command)
            self.assertEqual(
                command[-1],
                "sAMAccountName msDS-User-Account-Control-Computed lockoutTime",
            )
            state.save()
            self.assertEqual(
                (Path(tmp) / "locked-out.txt").read_text(encoding="utf-8"),
                "alice\n",
            )
            self.assertEqual(
                (Path(tmp) / authtempo.ACTIVE_LOCKOUTS_FILE_NAME).read_text(
                    encoding="utf-8"
                ),
                "",
            )

    def test_ldap_recheck_retains_account_when_computed_lockout_bit_is_set(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["reader", "alice"])
            state = authtempo.State(tmp, cfg)
            state.add_cred("reader", "Good!", engine="nxc:ldap")
            state.add_lockout("alice", secret="Bad!")
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout="msDS-User-Account-Control-Computed 16\n",
            )
            with patch.object(authtempo.subprocess, "run", return_value=completed):
                result = authtempo.recheck_active_lockouts(
                    cfg,
                    state,
                    Console(file=io.StringIO(), force_terminal=False),
                )
            self.assertEqual(result, (0, 1))
            self.assertEqual(state.active_lockouts, {"alice"})
            self.assertIn("confirmed_lockout", state.quarantine_reasons("alice"))

    def test_ldap_recheck_uses_one_bind_for_multiple_quarantined_users(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["reader", "alice", "bob"])
            state = authtempo.State(tmp, cfg)
            state.add_cred("reader", "Good!", engine="nxc:ldap")
            state.add_lockout("alice", secret="Bad!")
            state.add_lockout("bob", secret="Bad!")
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout=(
                    "sAMAccountName alice\n"
                    "msDS-User-Account-Control-Computed 0\n"
                    "lockoutTime 123\n"
                    "sAMAccountName bob\n"
                    "msDS-User-Account-Control-Computed 16\n"
                    "lockoutTime 456\n"
                ),
            )
            with patch.object(
                authtempo.subprocess,
                "run",
                return_value=completed,
            ) as run:
                result = authtempo.recheck_active_lockouts(
                    cfg,
                    state,
                    Console(file=io.StringIO(), force_terminal=False),
                )
            self.assertEqual(result, (1, 1))
            self.assertEqual(state.active_lockouts, {"bob"})
            run.assert_called_once()
            query = run.call_args.args[0][run.call_args.args[0].index("--query") + 1]
            self.assertTrue(query.startswith("(|"))
            self.assertIn("sAMAccountName=alice", query)
            self.assertIn("sAMAccountName=bob", query)

    def test_ldap_recheck_without_known_credential_never_dispatches(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["alice"])
            state = authtempo.State(tmp, cfg)
            state.add_lockout("alice", secret="Bad!")

            with patch.object(authtempo.subprocess, "run") as run:
                result = authtempo.recheck_active_lockouts(
                    cfg,
                    state,
                    Console(file=io.StringIO(), force_terminal=False),
                )

            self.assertEqual(result, (0, 1))
            self.assertEqual(state.active_lockouts, {"alice"})
            run.assert_not_called()

    def test_failed_ldap_recheck_cannot_clear_quarantine_from_partial_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["reader", "alice"])
            state = authtempo.State(tmp, cfg)
            state.add_cred("reader", "Good!", engine="nxc:ldap")
            state.add_lockout("alice", secret="Bad!")
            completed = subprocess.CompletedProcess(
                [],
                1,
                stdout=(
                    "sAMAccountName alice\n"
                    "msDS-User-Account-Control-Computed 0\n"
                ),
            )

            with patch.object(authtempo.subprocess, "run", return_value=completed):
                result = authtempo.recheck_active_lockouts(
                    cfg,
                    state,
                    Console(file=io.StringIO(), force_terminal=False),
                )

            self.assertEqual(result, (0, 1))
            self.assertEqual(state.active_lockouts, {"alice"})
            self.assertIn("confirmed_lockout", state.quarantine_reasons("alice"))

    def test_campaign_history_failure_saves_local_quarantine_before_pausing(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, ["alice"])
            state = authtempo.State(tmp, cfg)
            with patch.object(
                state,
                "_register_campaign_lockout",
                side_effect=OSError("disk unavailable"),
            ):
                with self.assertRaises(authtempo.CampaignHistoryUnavailable):
                    state.add_lockout("alice", secret="Bad!", persist=False)

            saved = json.loads(
                (Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(set(saved["active_lockouts"]), {"alice"})
            self.assertEqual(set(saved["locked_users"]), {"alice"})
            self.assertEqual(len(saved["lockout_signals"]), 1)

    def test_resume_preserves_stricter_legacy_lockout_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            legacy_cfg = self.make_config(tmp, ["alice"], lockout_burst=3)
            first = authtempo.State(tmp, legacy_cfg)
            first.close()

            resumed_cfg = self.make_config(
                tmp,
                ["alice"],
                lockout_burst=4,
                resume=True,
            )
            resumed = authtempo.State(tmp, resumed_cfg)
            self.assertEqual(resumed.cfg.lockout_burst, 3)

    def test_default_display_filters_banner_noise_and_shows_exact_lockout_pair(self):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        ui = authtempo.RichUI(console, live_ui=False, show_raw=False)
        ui.start_spray(authtempo.Engine("kerbrute"), "Bad!", 1)
        ui.feed_line("kerbrute giant ASCII banner")
        ui.update_lockout("alice", "Bad!", "kerbrute", 1)

        rendered = output.getvalue()
        self.assertNotIn("ASCII banner", rendered)
        self.assertIn("alice:Bad!", rendered)
        self.assertIn("consecutive 1", rendered)

    def test_streaming_lockout_pair_preserves_rich_markup_characters(self):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        ui = authtempo.RichUI(console, live_ui=False, show_raw=False)
        ui.start_spray(authtempo.Engine("kerbrute"), "Bad[red]!", 1)
        ui.update_lockout("user[blue]", "Bad[red]!", "kerbrute", 1)

        rendered = output.getvalue()
        self.assertIn("user[blue]:Bad[red]!", rendered)


class StateAndRunTests(unittest.TestCase):
    def test_product_brand_and_artifact_names_are_authtempo(self):
        self.assertEqual(authtempo.PRODUCT_NAME, "AuthTempo")
        self.assertEqual(authtempo.PRODUCT_SLUG, "authtempo")
        self.assertIn("enforced safety limits", authtempo.PRODUCT_TAGLINE)
        self.assertEqual(authtempo.STATE_FILE_NAME, "authtempo.state.json")
        self.assertEqual(authtempo.AUDIT_LOG_NAME, "authtempo.log")
        self.assertEqual(
            authtempo.TIMELINE_HTML_NAME,
            "authtempo-timeline.html",
        )

    def test_identity_enumeration_signal_stops_before_password_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
                filter_disabled=True,
                no_preflight=True,
            )

            def enumerate_with_signal(_cfg, _ui, _console, state):
                state.add_lockout(
                    "alice",
                    certainty="ambiguous",
                    engine="kerbrute",
                    protocol="userenum",
                    stage="identity_enumeration",
                )
                return ["alice"]

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(
                authtempo,
                "enumerate_valid_users",
                side_effect=enumerate_with_signal,
            ), patch.object(authtempo, "setup_signal_handler"), patch.object(
                authtempo,
                "spray_one_password",
            ) as spray:
                authtempo.run(cfg, console)

            spray.assert_not_called()
            self.assertIn("no password attempts", console.file.getvalue())

    def test_run_locks_output_directory_before_preflight_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
            )
            observed = {"locked": False}

            def inspect_lock(_cfg, _ui, _state):
                with self.assertRaisesRegex(RuntimeError, "already using"):
                    authtempo.State(tmp, cfg)
                observed["locked"] = True
                return False, "intentional test failure"

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "preflight", side_effect=inspect_lock), \
                    patch.object(authtempo, "setup_signal_handler"):
                authtempo.run(cfg, console)

            self.assertTrue(observed["locked"])

    def test_sigint_terminates_active_spray_before_saving(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["First!"], log_dir=tmp,
            )
            state = authtempo.State(tmp, cfg)
            proc = Mock()
            proc.poll.return_value = None
            proc.wait.return_value = 0
            state.active_process = proc
            console = Console(file=io.StringIO(), force_terminal=False)

            with patch.object(authtempo.signal, "signal") as register:
                authtempo.setup_signal_handler(state, console)
            handler = register.call_args.args[1]

            with self.assertRaises(SystemExit) as stopped:
                handler(None, None)

            self.assertEqual(stopped.exception.code, 130)
            proc.terminate.assert_called_once()

    def test_attempts_and_credentials_are_counted_as_unique_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice", "bob"], passwords=["First!", "Second!"],
                log_dir=tmp,
            )
            state = authtempo.State(tmp, cfg)

            state.mark_attempted("First!", "alice")
            state.mark_attempted("First!", "alice")
            state.mark_attempted_batch("First!", ["alice", "bob"])
            state.add_cred("alice", "First!")
            state.add_cred("alice", "First!")
            state.add_cred("alice", "Second!")

            self.assertEqual(state.total_attempts, 2)
            self.assertEqual(state.attempts_by_password["First!"], 2)
            self.assertEqual(state.credential_count, 2)
            self.assertEqual(
                (Path(tmp) / "creds.txt").read_text(encoding="utf-8").splitlines(),
                ["alice:First!", "alice:Second!"],
            )

    def test_metrics_separate_dispatches_from_final_pair_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["First!"],
                log_dir=tmp,
                retry_indeterminate=True,
            )
            state = authtempo.State(tmp, cfg)
            engine = authtempo.Engine("nxc", "ldap")
            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "indeterminate")
            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "success")
            state.add_cred("alice", "First!", engine="nxc:ldap")

            compact = state.get_compact_stats()
            self.assertIn("Attempts sent: 2", compact)
            self.assertIn("Unique pairs: 1", compact)
            self.assertIn("Valid: 1", compact)
            self.assertIn("Uncertain: 0", compact)
            self.assertEqual(state.pair_success_rate(), 100.0)

    def test_dry_run_metrics_label_simulated_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["First!"],
                log_dir=tmp,
                dry_run=True,
            )
            state = authtempo.State(tmp, cfg)
            state.mark_attempted("First!", "alice", status="dry_run")

            compact = state.get_compact_stats()
            self.assertIn("Attempts sent: 1", compact)
            self.assertIn("Unique pairs: 1", compact)
            self.assertIn("Simulated: 1", compact)
            self.assertIsNone(state.pair_success_rate())

    def test_completed_resume_does_not_duplicate_completion_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            common = dict(
                users=["alice"],
                passwords=["First!"],
                log_dir=tmp,
                dry_run=True,
                no_preflight=True,
                time_between_rounds=0,
                realm_retry=False,
            )
            first = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1", **common
            )
            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "setup_signal_handler"):
                self.assertTrue(authtempo.run(first, console))

            resumed = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                resume=True,
                **common,
            )
            with patch.object(authtempo, "setup_signal_handler"):
                self.assertTrue(authtempo.run(resumed, console))

            data = json.loads(
                (Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(
                [event["type"] for event in data["timeline_events"]].count(
                    "complete"
                ),
                1,
            )

    def test_resume_rejects_state_for_a_different_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = authtempo.Config(
                "users", "passwords", "LAB", "10.0.0.1",
                users=["alice"], passwords=["First!"], log_dir=tmp,
            )
            authtempo.State(tmp, first)
            second = authtempo.Config(
                "users", "passwords", "LAB", "10.0.0.2",
                users=["alice"], passwords=["First!"], log_dir=tmp,
                resume=True,
            )

            with self.assertRaisesRegex(RuntimeError, "different target"):
                authtempo.State(tmp, second)

    def test_live_summary_keeps_credentials_across_failover_and_rounds(self):
        output = io.StringIO()
        console = Console(
            file=output,
            force_terminal=True,
            width=80,
            height=14,
            color_system=None,
        )
        ui = authtempo.RichUI(console, max_feed_lines=50, live_ui=False)

        ui.start_spray(authtempo.Engine("kerbrute"), "First!", 1)
        ui.update_success("alice", "First!")
        ui.end_spray()
        ui.start_spray(authtempo.Engine("nxc", "ldap"), "First!", 1)

        with console.capture() as capture:
            console.print(ui._build_summary())
        first_round = capture.get()
        self.assertIn("alice:First!", first_round)
        self.assertIn("1 / 1", first_round)
        self.assertLessEqual(ui._summary_height(), 7)

        ui.end_spray()
        ui.start_spray(authtempo.Engine("nxc", "ldap"), "Second!", 2)
        with console.capture() as capture:
            console.print(ui._build_summary())
        next_round = capture.get()
        self.assertIn("alice:First!", next_round)
        self.assertIn("0 / 1", next_round)

    def test_password_change_credential_is_highlighted_separately(self):
        output = io.StringIO()
        console = Console(file=output, force_terminal=False, color_system=None)
        ui = authtempo.RichUI(console, live_ui=False)
        command = (
            "impacket-changepasswd -protocol smb-samr LAB/alice@127.0.0.1"
        )

        ui.start_spray(authtempo.Engine("nxc", "smb"), "First!", 1)
        ui.update_password_change(
            "alice",
            "First!",
            "password_expired",
            command,
        )

        rendered_stream = output.getvalue()
        self.assertIn("VALID CREDENTIAL", rendered_stream)
        self.assertIn("PASSWORD EXPIRED", rendered_stream)
        self.assertIn(command, rendered_stream)
        with console.capture() as capture:
            console.print(ui._build_summary())
        self.assertIn("CHANGE REQUIRED", capture.get())

    def test_tmux_uses_streaming_mode_unless_live_is_forced(self):
        console = Console(
            file=io.StringIO(),
            force_terminal=True,
            width=80,
            height=24,
            color_system=None,
        )
        with patch.dict(os.environ, {"TMUX": "/tmp/tmux/default,1,0", "TERM": "screen-256color"}):
            automatic = authtempo.RichUI(console, live_ui=True)
            forced = authtempo.RichUI(console, live_ui=True, force_live=True)

        self.assertFalse(automatic.live_enabled)
        self.assertTrue(automatic._stream_fallback)
        self.assertTrue(forced.live_enabled)

    def test_live_summary_separates_signal_events_from_affected_identities(self):
        console = Console(
            file=io.StringIO(),
            force_terminal=True,
            width=100,
            height=20,
            color_system=None,
        )
        ui = authtempo.RichUI(console, live_ui=False)
        ui.load_totals([], set(), {"alice"}, unknown_lockouts=1, signal_events=3)
        ui.start_spray(authtempo.Engine("nxc", "ldap"), "First!", 1)
        ui.update_lockout("bob")
        with console.capture() as capture:
            console.print(ui._build_summary())
        rendered = capture.get()
        self.assertIn("Safety / affected", rendered)
        self.assertIn("1 · 4 / 1 · 2", rendered)

    def test_live_dashboard_is_content_sized_and_caps_recent_output(self):
        console = Console(
            file=io.StringIO(),
            force_terminal=True,
            width=100,
            height=40,
            color_system=None,
        )
        ui = authtempo.RichUI(
            console,
            max_feed_lines=10,
            live_ui=False,
            show_raw=True,
        )
        ui.start_spray(authtempo.Engine("nxc", "smb"), "First!", 1)
        ui.raw_feed = [f"raw line {index}" for index in range(15)]

        with console.capture() as capture:
            console.print(ui._render_spray())
        rendered = capture.get()

        self.assertIn("raw line 14", rendered)
        self.assertIn("raw line 5", rendered)
        self.assertNotIn("raw line 4", rendered)
        self.assertLess(len(rendered.splitlines()), console.height)

    def test_new_demotion_keeps_its_full_configured_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"], log_dir=tmp,
                engine_cooldown_rounds=3, engine_transient_threshold=1,
            )
            state = authtempo.State(tmp, cfg)
            active_at_round_start = set()

            state.register_engine_failure("kerbrute", "timeout")
            state.tick_cooldowns(active_at_round_start)

            self.assertEqual(state.engine_health["kerbrute"]["cooldown_remaining"], 3)

    def test_fresh_run_clears_stale_human_readable_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "creds.txt").write_text("old:credential\n", encoding="utf-8")
            (root / authtempo.PASSWORD_CHANGES_FILE_NAME).write_text(
                "old command\n",
                encoding="utf-8",
            )
            (root / "locked-out.txt").write_text("old-user\n", encoding="utf-8")
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                users=["alice"], passwords=["Password1!"], log_dir=tmp,
                start_fresh=True,
            )

            authtempo.State(tmp, cfg)

            self.assertEqual((root / "creds.txt").read_text(encoding="utf-8"), "")
            self.assertEqual(
                (root / authtempo.PASSWORD_CHANGES_FILE_NAME).read_text(
                    encoding="utf-8"
                ),
                "",
            )
            self.assertEqual((root / "locked-out.txt").read_text(encoding="utf-8"), "")

    def test_all_engine_failure_retries_without_marking_secret_used(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                tool="nxc", protocol="smb", users=["alice"],
                passwords=["Password1!"], log_dir=tmp, dry_run=True,
                no_preflight=True, time_between_rounds=0,
                passwords_per_round=1, realm_retry=False,
                engine_transient_threshold=1,
            )
            failed = authtempo.RoundResult(aborted=True, abort_reason="exit-code-1")
            succeeded = authtempo.RoundResult(
                clean_finish=True,
                reconciled_complete=True,
            )
            outcomes = [failed, failed, failed, succeeded]
            console = Console(file=io.StringIO(), force_terminal=False)

            with patch.object(authtempo, "spray_one_password", side_effect=outcomes) as spray, \
                    patch.object(authtempo, "setup_signal_handler"), \
                    patch("builtins.input", return_value=""):
                authtempo.run(cfg, console)

            self.assertEqual(spray.call_count, 3)
            data = json.loads((Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(data["used_passwords"], [])
            self.assertEqual(data["remaining_queue"], ["Password1!"])
            self.assertEqual(data["completed_batches"], 0)

    def test_tool_pause_output_uses_operator_language(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
                dry_run=True,
                no_preflight=True,
                time_between_rounds=0,
                realm_retry=False,
            )

            def tool_result(engine, _cfg, secret, _ui, state, _realm=None):
                if engine.tool == "kerbrute":
                    return authtempo.RoundResult(
                        aborted=True,
                        abort_reason="command-not-found",
                    )
                state.mark_attempted(secret, "alice", status="auth_failure")
                return authtempo.RoundResult(
                    clean_finish=True,
                    reconciled_complete=True,
                    dispatches=1,
                )

            output = io.StringIO()
            console = Console(file=output, force_terminal=False)
            with patch.object(
                authtempo,
                "spray_one_password",
                side_effect=tool_result,
            ), patch.object(authtempo, "setup_signal_handler"):
                self.assertTrue(authtempo.run(cfg, console))

            rendered = output.getvalue()
            self.assertIn("tool command was not found; paused for 3", rendered)
            self.assertIn("Tool status:", rendered)
            self.assertIn("retry after 3 password group(s)", rendered)
            self.assertNotIn("DEMOTED", rendered)
            self.assertNotIn("cooldown 3r", rendered)

    def test_isolated_lockout_does_not_prompt_or_stop_next_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                tool="nxc", protocol="smb", users=["alice"],
                passwords=["First!", "Second!"], log_dir=tmp,
                dry_run=True, no_preflight=True, time_between_rounds=0,
                passwords_per_round=2, realm_retry=False,
                lockout_threshold=1, lockout_burst=5,
            )

            def lock_first(_engine, _cfg, _secret, _ui, state, _realm=None):
                state.add_lockout("alice", secret=_secret)
                return authtempo.RoundResult(
                    lockouts={"alice"},
                    clean_finish=True,
                    reconciled_complete=True,
                )

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "spray_one_password", side_effect=lock_first) as spray, \
                    patch.object(authtempo, "setup_signal_handler"), \
                    patch.object(authtempo, "prompt_continue", return_value=False) as prompt:
                authtempo.run(cfg, console)

            self.assertEqual(spray.call_count, 2)
            prompt.assert_not_called()
            data = json.loads((Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(data["used_passwords"], ["First!", "Second!"])
            self.assertEqual(data["completed_batches"], 1)

    def test_isolated_lockout_result_completes_without_prompt_or_failover(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                tool="nxc", protocol="smb", users=["alice", "bob"],
                passwords=["First!"], log_dir=tmp, dry_run=True,
                no_preflight=True, time_between_rounds=0,
                passwords_per_round=1, realm_retry=False,
                lockout_threshold=1, lockout_burst=5,
            )

            def quarantine_then_finish(_engine, _cfg, _secret, _ui, state, _realm=None):
                state.add_lockout("alice", secret=_secret)
                state.mark_attempted(_secret, "bob", status="dry_run")
                return authtempo.RoundResult(
                    lockouts={"alice"},
                    clean_finish=True,
                    reconciled_complete=True,
                )

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "spray_one_password", side_effect=quarantine_then_finish) as spray, \
                    patch.object(authtempo, "setup_signal_handler"), \
                    patch.object(authtempo, "prompt_continue", return_value=True) as prompt:
                authtempo.run(cfg, console)

            self.assertEqual(spray.call_count, 1)
            self.assertEqual(
                [str(call.args[0]) for call in spray.call_args_list],
                ["nxc:smb"],
            )
            prompt.assert_not_called()
            data = json.loads((Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(data["used_passwords"], ["First!"])
            self.assertEqual(set(data["active_lockouts"]), {"alice"})

    def test_consecutive_lockout_pause_never_uses_an_operator_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = ["alice", "bob", "carol", "dave"]
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                tool="nxc", protocol="smb", users=users,
                passwords=["First!"], log_dir=tmp, dry_run=True,
                no_preflight=True, time_between_rounds=0,
                passwords_per_round=1, realm_retry=False,
                lockout_threshold=1, lockout_burst=3,
            )
            def report_streak(_engine, _cfg, _secret, _ui, state, _realm=None):
                for user in users:
                    state.add_lockout(user, secret=_secret)
                return authtempo.RoundResult(
                    lockouts=set(users),
                    aborted=True,
                    abort_reason="consecutive-lockouts",
                )

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "spray_one_password", side_effect=report_streak) as spray, \
                    patch.object(authtempo, "setup_signal_handler"), \
                    patch.object(authtempo, "prompt_continue", return_value=True) as prompt:
                authtempo.run(cfg, console)

            self.assertEqual(spray.call_count, 1)
            prompt.assert_not_called()
            data = json.loads((Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(set(data["locked_users"]), set(users))
            self.assertEqual(data["used_passwords"], [])

    def test_per_pass_ceiling_does_not_combine_signals_across_a_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                tool="nxc",
                protocol="ldap",
                users=["alice", "bob"],
                passwords=["First!", "Second!"],
                log_dir=tmp,
                dry_run=True,
                no_preflight=True,
                time_between_rounds=0,
                passwords_per_round=2,
                realm_retry=False,
                lockout_threshold=99,
                lockout_burst=1,
            )
            affected = {"First!": "alice", "Second!": "bob"}

            def one_signal_per_pass(_engine, _cfg, secret, _ui, state, _realm=None):
                user = affected[secret]
                state.add_lockout(user, secret=secret)
                for candidate in _cfg.users:
                    if (
                        candidate != user
                        and state.quarantine_reason(candidate) is None
                    ):
                        state.mark_attempted(
                            secret,
                            candidate,
                            status="auth_failure",
                        )
                return authtempo.RoundResult(
                    lockouts={user},
                    clean_finish=True,
                    reconciled_complete=True,
                    dispatches=1,
                )

            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(
                authtempo,
                "spray_one_password",
                side_effect=one_signal_per_pass,
            ), patch.object(authtempo, "setup_signal_handler"):
                authtempo.run(cfg, console)

            data = json.loads(
                (Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(data["used_passwords"], ["First!", "Second!"])
            self.assertEqual(data["completed_batches"], 1)

    def test_kerbrute_safe_stop_never_fails_over(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users", "passwords", "LAB", "127.0.0.1",
                tool="kerbrute", users=["alice", "bob"],
                passwords=["First!"], log_dir=tmp, dry_run=True,
                no_preflight=True, time_between_rounds=0,
                passwords_per_round=1, realm_retry=False,
            )
            stopped = authtempo.RoundResult(
                lockouts={"alice"},
                aborted=True,
                abort_reason="lockout-safety-stop",
            )
            console = Console(file=io.StringIO(), force_terminal=False)

            with patch.object(authtempo, "spray_one_password", return_value=stopped) as spray, \
                    patch.object(authtempo, "setup_signal_handler"):
                authtempo.run(cfg, console)

            self.assertEqual(spray.call_count, 1)
            data = json.loads((Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8"))
            self.assertEqual(data["used_passwords"], [])
            self.assertEqual(data["completed_batches"], 0)

    def test_cli_failover_options_reach_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = Path(tmp) / "users.txt"
            passwords = Path(tmp) / "passwords.txt"
            users.write_text("alice\n", encoding="utf-8")
            passwords.write_text("Password1!\n", encoding="utf-8")
            argv = [
                "authtempo.py", "-u", str(users), "-p", str(passwords),
                "-d", "LAB", "-dc-ip", "127.0.0.1", "--dry-run",
                "--engine-cooldown", "7", "--engine-fail-threshold", "4",
                "--max-lockouts-per-spray", "6",
                "--no-realm-retry", "--verbose", "--no-live",
            ]

            with patch.object(sys, "argv", argv), patch.object(authtempo, "run") as run:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    authtempo.main()

            cfg = run.call_args.args[0]
            self.assertEqual(cfg.engine_cooldown_rounds, 7)
            self.assertEqual(cfg.engine_transient_threshold, 4)
            self.assertFalse(cfg.realm_retry)
            self.assertTrue(cfg.verbose)
            self.assertFalse(cfg.live_ui)
            self.assertEqual(cfg.passwords_per_round, 1)
            self.assertEqual(cfg.lockout_burst, 6)
            self.assertEqual(cfg.feed_lines, 10)

    def test_compact_help_uses_operator_language_and_hides_tuning(self):
        compact = authtempo.build_argument_parser("authtempo").format_help()

        self.assertIn("--limit N", compact)
        self.assertIn("--max-lockouts N", compact)
        self.assertIn("--validate-users", compact)
        self.assertIn("--advanced-help", compact)
        self.assertNotIn("--passes-per-batch", compact)
        self.assertNotIn("--engine-skip-batches", compact)
        self.assertNotIn("--engine-fail-threshold", compact)
        self.assertNotIn("--tool-retry-after", compact)

    def test_advanced_help_explains_tool_recovery_in_plain_language(self):
        advanced = authtempo.build_argument_parser("authtempo", advanced=True).format_help()

        self.assertIn("--tool-retry-after GROUPS", advanced)
        self.assertIn("completed password groups", advanced)
        self.assertIn("--tool-error-limit N", advanced)
        self.assertIn("Pause a tool after N consecutive temporary errors", advanced)
        self.assertNotIn("--engine-skip-batches", advanced)
        self.assertNotIn("--engine-fail-threshold", advanced)

    def test_human_facing_options_reach_the_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = Path(tmp) / "users.txt"
            passwords = Path(tmp) / "passwords.txt"
            users.write_text("alice\n", encoding="utf-8")
            passwords.write_text("Password1!\n", encoding="utf-8")
            argv = [
                "authtempo.py", "-u", str(users), "-p", str(passwords),
                "-d", "LAB", "-dc-ip", "127.0.0.1", "--dry-run",
                "--limit", "2", "--wait", "10", "--max-lockouts", "3",
                "--review-after-lockouts", "4", "--tool-retry-after", "5",
                "--tool-error-limit", "6", "--stream",
                "--report", "all", "--output", str(Path(tmp) / "out"),
            ]

            with patch.object(sys, "argv", argv), patch.object(authtempo, "run") as run:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    authtempo.main()

            cfg = run.call_args.args[0]
            self.assertEqual(cfg.passwords_per_round, 2)
            self.assertEqual(cfg.time_between_rounds, 10)
            self.assertEqual(cfg.lockout_burst, 3)
            self.assertEqual(cfg.lockout_threshold, 4)
            self.assertEqual(cfg.engine_cooldown_rounds, 5)
            self.assertEqual(cfg.engine_transient_threshold, 6)
            self.assertFalse(cfg.live_ui)
            self.assertEqual(cfg.export, "all")
            self.assertEqual(cfg.log_dir, str(Path(tmp) / "out"))

    def test_cli_returns_nonzero_when_a_run_stops_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = Path(tmp) / "users.txt"
            passwords = Path(tmp) / "passwords.txt"
            users.write_text("alice\n", encoding="utf-8")
            passwords.write_text("Password1!\n", encoding="utf-8")
            argv = [
                "authtempo.py",
                "-u",
                str(users),
                "-p",
                str(passwords),
                "-d",
                "LAB",
                "-dc-ip",
                "127.0.0.1",
                "--dry-run",
            ]

            with patch.object(sys, "argv", argv), patch.object(
                authtempo,
                "run",
                return_value=False,
            ), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                with self.assertRaises(SystemExit) as stopped:
                    authtempo.main()

            self.assertEqual(stopped.exception.code, 2)


class AdversarialSafetyTests(unittest.TestCase):
    def make_config(self, tmp, **overrides):
        values = {
            "users": ["alice"],
            "passwords": ["Password1!"],
            "log_dir": tmp,
            "nxc_binary": "/fake/nxc",
            "kerbrute_binary": "/fake/kerbrute",
        }
        values.update(overrides)
        return authtempo.Config(
            "users",
            "passwords",
            "LAB",
            "127.0.0.1",
            **values,
        )

    def test_version_labeled_engine_output_fixtures(self):
        fixture_cases = [
            ("netexec-1.5.1-observed.golden", authtempo.Engine("nxc", "ldap")),
            ("kerbrute-1.0.3-observed.golden", authtempo.Engine("kerbrute")),
        ]
        fixture_dir = Path(__file__).parent / "fixtures"
        for fixture_name, engine in fixture_cases:
            with self.subTest(fixture=fixture_name):
                source = (fixture_dir / fixture_name).read_text(encoding="utf-8")
                for source_line in source.splitlines():
                    if not source_line or source_line.startswith("#"):
                        continue
                    expected_type, expected_data, output_line = source_line.split("\t", 2)
                    line_type, data = authtempo.classify_line(engine, output_line)
                    self.assertEqual(line_type.name, expected_type)
                    self.assertEqual(data, expected_data)

    def test_unrelated_domain_aliases_are_not_collapsed(self):
        configured = [r"OTHER\alice", "bob@other.example"]
        self.assertEqual(
            authtempo._normalize_reported_user("alice", configured, "LAB.EXAMPLE"),
            "alice",
        )
        self.assertEqual(
            authtempo._normalize_reported_user("bob", configured, "LAB.EXAMPLE"),
            "bob",
        )
        self.assertNotEqual(
            authtempo.canonical_identity(r"OTHER\alice", "LAB.EXAMPLE"),
            authtempo.canonical_identity("alice", "LAB.EXAMPLE"),
        )

    @unittest.skipUnless(hasattr(os, "killpg") and Path("/proc").is_dir(), "Linux process groups required")
    def test_stop_process_kills_a_wrapper_and_its_grandchild(self):
        grandchild_code = (
            "import signal,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "time.sleep(60)"
        )
        wrapper_code = (
            "import signal,subprocess,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            f"child=subprocess.Popen([sys.executable, '-c', {grandchild_code!r}]); "
            "print(child.pid, flush=True); "
            "time.sleep(60)"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", wrapper_code],
            stdout=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            self.assertIsNotNone(proc.stdout)
            grandchild_pid = int(proc.stdout.readline().strip())
            authtempo._stop_process(proc)
            self.assertIsNotNone(proc.poll())
            stat_path = Path(f"/proc/{grandchild_pid}/stat")
            deadline = authtempo.time.monotonic() + 1
            state = ""
            while stat_path.exists() and authtempo.time.monotonic() < deadline:
                state = stat_path.read_text(encoding="utf-8").split()[2]
                if state == "Z":
                    break
                authtempo.time.sleep(0.02)
            self.assertTrue(not stat_path.exists() or state == "Z")
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if proc.stdout is not None:
                proc.stdout.close()

    def test_nxc_ldap_user_account_locked_is_not_an_auth_failure(self):
        line = "LDAP 127.0.0.1 389 DC [-] LAB\\alice:One! USER_ACCOUNT_LOCKED"
        line_type, user = authtempo.classify_line(authtempo.Engine("nxc", "ldap"), line)
        self.assertEqual(line_type, authtempo.LineType.LOCKOUT)
        self.assertEqual(user, "alice")

    def test_signal_four_stops_before_a_fifth_identity_is_dispatched(self):
        users = ["alice", "bob", "carol", "dave", "erin"]
        lines = [
            f"LDAP 127.0.0.1 389 DC [-] LAB\\{user}:One! USER_ACCOUNT_LOCKED\n"
            for user in users[:4]
        ]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=users,
                passwords=["One!"],
                lockout_threshold=99,
                lockout_burst=3,
            )
            state = authtempo.State(tmp, cfg)
            processes = [fake_process([line]) for line in lines]
            with patch.object(authtempo.subprocess, "Popen", side_effect=processes) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "ldap"), cfg, "One!", QuietUI(), state,
                )

            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "consecutive-lockouts")
            self.assertEqual(popen.call_count, 4)
            self.assertEqual(state.lockout_count, 4)
            self.assertEqual(state.eligible_users_for("One!"), ["erin"])

    def test_resume_skips_quarantined_users_and_can_continue(self):
        users = ["alice", "bob", "carol", "dave", "erin"]
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, users=users, passwords=["One!"], lockout_burst=3)
            first = authtempo.State(tmp, cfg)
            for user in users[:4]:
                first.add_lockout(user, secret="One!", engine="nxc", protocol="ldap")
            first.close()

            resumed_cfg = self.make_config(
                tmp,
                users=users,
                passwords=["One!"],
                lockout_burst=3,
                resume=True,
            )
            resumed = authtempo.State(tmp, resumed_cfg)
            erin_failure = fake_process([
                "LDAP 127.0.0.1 389 DC [-] LAB\\erin:One! STATUS_LOGON_FAILURE\n"
            ])
            with patch.object(
                authtempo.subprocess,
                "Popen",
                return_value=erin_failure,
            ) as popen:
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "ldap"),
                    resumed_cfg,
                    "One!",
                    QuietUI(),
                    resumed,
                )
            self.assertFalse(result.aborted)
            self.assertTrue(result.clean_finish)
            popen.assert_called_once()
            self.assertEqual(resumed.pair_status("One!", "erin"), "auth_failure")

    def test_resume_preserves_the_interrupted_batch_boundary(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {
                "users": ["alice"],
                "passwords": ["One!", "Two!", "Three!", "Four!"],
                "passwords_per_round": 3,
                "time_between_rounds": 0,
                "dry_run": True,
            }
            first = authtempo.State(tmp, self.make_config(tmp, **values))
            for secret in values["passwords"][:2]:
                first.mark_attempted(secret, "alice", status="dry_run")
                first.mark_used(secret)
            first.close()

            resumed_cfg = self.make_config(tmp, resume=True, **values)
            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "setup_signal_handler"), patch.object(
                authtempo.time,
                "sleep",
            ):
                authtempo.run(resumed_cfg, console)

            data = json.loads(
                (Path(tmp) / authtempo.STATE_FILE_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual(data["completed_batches"], 2)
            self.assertEqual(data["remaining_queue"], [])

    def test_resume_preserves_an_unfinished_inter_batch_delay(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {
                "users": ["alice"],
                "passwords": ["One!", "Two!"],
                "passwords_per_round": 1,
                "time_between_rounds": 35,
                "dry_run": True,
            }
            first = authtempo.State(tmp, self.make_config(tmp, **values))
            first.mark_attempted("One!", "alice", status="dry_run")
            first.mark_used("One!")
            first.mark_round_complete()
            first.close()

            waits = []
            resumed_cfg = self.make_config(tmp, resume=True, **values)
            console = Console(file=io.StringIO(), force_terminal=False)
            with patch.object(authtempo, "setup_signal_handler"), patch.object(
                authtempo.RichUI,
                "countdown",
                side_effect=lambda seconds: waits.append(seconds),
            ), patch.object(authtempo.time, "sleep"):
                authtempo.run(resumed_cfg, console)

            self.assertEqual(len(waits), 1)
            self.assertGreaterEqual(waits[0], 35 * 60 - 2)

    def test_locked_and_compromised_identities_are_quarantined(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=["Alice", "bob", "carol"],
                passwords=["Password1!", "Different!"],
            )
            state = authtempo.State(tmp, cfg)
            state.add_lockout("alice", secret="Password1!")
            state.add_cred("BOB", "Different!")
            self.assertEqual(state.eligible_users_for("Password1!"), ["carol"])

    def test_overlapping_quarantine_reasons_require_every_applicable_override(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=["alice"],
                passwords=["One!", "Two!", "Three!"],
            )
            state = authtempo.State(tmp, cfg)
            state.add_cred("alice", "One!")
            state.begin_attempt("Two!", "alice", authtempo.Engine("nxc", "ldap"))
            state.finish_attempt("Two!", "alice", "indeterminate")
            self.assertEqual(
                state.quarantine_reasons("alice"),
                {"credential_found", "indeterminate"},
            )

            cfg.retry_indeterminate = True
            self.assertEqual(state.eligible_users_for("Three!"), [])
            cfg.retry_compromised = True
            self.assertEqual(state.eligible_users_for("Three!"), ["alice"])

            state.add_lockout("alice", certainty="ambiguous", secret="Three!")
            self.assertEqual(state.eligible_users_for("Three!"), [])

    def test_kerbrute_failure_and_password_expiry_keep_the_identity(self):
        failure = "2026/10/13 > [!] HOST$@LAB:One! - KDC_ERR_PREAUTH_FAILED"
        line_type, user = authtempo.classify_line(authtempo.Engine("kerbrute"), failure)
        self.assertEqual((line_type, user), (authtempo.LineType.AUTHFAIL, "HOST$@LAB"))

        success = (
            "2026/10/13 > [+] VALID LOGIN WITH ERROR: HOST$@LAB:One! "
            "(KDC_ERR_KEY_EXPIRED)"
        )
        line_type, data = authtempo.classify_line(authtempo.Engine("kerbrute"), success)
        self.assertEqual(line_type, authtempo.LineType.PASSWORD_EXPIRED)
        self.assertEqual(data, "HOST$@LAB:One!")

    def test_nxc_password_change_states_are_valid_credential_results(self):
        cases = (
            ("STATUS_PASSWORD_EXPIRED", authtempo.LineType.PASSWORD_EXPIRED),
            ("STATUS_PASSWORD_MUST_CHANGE", authtempo.LineType.PASSWORD_MUST_CHANGE),
        )
        for protocol in ("smb", "ldap"):
            for status, expected_type in cases:
                with self.subTest(protocol=protocol, status=status):
                    line = (
                        f"{protocol.upper()} 127.0.0.1 445 DC [-] "
                        f"LAB\\alice:One! {status}"
                    )
                    line_type, data = authtempo.classify_line(
                        authtempo.Engine("nxc", protocol),
                        line,
                        expected_secret="One!",
                    )
                    self.assertEqual(line_type, expected_type)
                    self.assertEqual(data, "alice:One!")

    def test_password_expired_finding_writes_actionable_impacket_command(self):
        line = (
            "SMB 127.0.0.1 445 DC [-] "
            "LAB\\alice:Password1! STATUS_PASSWORD_EXPIRED\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
                nxc_binary="/fake/nxc",
            )
            state = authtempo.State(tmp, cfg)
            with patch.object(
                authtempo.subprocess,
                "Popen",
                return_value=fake_process([line]),
            ):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "smb"),
                    cfg,
                    "Password1!",
                    QuietUI(),
                    state,
                )

            self.assertTrue(result.clean_finish)
            self.assertEqual(
                result.password_change_required,
                [("alice", "Password1!", "password_expired")],
            )
            self.assertEqual(
                state.pair_status("Password1!", "alice"),
                "password_expired",
            )
            self.assertEqual(
                state.credentials[0]["credential_state"],
                "password_expired",
            )
            action_text = (
                Path(tmp) / authtempo.PASSWORD_CHANGES_FILE_NAME
            ).read_text(encoding="utf-8")
            self.assertIn("Credential: alice:Password1!", action_text)
            command = next(
                line.removeprefix("Command: ")
                for line in action_text.splitlines()
                if line.startswith("Command: ")
            )
            self.assertEqual(
                command,
                "impacket-changepasswd -protocol smb-samr LAB/alice@127.0.0.1",
            )
            self.assertNotIn("Password1!", command)
            state.export_results("json")
            exported = json.loads(
                (Path(tmp) / "results.json").read_text(encoding="utf-8")
            )
            self.assertEqual(exported["stats"]["password_change_required"], 1)
            self.assertEqual(exported["stats"]["successful_pairs"], 1)
            self.assertEqual(
                exported["credentials"][0]["password_change_command"],
                command,
            )
            state.close()

            resumed_cfg = authtempo.Config(
                "users",
                "passwords",
                "LAB",
                "127.0.0.1",
                users=["alice"],
                passwords=["Password1!"],
                log_dir=tmp,
                nxc_binary="/fake/nxc",
                resume=True,
            )
            resumed = authtempo.State(tmp, resumed_cfg)
            self.assertEqual(
                resumed.credentials[0]["credential_state"],
                "password_expired",
            )
            resumed.close()

    def test_hash_password_change_command_supplies_the_recorded_hash(self):
        command = authtempo.build_password_change_command(
            "LAB",
            "LAB\\Alice",
            "127.0.0.1",
            secret="0123456789abcdef",
            pth_mode=True,
        )
        self.assertEqual(
            command,
            "impacket-changepasswd -protocol smb-samr -hashes "
            "0123456789abcdef LAB/Alice@127.0.0.1",
        )

    def test_nxc_machine_account_success_is_parsed(self):
        line = "SMB 127.0.0.1 445 DC [+] LAB\\HOST$:One!"
        line_type, data = authtempo.classify_line(authtempo.Engine("nxc", "smb"), line)
        self.assertEqual(line_type, authtempo.LineType.SUCCESS)
        self.assertEqual(data, "HOST$:One!")

    def test_resume_requires_an_existing_valid_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, resume=True)
            with self.assertRaisesRegex(RuntimeError, "state file is missing"):
                authtempo.State(tmp, cfg)

    def test_resume_detects_former_authcadence_state_without_migrating_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "authcadence.state.json").write_text(
                "{}",
                encoding="utf-8",
            )
            cfg = self.make_config(tmp, resume=True)
            with self.assertRaisesRegex(RuntimeError, "legacy state"):
                authtempo.State(tmp, cfg)

    def test_resume_refuses_corrupt_and_incomplete_state(self):
        for payload in ("{", "{}"):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                (Path(tmp) / authtempo.STATE_FILE_NAME).write_text(payload, encoding="utf-8")
                cfg = self.make_config(tmp, resume=True)
                with self.assertRaises(RuntimeError):
                    authtempo.State(tmp, cfg)

    def test_resume_refuses_an_inconsistent_secret_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = authtempo.State(tmp, self.make_config(tmp))
            state.close()
            state_path = Path(tmp) / authtempo.STATE_FILE_NAME
            data = json.loads(state_path.read_text(encoding="utf-8"))
            data["remaining_queue"] = []
            state_path.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(state_path, 0o600)

            with self.assertRaisesRegex(RuntimeError, "secret queue"):
                authtempo.State(tmp, self.make_config(tmp, resume=True))

    def test_attempt_metrics_are_rebuilt_from_the_pair_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {
                "users": ["alice", "bob", "carol"],
                "passwords": ["Password1!"],
            }
            state = authtempo.State(tmp, self.make_config(tmp, **values))
            for user, status in (("alice", "auth_failure"), ("bob", "indeterminate")):
                self.assertTrue(
                    state.begin_attempt(
                        "Password1!",
                        user,
                        authtempo.Engine("nxc", "ldap"),
                    )
                )
                state.finish_attempt("Password1!", user, status)
            state.add_lockout(
                "carol",
                certainty="ambiguous",
                secret="Password1!",
            )
            state.mark_used("Password1!")
            state.close()

            state_path = Path(tmp) / authtempo.STATE_FILE_NAME
            data = json.loads(state_path.read_text(encoding="utf-8"))
            data["total_attempts"] = 999
            data["attempts_by_password"] = {"Password1!": 999}
            state_path.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(state_path, 0o600)

            resumed = authtempo.State(
                tmp,
                self.make_config(tmp, resume=True, **values),
            )
            self.assertEqual(resumed.total_attempts, 2)
            self.assertEqual(resumed.attempts_by_password, {"Password1!": 2})
            self.assertEqual(resumed.skipped_pair_count(), 1)
            resumed.close()

    def test_resume_rejects_changed_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            first_cfg = self.make_config(tmp)
            first = authtempo.State(tmp, first_cfg)
            first.close()
            second_cfg = self.make_config(tmp, users=["alice", "bob"], resume=True)
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                authtempo.State(tmp, second_cfg)

    def test_resume_restores_filtered_identities_from_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {
                "users": ["alice", "bob"],
                "filter_disabled": True,
            }
            first = authtempo.State(tmp, self.make_config(tmp, **values))
            first.set_effective_users(["alice"])
            first.close()

            self.assertFalse((Path(tmp) / "active-users.txt").exists())
            resumed_cfg = self.make_config(tmp, resume=True, **values)
            resumed = authtempo.State(tmp, resumed_cfg)
            self.assertTrue(resumed.identity_filter_complete)
            self.assertEqual(resumed_cfg.users, ["alice"])
            resumed.close()

    def test_resume_can_continue_a_pending_identity_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {
                "users": ["alice", "bob"],
                "filter_disabled": True,
            }
            first = authtempo.State(tmp, self.make_config(tmp, **values))
            first.close()

            resumed = authtempo.State(
                tmp,
                self.make_config(tmp, resume=True, **values),
            )
            self.assertFalse(resumed.identity_filter_complete)
            self.assertEqual(resumed.cfg.users, ["alice", "bob"])
            resumed.close()

    def test_resume_rejects_changed_spray_timing(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = authtempo.State(
                tmp,
                self.make_config(tmp, time_between_rounds=35),
            )
            first.close()
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                authtempo.State(
                    tmp,
                    self.make_config(
                        tmp,
                        time_between_rounds=5,
                        resume=True,
                    ),
                )

    def test_resume_rejects_changed_engine_safety_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = authtempo.State(
                tmp,
                self.make_config(tmp, engine_cooldown_rounds=3),
            )
            first.close()
            with self.assertRaisesRegex(RuntimeError, "does not match"):
                authtempo.State(
                    tmp,
                    self.make_config(
                        tmp,
                        engine_cooldown_rounds=1,
                        resume=True,
                    ),
                )

    def test_resume_rejects_inconsistent_engine_cooldown_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            values = {"engine_transient_threshold": 1}
            state = authtempo.State(tmp, self.make_config(tmp, **values))
            state.register_engine_failure("kerbrute", "timeout")
            state.save()
            state.close()

            state_path = Path(tmp) / authtempo.STATE_FILE_NAME
            data = json.loads(state_path.read_text(encoding="utf-8"))
            data["engine_health"]["kerbrute"]["demoted"] = False
            state_path.write_text(json.dumps(data), encoding="utf-8")
            os.chmod(state_path, 0o600)

            with self.assertRaisesRegex(RuntimeError, "engine-health"):
                authtempo.State(
                    tmp,
                    self.make_config(tmp, resume=True, **values),
                )

    def test_in_flight_pair_becomes_indeterminate_and_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp)
            first = authtempo.State(tmp, cfg)
            first.begin_attempt("Password1!", "alice", authtempo.Engine("nxc", "ldap"))
            first.close()

            resumed_cfg = self.make_config(tmp, resume=True)
            resumed = authtempo.State(tmp, resumed_cfg)
            self.assertEqual(resumed.pair_status("Password1!", "alice"), "indeterminate")
            self.assertEqual(resumed.eligible_users_for("Password1!"), [])

    def test_resume_reconstructs_global_evidence_from_terminal_pair_ledger(self):
        for status in ("success", "lockout", "ambiguous_lockout"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                cfg = self.make_config(tmp)
                first = authtempo.State(tmp, cfg)
                first.begin_attempt(
                    "Password1!",
                    "alice",
                    authtempo.Engine("nxc", "ldap"),
                )
                # Simulate a crash from the former two-write path: the terminal
                # pair reached disk but its aggregate finding/signal did not.
                first.finish_attempt("Password1!", "alice", status)
                first.close()

                resumed = authtempo.State(tmp, self.make_config(tmp, resume=True))
                if status == "success":
                    self.assertEqual(
                        resumed.credential_pairs(),
                        [("alice", "Password1!")],
                    )
                    self.assertEqual(
                        resumed.quarantine_reason("alice"),
                        "credential_found",
                    )
                elif status == "lockout":
                    self.assertEqual(resumed.locked_users, {"alice"})
                    self.assertEqual(resumed.lockout_count, 1)
                else:
                    self.assertEqual(resumed.locked_users, set())
                    self.assertEqual(resumed.lockout_count, 1)
                    self.assertEqual(
                        resumed.quarantine_reason("alice"),
                        "ambiguous_lockout_signal",
                    )
                resumed.close()

    def test_successful_explicit_retry_clears_resolved_indeterminate_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                passwords=["First!", "Second!"],
                retry_indeterminate=True,
            )
            state = authtempo.State(tmp, cfg)
            engine = authtempo.Engine("nxc", "ldap")
            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "indeterminate")
            self.assertIn("indeterminate", state.quarantine_reasons("alice"))

            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "auth_failure")
            self.assertNotIn("indeterminate", state.quarantine_reasons("alice"))
            cfg.retry_indeterminate = False
            self.assertEqual(state.eligible_users_for("Second!"), ["alice"])

    def test_nxc_receives_one_line_secret_file_not_literal_path_like_secret(self):
        observed = {}

        def launch(command, **_kwargs):
            secret_path = command[command.index("-p") + 1]
            observed["argument"] = secret_path
            observed["content"] = Path(secret_path).read_text(encoding="utf-8")
            return fake_process([
                "LDAP 127.0.0.1 389 DC [-] LAB\\alice:passwords.txt STATUS_LOGON_FAILURE\n"
            ])

        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, passwords=["passwords.txt"])
            state = authtempo.State(tmp, cfg)
            with patch.object(authtempo.subprocess, "Popen", side_effect=launch):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "ldap"),
                    cfg,
                    "passwords.txt",
                    QuietUI(),
                    state,
                )

            self.assertTrue(result.reconciled_complete)
            self.assertNotEqual(observed["argument"], "passwords.txt")
            self.assertEqual(observed["content"], "passwords.txt\n")
            self.assertFalse(Path(observed["argument"]).exists())

    def test_output_directory_lock_prevents_concurrent_state_writers(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp)
            first = authtempo.State(tmp, cfg)
            try:
                with self.assertRaisesRegex(RuntimeError, "already using"):
                    authtempo.State(tmp, cfg)
            finally:
                first.close()

    def test_demoted_engine_is_absent_during_cooldown(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp, engine_transient_threshold=1)
            state = authtempo.State(tmp, cfg)
            chain = [authtempo.Engine("kerbrute"), authtempo.Engine("nxc", "ldap")]
            state.register_engine_failure("kerbrute", "timeout")
            self.assertEqual(
                [str(engine) for engine in state.compute_effective_chain(chain)],
                ["nxc:ldap"],
            )

            state.register_engine_failure("nxc:ldap", "timeout")
            probe = state.select_demoted_probe(chain, set())
            self.assertEqual(str(probe), "kerbrute")
            second = state.select_demoted_probe(chain, {"kerbrute"})
            self.assertEqual(str(second), "nxc:ldap")

    def test_missing_kerbrute_summary_is_not_reconciled(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp)
            state = authtempo.State(tmp, cfg)
            proc = fake_process([
                "2026/10/13 > [!] alice@LAB:Password1! - KDC_ERR_PREAUTH_FAILED\n"
            ])
            with patch.object(authtempo.subprocess, "Popen", return_value=proc):
                result = authtempo.spray_one_password(
                    authtempo.Engine("kerbrute"), cfg, "Password1!", QuietUI(), state,
                )
            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "missing-summary")
            self.assertFalse(result.reconciled_complete)

    def test_runtime_artifacts_are_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp)
            authtempo.State(tmp, cfg)
            for name in (
                authtempo.STATE_FILE_NAME,
                authtempo.AUDIT_LOG_NAME,
                "creds.txt",
                authtempo.PASSWORD_CHANGES_FILE_NAME,
                "locked-out.txt",
                "used-passwords.txt",
            ):
                mode = os.stat(Path(tmp) / name).st_mode & 0o777
                self.assertEqual(mode, 0o600, name)

    def test_engine_idle_timeout_marks_only_pair_indeterminate(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(tmp)
            state = authtempo.State(tmp, cfg)
            proc = fake_process([], running=True)
            with patch.object(authtempo.subprocess, "Popen", return_value=proc), \
                    patch.object(
                        authtempo,
                        "_iter_process_output",
                        side_effect=authtempo.EngineOutputTimeout("idle-timeout"),
                    ):
                result = authtempo.spray_one_password(
                    authtempo.Engine("nxc", "ldap"), cfg, "Password1!", QuietUI(), state,
                )
            self.assertTrue(result.aborted)
            self.assertEqual(result.abort_reason, "idle-timeout")
            self.assertEqual(state.pair_status("Password1!", "alice"), "indeterminate")
            proc.terminate.assert_called_once()

    def test_fresh_run_requires_explicit_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = authtempo.State(tmp, self.make_config(tmp))
            first.close()
            with self.assertRaisesRegex(RuntimeError, "--start-fresh"):
                authtempo.State(tmp, self.make_config(tmp))

    def test_csv_escapes_spreadsheet_formulas_and_keeps_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=["=cmd", "safe"],
                passwords=["+payload", " =payload"],
                export="csv",
            )
            state = authtempo.State(tmp, cfg)
            state.current_round = 7
            state.add_cred("=cmd", "+payload", engine="nxc:ldap")
            state.add_cred("safe", " =payload", engine="nxc:ldap")
            rows = list(csv.DictReader(
                (Path(tmp) / "results.csv").read_text(encoding="utf-8").splitlines()
            ))
            self.assertEqual(rows[0]["user"], "'=cmd")
            self.assertEqual(rows[0]["password"], "'+payload")
            self.assertEqual(rows[0]["status"], "success")
            self.assertEqual(rows[0]["password_pass"], "7")
            self.assertEqual(rows[0]["batch"], "7")
            self.assertEqual(rows[0]["engine"], "nxc:ldap")
            self.assertEqual(rows[1]["password"], "' =payload")

    def test_results_csv_contains_every_pair_outcome(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=["alice", "bob"],
                passwords=["First!"],
                export="csv",
            )
            state = authtempo.State(tmp, cfg)
            state.current_round = 1
            state.current_pass = 1
            engine = authtempo.Engine("nxc", "smb")

            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "success")
            state.add_cred("alice", "First!", engine="nxc:smb")
            state.begin_attempt("First!", "bob", engine)
            state.finish_attempt("First!", "bob", "auth_failure")
            state.save()

            rows = list(csv.DictReader(
                (Path(tmp) / "results.csv").read_text(encoding="utf-8").splitlines()
            ))
            self.assertEqual(len(rows), 2)
            self.assertEqual(
                {(row["user"], row["status"]) for row in rows},
                {("alice", "success"), ("bob", "auth_failure")},
            )
            alice = next(row for row in rows if row["user"] == "alice")
            self.assertEqual(alice["credential_state"], "valid")
            self.assertEqual(alice["password_pass"], "1")
            self.assertEqual(alice["batch"], "1")
            self.assertEqual(alice["dispatches"], "1")
            self.assertEqual(alice["protocol"], "smb")

    def test_timeline_html_summarizes_pair_and_pass_activity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.make_config(
                tmp,
                users=["alice", "bob"],
                passwords=["First!"],
            )
            state = authtempo.State(tmp, cfg)
            state.current_round = 1
            state.current_pass = 1
            engine = authtempo.Engine("nxc", "smb")
            state.begin_attempt("First!", "alice", engine)
            state.finish_attempt("First!", "alice", "success")
            state.add_cred("alice", "First!", engine="nxc:smb")
            state.begin_attempt("First!", "bob", engine)
            state.finish_attempt("First!", "bob", "auth_failure")
            state.completed_rounds = 1

            rendered = state.render_timeline_html()

            self.assertIn("AuthTempo Run Report", rendered)
            self.assertIn("Attempts sent", rendered)
            self.assertIn("Unique pairs", rendered)
            self.assertIn("Password-pass activity", rendered)
            self.assertIn("Credential findings", rendered)
            self.assertIn("nxc:smb", rendered)
            self.assertIn("alice", rendered)

    def test_input_reader_preserves_literal_secret_whitespace_and_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "passwords.txt"
            path.write_text(
                "  spaced secret  \n\\#literal\n# comment\n #leading-space-hash\n",
                encoding="utf-8",
            )
            self.assertEqual(
                authtempo.read_input_lines(str(path), identities=False),
                ["  spaced secret  ", "#literal", " #leading-space-hash"],
            )

    def test_programmatic_inputs_cannot_expand_one_dispatch_into_multiple_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "line/control"):
                authtempo.State(
                    tmp,
                    self.make_config(tmp, passwords=["One!\nTwo!"]),
                )


if __name__ == "__main__":
    unittest.main()
