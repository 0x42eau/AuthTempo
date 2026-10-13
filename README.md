# AuthTempo

**Controlled authentication testing with enforced safety limits.**

AuthTempo is a safety-first operator tool for authorized authentication assessments. It wraps NetExec (`nxc`) and Kerbrute with strict per-identity dispatch, persistent attempt reconciliation, conservative lockout controls, engine failover, and resumable state.

A companion **`password_mutator.py`** generates targeted enterprise password lists from the domain/org name you give it — with leetspeak, acronyms, and editable building-block wordlists.

> For authorized penetration testing only. Use only on systems you have explicit written permission to test.

---

## Features

### Orchestrator (`authtempo.py`)

- **Strict dispatch**: the parent authorizes one identity at a time, so a recognized stop condition is checked before the next authentication starts
- **Exact lockout ceiling**: the default maximum is three signals in a pass; signal four is recorded and no fifth attempt is launched
- **Identity quarantine**: confirmed lockouts, ambiguous revocation signals, valid credentials, and indeterminate attempts are excluded from later work by default
- **Reconciled ledger**: every pair is persisted as in-flight before launch and receives a terminal or indeterminate outcome; metrics are rebuilt from this ledger
- **Resume-safe cadence**: an interrupted batch retains only its unused pass slots, and an unfinished inter-batch delay is honored before new work
- **Fail-closed resume**: missing, corrupt, incompatible, or incomplete state refuses to run instead of silently starting over
- **Multi-engine failover**: Kerbrute (default) and NetExec LDAP/SMB health is persisted, with actual cooldown skips and explicit probes
- **Process containment**: engine sessions have total/idle timeouts and process-group termination, including descendant cleanup
- **Operator display**: credentials remain visible at the top; tmux defaults to a stable streaming view while `--live` explicitly forces the cursor dashboard
- **Private artifacts**: the run directory is `0700`; state, findings, reports, logs, and temporary inputs are created as `0600`
- **Pass-the-hash, schedules, exports, timelines, realm retry, throttling, and dry-run support**

### Password mutator (`password_mutator.py`)
- **Variable-driven**: derives base names from what you actually provide — spaces in `--org`, separators (`-`/`_`) in the domain, or explicit `--keywords`. **Never guesses** word boundaries from keyword lists
- **Base-name transparency**: prints exactly which base names it derived so you can verify before spraying (`--show-bases`)
- **Leetspeak mutation**: bounded combinatorial leet per name (`Contoso → C0nt0s0, Cont0so, C0ntoso`)
- **Acronyms**: `Example Company → EC`, `Some Random Company → SRC`
- **Editable wordlists/**: seasons, months, anchors, years, suffixes, common passwords, and the leet map are all text files you edit — no Python changes
- **Balanced capped output**: target-specific forms and common enterprise passwords are prioritized without exceeding `--count`

---

## Quick start

```bash
python3 -m pip install -e .

# 1) Generate a targeted password list from the target's domain/org
python3 password_mutator.py -d sevenkingdoms.local --org "Seven Kingdoms" \
    --count 150 -o passwords.txt

# 2) Validate the workflow without target activity
authtempo -u users.txt -p passwords.txt -d sevenkingdoms.local \
    -dc-ip 10.10.10.10 --dry-run

# 3) Run only after confirming the authorized lockout policy
authtempo -u users.txt -p passwords.txt -d sevenkingdoms.local \
    -dc-ip 10.10.10.10 -t 35 --passes-per-batch 1
```

---

## Password mutator

The mutator builds passwords from **observed variables** (the words you give it), not keyword guessing. Word boundaries come from:

1. **`--org "Seven Kingdoms"`** — spaces split the name into words
2. **domain separators** — `seven-kingdoms.local` / `seven_kingdoms.local` split on `-`/`_`
3. **`--keywords seven,sevenkingdoms`** — explicit extra tokens to mutate

A space-less domain label with no separator is treated as **one word**. The tool always shows what it derived so you can correct it:

```bash
$ python3 password_mutator.py -d sevenkingdoms.local --org "Seven Kingdoms" --show-bases
[*] Base names derived (3): Seven, SK*, SevenKingdoms  (* = acronym)
[*] Leetspeak: ON (use --no-leet to disable)
```

If the domain is one word with no org/keywords, it proactively tips you:
```
[*] Tip: domain treated as one word. To split a compound (e.g. seven + sevenkingdoms),
    use --org "Seven Kingdoms" or --keywords seven,sevenkingdoms
```

### Examples

```bash
# Org with spaces -> Seven + SK + SevenKingdoms (double mutation)
python3 password_mutator.py -d sevenkingdoms.local --org "Seven Kingdoms" -o passwords.txt

# Explicit keywords
python3 password_mutator.py -d contoso.local --keywords contoso,contosocorp

# Leetspeak, more variants
python3 password_mutator.py -d contoso.org --org "Contoso" --leet-variants 12

# Password policy: enforce minimum length
python3 password_mutator.py -d contoso.local --length 12 --count 200

# Custom building-block files
python3 password_mutator.py -d contoso.local --wordlist-dir ./my_lists

# Disable leetspeak
python3 password_mutator.py -d contoso.local --no-leet
```

### Sample output (`-d sub.domain.local --org "This Fancy Org"`)

Base names: `ThisFancyOrg`, `TFO*`, `Sub`, `Domain`. Generates:
```
SummerThisFancyOrg2026!     WelcomeThisFancyOrg2026!     ThisFancyOrg2026!
TFO2026!                    7h15F4ncy0r92026!  (leet)    5u82026!  (Sub leet)
D0m41n2026!  (Domain leet)  Password123!                  Welcome123!
```

### Editable wordlists/

Every building block lives in `wordlists/` as plain text (one token per line; `#` comments ignored, except a line containing only `#`, which is a literal suffix). Edit them to match the target — no code changes. Each falls back to a built-in default if missing, so the mutator always works:

| File | Purpose |
|---|---|
| `seasons.txt` | seasonal words combined with name+year |
| `months.txt` | months combined with year |
| `anchors.txt` | words attached to the name (Welcome, Password, Ilove, …) |
| `years.txt` | supplementary/historical years (primary year = `--year`) |
| `suffixes.txt` | finales & separators (`!`, `!@#`, `@`, `-`, `_`) |
| `common_passwords.txt` | always-included common passwords (the floor) |
| `leet.txt` | leetspeak substitution map (`a=4,@`  `e=3`  …) |

Point at a different directory with `--wordlist-dir`.

### Mutator CLI

| Flag | Description |
|---|---|
| `-d`, `--domain` | Active Directory domain (e.g. `contoso.local`) |
| `--org` | Organization name — spaces split into words (e.g. `"Contoso Corp"`) |
| `--year` | Target year (default 2026) |
| `--count` | Max passwords to generate (default 100) |
| `-l`, `--length` | Minimum password length (default 0, no filter) |
| `-o`, `--output` | Output file (default stdout) |
| `--keywords` | Extra base tokens, comma-separated (`seven,sevenkingdoms`) |
| `--wordlist-dir` | Directory of building-block files (default `./wordlists`) |
| `--no-leet` | Disable leetspeak variants |
| `--leet-variants` | Max leet forms per base name (default 8) |
| `--show-bases` | Print derived base names and exit (dry check) |

---

## AuthTempo usage

```bash
# Plaintext spray, Kerbrute default
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 \
    -t 35 --passes-per-batch 1

# NetExec SMB
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 \
    --engine nxc --protocol smb -t 30

# Pass-the-hash
authtempo -u users.txt -p hashes.txt -d LAB -dc-ip 10.10.10.10 \
    --pth --engine nxc --protocol smb

# Dry run uses ./authtempo-dry-run-out by default
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --dry-run

# Resume only from compatible state, using the same inputs and safety settings
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --resume

# Explicitly replace generated artifacts for a new run
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --start-fresh

# Enumerate known users, export results, and generate the HTML timeline
authtempo -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 \
    --exclude-unknown-users --export all --timeline
```

### Primary CLI controls

**Required:** `-u` userlist, `-p` password/hash file, `-d` domain, `-dc-ip` DC IP

| Flag | Description |
|---|---|
| `--engine {kerbrute,nxc}` | initial engine (default Kerbrute) |
| `--protocol {smb,ldap}` | protocol for nxc (default ldap; ignored for kerbrute) |
| `-t MINUTES` | minutes between batches (default 35) |
| `--passes-per-batch N` | secrets evaluated before the configured delay (default 1) |
| `--pth` | pass-the-hash mode (forces nxc, excludes kerbrute) |
| `--pause-after-lockout-signals N` | cumulative signal count that requires operator review (default 2) |
| `--max-lockout-signals-per-pass N` | permit N signals in one pass; signal N+1 hard-stops (default 3) |
| `--exclude-unknown-users` | pre-run Kerbrute enumeration to retain identities proven to exist |
| `--export {none,json,csv,all}` | results export format (default none) |
| `--schedule {preset\|HH:MM-HH:MM}` | spray window: `business-hours`, `off-hours`, or range |
| `--timeline` | generate `authtempo-timeline.html` |
| `--no-live` / `--live` | select streaming output or force the cursor dashboard |
| `--engine-skip-batches N` | completed batches to omit a demoted engine before its normal probe (default 3) |
| `--engine-fail-threshold N` | consecutive transient failures before demoting (default 2) |
| `--probe-demoted` | after troubleshooting, explicitly probe each engine once if all remain in cooldown |
| `--engine-timeout N` | total seconds allowed for one per-identity engine process (default 300) |
| `--engine-idle-timeout N` | seconds allowed without engine output (default 60) |
| `--include-compromised` | **unsafe:** continue testing an identity after a valid credential |
| `--retry-indeterminate` | **unsafe:** retry a pair whose prior dispatch could not be reconciled |
| `--no-realm-retry` | disable kerbrute realm-variant auto-retry |
| `--nxc-path`, `--kerbrute-path` | override binary paths |
| `--no-preflight` | skip DC/domain preflight (discouraged) |
| `--log-dir DIR` | output/state directory (default `./authtempo-out`) |
| `--resume` / `--start-fresh` | resume compatible state or explicitly replace generated artifacts |

Run `authtempo --help` for the complete interface. The former flag names (`--tool`, `--limit`, `--lockout-threshold`, `--max-lockouts-per-spray`, `--filter-disabled`, `--engine-skip-passes`, and `--engine-cooldown`) remain compatibility aliases. `authcadence`, `authcadence.py`, and `spraygun.py` are warning compatibility entry points for one transition release.

A fully completed run exits `0`. A conservative stop that leaves queued work—such as a lockout hard-stop, failed preflight, or enumeration safety signal—exits `2` after saving state, so automation cannot mistake the pause for completion.

---

## Engine health and reconciliation

Engines are tracked for health across the run. When an engine aborts:

- Permanent errors demote an engine immediately; repeated transient failures demote it at `--engine-fail-threshold`.
- An engine in cooldown is omitted, not moved to the end as an implicit fallback.
- Cooldowns advance only when a batch completes. When a cooldown reaches zero, one reconciled probe can restore the engine.
- If every engine is in cooldown, AuthTempo stops. It bypasses cooldown only when the operator resumes with `--probe-demoted`.
- A process exit is successful only when the dispatched identity has a terminal result. Kerbrute also must report a tested-login summary of exactly one.

Every demotion, omission, probe, failover, and restoration is logged. `--verbose` adds masked command details.

**Failover chains:**
- kerbrute start: `kerbrute → nxc:ldap → nxc:smb`
- nxc SMB start: `nxc:smb → kerbrute → nxc:ldap`
- nxc LDAP start: `nxc:ldap → kerbrute → nxc:smb`
- PTH mode: `nxc:<chosen> → nxc:<other>` (kerbrute excluded)

Realm errors that are known to occur before authentication can try a configured realm variant without consuming a pair. Output truncation, timeouts, exceptions, identity mismatches, or missing summaries leave the affected pair indeterminate rather than guessing.

---

## Output & state files

All output goes to `./authtempo-out/` (or `--log-dir`):

| File | Contents |
|---|---|
| `authtempo.state.json` | versioned target/input fingerprints, exact remaining queue and batch boundary, pair ledger, quarantine, engine health, and counters |
| `creds.txt` | human-readable `user:password` hits |
| `locked-out.txt` | identities with definitive lockout evidence; ambiguous signals remain in state/logs |
| `used-passwords.txt` | fully reconciled secrets/hashes |
| `authtempo.log` | timestamped audit log and raw engine output |
| `active-users.txt` | enumerated identity set (with `--exclude-unknown-users`) |
| `results.json` / `results.csv` | structured exports (with `--export`) |
| `timeline.json` | machine-readable event log generated when a run reaches its final reporting stage; state retains the same events earlier |
| `authtempo-timeline.html` | self-contained visualization (with `--timeline`) |

State is written atomically. `--resume` validates schema, target, source and effective identity sets, identity-filter phase, exact secrets, safety settings, queue/batch invariants, identities, statuses, and dispatch counts. The effective identity set is authoritative in state; `active-users.txt` can be recreated instead of forcing another enumeration. Unreadable JSON is preserved as a timestamped private backup, then the run refuses to continue. It never falls back to a fresh spray. AuthCadence and Spraygun state is detected but deliberately not migrated automatically.

Credentials are intentionally displayed in clear text at the top of the dashboard and immediately when found in streaming mode, as requested for operator use. `creds.txt` and raw engine logs also contain sensitive material; protect or remove the run directory when the engagement permits. NetExec receives each candidate through a private one-line file, but Kerbrute requires the candidate as a process argument, so other privileged local process inspectors may be able to observe it while that child is running.

---

## Lockout-control semantics

- Safety signals are classified before generic authentication failures.
- `USER_ACCOUNT_LOCKED`, `STATUS_ACCOUNT_LOCKED_OUT`, and supported variants are definitive. `KDC_ERR_CLIENT_REVOKED` is ambiguous evidence and is not labeled a confirmed lockout.
- The default per-pass maximum is three signals: signals one through three are retained, signal four hard-stops, and attempt five is never dispatched.
- Kerbrute runs with `--safe --threads 1`; any recognized locked/revoked signal causes an immediate safety stop.
- Optional identity enumeration records locked/revoked evidence, quarantines the identity, and stops before password dispatch so the operator can review it.
- The default cumulative review threshold is two signals. Acknowledging that prompt cannot override the per-pass hard ceiling.
- Resume preserves a partially consumed batch and any unfinished inter-batch delay, preventing a restart from granting extra immediate passes.
- Confirmed, ambiguous, compromised, and indeterminate identities are quarantined. Configured-domain aliases share one record; unrelated domains do not.
- Ctrl-C, termination, timeout, and output-reader failure stop the entire process group and persist in-flight work conservatively.

No wrapper can guarantee zero lockouts without the effective domain and fine-grained lockout policies, observation windows, replication timing, and complete third-party tool output. Keep `--passes-per-batch` and `-t` within the authorized policy. The strict controller guarantees only that it will not launch new work after it observes its configured hard-stop condition.

## Input-file semantics

- Identity lines are trimmed, blank/comment lines are skipped, and configured-domain aliases are de-duplicated case-insensitively while preserving the first display spelling.
- Secret/hash lines preserve leading and trailing spaces. A line whose first character is `#` is a comment; prefix it as `\#` for a literal leading hash. A leading space before `#` is literal data.
- Exact duplicate secrets are de-duplicated in first-seen order. Empty secrets are not supported. Unsupported control characters fail with a file and line reference.

---

## Installation

Python 3.10 or newer is required.

```bash
python3 -m pip install -e .

# Development/test dependencies
python3 -m pip install -r requirements-dev.txt
```

Install at least one spray engine (both recommended for full failover):

**NetExec (nxc):**
```bash
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

**Kerbrute:**
```bash
# https://github.com/ropnop/kerbrute/releases
go install github.com/ropnop/kerbrute@latest
```

---

## Repository layout

```
authtempo.py           # canonical launcher
authcadence.py         # former-name compatibility launcher
spraygun.py            # implementation and historical compatibility launcher
password_mutator.py    # variable-driven password list generator
wordlists/             # editable building blocks (seasons, months, anchors, years, suffixes, common, leet)
tests/                 # unit, golden-parser, fault-injection, permission, and tmux-mode tests
REMEDIATION_PLAN.md    # threat findings, acceptance criteria, and implementation status
spraygun.sh            # disabled historical prototype; exits without running engines
authtempo-out/         # default runtime output (gitignored)
```

## For authorized use only

AuthTempo is designed for authorized penetration testing and security assessments. Use only on systems you have explicit permission to test. Unauthorized password spraying is illegal.

## License

Same as the original spraygun.sh project.
