# AuthTempo operator reference

This is the detailed reference. The main [README](../README.md) intentionally stays focused on the normal workflow.

## Safety behavior

AuthTempo dispatches one identity at a time. It writes the pair to its ledger before launch, observes the tool result, then records a terminal or uncertain outcome before moving on. That boundary lets it stop before starting another identity once a recognized safety condition is reached.

- One isolated definitive lockout is recorded, shown with its exact attempted pair, and quarantined. It does not stop the run.
- `--max-lockouts 4` permits four consecutive distinct locked identities. The fifth pauses the run before a sixth identity is dispatched.
- A definitive non-lockout authentication result resets the consecutive streak. A nonexistent username, skipped/quarantined identity, uncertain result, or tool error is neutral and does not hide a developing streak.
- Scattered lockouts in separate runs remain warnings. A target-specific campaign guard pauses when the historical affected population grows by **more than 50%** during one invocation and at least five new unique identities were added. For example, a baseline of 15 pauses at 23, not 22.
- Confirmed lockouts, ambiguous revocation signals, found credentials, and uncertain attempts quarantine the affected identity by default.
- Kerbrute always runs with safe mode and one worker. Its child process may stop on one locked user; AuthTempo reconciles that pair, quarantines it, and starts a fresh one-user child for the next eligible identity.
- Ambiguous lockout/revocation evidence still causes an immediate resumable safety pause because it cannot be safely labeled as a routine failure.
- Resume retains a partially consumed group and any unfinished inter-group wait. Restarting does not grant extra immediate passwords.

Recognized definitive evidence includes `USER_ACCOUNT_LOCKED`, `STATUS_ACCOUNT_LOCKED_OUT`, and supported variants. `KDC_ERR_CLIENT_REVOKED` is treated as an ambiguous safety signal rather than proof of a lockout.

### Active quarantine and safe rechecks

Historical observations and current quarantine are separate:

- `locked-out.txt` is immutable historical evidence.
- `active-lockouts.txt` contains identities currently excluded from authentication attempts.

When AuthTempo has a previously confirmed valid directory credential, it issues one read-only NetExec LDAP query at group boundaries for all active lockouts. It checks the `UF_LOCKOUT` (`0x10`) bit in `msDS-User-Account-Control-Computed`; `lockoutTime` alone is not used because it can remain nonzero after automatic unlock. A zero computed bit removes only the `confirmed_lockout` quarantine reason and resets the live consecutive streak. If no valid credential is available, the query fails, or the computed attribute is absent, the identity remains quarantined. No candidate password is retried for this check.

The campaign history stores hashed identity keys in the user's private state directory (`$XDG_STATE_HOME/authtempo/lockout-history.json`, or `~/.local/state/authtempo/lockout-history.json`). `AUTHTEMPO_HISTORY_PATH` can select a different private location. It is keyed by target and source user set, so separate output directories share safety history without storing plaintext usernames there.

## Password-change findings

`STATUS_PASSWORD_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, and Kerbrute's `KDC_ERR_KEY_EXPIRED` are valid credential evidence, not ordinary authentication failures. AuthTempo quarantines the identity from later spraying, highlights it as **change required**, and writes the credential plus an Impacket command to `password-change-required.txt`.

For plaintext passwords, the generated command deliberately prompts for the current and new passwords so they do not appear in shell history or the process list:

```bash
impacket-changepasswd -protocol smb-samr LAB/alice@10.10.10.10
```

Pass-the-hash findings require `-hashes`, so the generated command contains the recorded hash and must be handled as sensitive evidence.

AuthTempo cannot see policy details, replication delays, or server-side events that its tools do not report. Configure pacing and ceilings within the written rules of the assessment.

## Tool recovery in plain English

AuthTempo normally tries these chains:

- Kerbrute start: `kerbrute → nxc:ldap → nxc:smb`
- NetExec LDAP start: `nxc:ldap → kerbrute → nxc:smb`
- NetExec SMB start: `nxc:smb → kerbrute → nxc:ldap`
- Pass-the-hash: the selected NetExec protocol, then the other NetExec protocol

Authentication failures are results, not tool failures. Only network, process, output-integrity, or similar operational failures affect tool health.

| Option | What it means |
|---|---|
| `--tool-error-limit N` | Pause a tool after `N` consecutive temporary tool or network errors; default `2` |
| `--tool-retry-after GROUPS` | Retry a paused tool after this many completed password groups; default `3` |
| `--retry-paused-tools` | If every tool is paused, explicitly try each once instead of stopping |
| `--tool-timeout SECONDS` | Maximum total time for one identity/tool invocation; default `300` |
| `--tool-silence-timeout SECONDS` | Maximum time that invocation may produce no output; default `60` |

Tool health, fallback, retry, and restoration events are saved in state and the audit log.

The normal output calls unavailable tools **paused** and reports their retry delay in password groups. Internal state retains its machine-readable health fields, but operators do not need to interpret cooldown or demotion terminology.

## Complete option guide

Run `authtempo --advanced-help` for the authoritative list.

### Safety and recovery

| Option | Purpose |
|---|---|
| `--max-lockouts N` | Pause after more than `N` consecutive distinct locked identities; default `4` |
| `--tool-retry-after GROUPS` | Completed password groups before retrying a paused tool |
| `--tool-error-limit N` | Consecutive temporary errors allowed before pausing a tool |
| `--retry-paused-tools` | Explicitly try all tools once when each is currently paused |
| `--tool-timeout SECONDS` | Total time limit for one tool invocation |
| `--tool-silence-timeout SECONDS` | No-output time limit for one tool invocation |
| `--exact-domain-only` | Disable Kerbrute’s retry with a common alternate realm spelling |
| `--keep-testing-found` | **Unsafe:** keep testing a user after finding valid credentials |
| `--retry-uncertain` | **Unsafe:** retry a pair whose earlier result could not be reconciled |

### Scheduling, display, and troubleshooting

| Option | Purpose |
|---|---|
| `--schedule business-hours` | Run between 09:00 and 17:00 local time |
| `--schedule off-hours` | Run outside 09:00–17:00 local time |
| `--schedule HH:MM-HH:MM` | Use a custom local-time window, including overnight windows |
| `--stream` | Always use line-by-line output |
| `--dashboard` | Force the cursor-based dashboard, including inside tmux |
| `--display-lines N` | Structured activity lines retained in the compact dashboard; default `10` |
| `--nxc-path PATH` | Use a specific NetExec executable |
| `--kerbrute-path PATH` | Use a specific Kerbrute executable |
| `--skip-target-check` | Skip the DC/domain preflight check; not recommended |
| `-v`, `--verbose` | Show raw tool output, masked commands, domain retries, and failover hops |

## Compatibility names

Existing automation does not need an immediate rewrite. These older spellings remain accepted but are omitted from help so they do not crowd the operator interface.

| Older spelling | Preferred spelling |
|---|---|
| `--engine` | `--tool` |
| `--passes-per-batch` | `--limit` |
| `--review-after-lockouts`, `--pause-after-lockout-signals`, `--lockout-threshold` | Retired cumulative prompt; accepted only for saved-script compatibility |
| `--max-lockout-signals-per-pass`, `--max-lockouts-per-spray`, `--lockout-burst` | `--max-lockouts` |
| `--exclude-unknown-users`, `--filter-disabled` | `--validate-users` |
| `--export` | `--report` |
| `--log-dir` | `--output` |
| `--engine-skip-batches`, `--engine-skip-passes`, `--engine-cooldown` | `--tool-retry-after` |
| `--engine-fail-threshold` | `--tool-error-limit` |
| `--probe-demoted` | `--retry-paused-tools` |
| `--engine-timeout` | `--tool-timeout` |
| `--engine-idle-timeout` | `--tool-silence-timeout` |
| `--no-live` / `--live` | `--stream` / `--dashboard` |
| `--raw-lines`, `--feed-lines` | `--display-lines` |

The `authcadence`, `authcadence.py`, and `spraygun.py` launchers also remain as warning compatibility entry points.

## State and completion

State is written atomically. `--resume` checks the schema, target, input fingerprints, effective identity set, exact password order, safety settings, queue boundaries, quarantine, pair ledger, and tool health. Missing, corrupt, incomplete, or incompatible state is refused rather than silently treated as a new run.

Statistics separate authentication attempts sent from unique identity/password pairs. Pair outcomes are reported as valid, failed, safety-related, uncertain, or simulated, so a retry cannot make the outcome totals appear inconsistent.

`results.csv` contains one row for every recorded identity/password pair rather than only successful credentials. Its `password_pass` and `batch` columns make the execution order explicit, while `status`, `dispatches`, and timestamps expose failures and retries. The HTML report summarizes the same ledger by password pass and retains a compact event timeline.

A fully completed run exits `0`. A conservative stop with queued work exits `2`, including a lockout safety pause, failed target check, or enumeration safety signal. Configuration and fatal runtime errors exit `1`.

## Input files

Usernames are trimmed, comments and blank lines are skipped, and configured-domain aliases are de-duplicated case-insensitively while retaining the first display spelling.

Password whitespace is significant. A password line beginning with `#` is a comment; prefix it with `\#` for a literal leading hash. A space before `#` is literal data. Exact duplicate passwords are removed in first-seen order. Empty passwords and unsupported control characters are rejected.

## Sensitive output

Credentials stay visible at the top of the dashboard and are printed immediately in streaming mode. Routine failures and tool banners are summarized by default; raw lines remain in `authtempo.log` and can be displayed with `--verbose`. `creds.txt`, `password-change-required.txt`, the reports, and the audit log contain sensitive material. NetExec receives each candidate through a private one-line file. Kerbrute requires the candidate in its process arguments, so privileged local process inspection may observe it while the child is running.
