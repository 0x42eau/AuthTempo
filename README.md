# spraygun

Spraygun is a **resilient, operator-grade password-spray orchestrator** for authorized penetration testing. It wraps `nxc` (NetExec) and `kerbrute` with preflight checks, automatic failover between tools, **failover memory** (sticky engine health with cooldowns + probes), **kerbrute realm resilience**, lockout safety, a live `rich` terminal UI, and state persistence for resumable sprays.

A companion **`password_mutator.py`** generates targeted enterprise password lists from the domain/org name you give it — with leetspeak, acronyms, and editable building-block wordlists.

> For authorized penetration testing only. Use only on systems you have explicit written permission to test.

---

## Features

### Spraying engine (`spraygun.py`)
- **Multi-engine**: kerbrute (default) or nxc (SMB/LDAP), with automatic failover
- **Failover memory**: when an engine fails it's *demoted* for N rounds (exponential backoff), the working engine leads, and the failed one is *re-probed* after its cooldown — no more wasting every password on a dead engine
- **Kerbrute realm resilience**: auto-retries realm variants (as-given, UPPER, parent domain) and caches the working one, so a slightly-off `-d` no longer breaks kerbrute
- **No wrong-realm hard pause**: realm/KDC errors are handled via retry + demotion instead of blocking the run (only lockouts and all-engines-failed pause)
- **Preflight validation**: DC reachability + domain matching before spraying
- **Lockout safety**: burst hard-stop + cumulative interactive prompt
- **Credential-reuse matrix**: never re-attempts a (user, password) pair across resumes
- **Pattern learning**: re-prioritizes the live queue by which password patterns are hitting
- **Automatic throttling**: backs off inter-round delay when the DC is under stress (connection failures)
- **Spray window scheduling**: `business-hours`, `off-hours`, or a custom `HH:MM-HH:MM` window
- **Pass-the-hash mode**: spray NTLM hashes via `--pth` (nxc-only)
- **Live UI**: raw tool feed + summary + countdown; full decision log (realm attempts, demotions, effective chain, probes)
- **Timeline visualization**: self-contained HTML + JSON event log (`--timeline`)
- **State persistence**: resume canceled runs via `--resume`; corrupt-state safe
- **Dry-run mode**: test the full pipeline without a real target
- **Admin highlighting**: red ★ for high-privilege credentials

### Password mutator (`password_mutator.py`)
- **Variable-driven**: derives base names from what you actually provide — spaces in `--org`, separators (`-`/`_`) in the domain, or explicit `--keywords`. **Never guesses** word boundaries from keyword lists
- **Base-name transparency**: prints exactly which base names it derived so you can verify before spraying (`--show-bases`)
- **Leetspeak mutation**: bounded combinatorial leet per name (`Praeven → Pr43v3n, Praev3n, Pr4even, Pra3v3n`)
- **Acronyms**: `Praeven Security → PS`, `Some Random Company → SRC`
- **Editable wordlists/**: seasons, months, anchors, years, suffixes, common passwords, and the leet map are all text files you edit — no Python changes
- **Common-password floor**: common enterprise passwords are always included, even at small `--count`

---

## Quick start

```bash
pip install rich                                   # only Python dependency

# 1) Generate a targeted password list from the target's domain/org
python3 password_mutator.py -d sevenkingdoms.local --org "Seven Kingdoms" \
    --count 150 -o passwords.txt

# 2) Spray
python3 spraygun.py -u users.txt -p passwords.txt -d sevenkingdoms.local \
    -dc-ip 10.10.10.10 -t 35 --limit 2
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
python3 password_mutator.py -d praeven.org --org "Praeven" --leet-variants 12

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

Every building block lives in `wordlists/` as plain text (one token per line; `#` comments ignored). Edit them to match the target — no code changes. Each falls back to a built-in default if missing, so the mutator always works:

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

## spraygun usage

```bash
# Plaintext spray, kerbrute default
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 -t 35 --limit 2

# nxc SMB
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 \
    --tool nxc --protocol smb -t 30 --limit 1

# Pass-the-hash (NTLM hashes)
python3 spraygun.py -u users.txt -p hashes.txt -d LAB -dc-ip 10.10.10.10 --pth --tool nxc --protocol smb

# Dry-run (test UI/failover without a target)
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --dry-run

# Resume a canceled run
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --resume

# Filter non-existent accounts, export results, generate timeline
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 \
    --filter-disabled --export all --timeline

# Maximum verbosity (full masked commands, every failover hop)
python3 spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 -v
```

### spraygun CLI

**Required:** `-u` userlist, `-p` password/hash file, `-d` domain, `-dc-ip` DC IP

| Flag | Description |
|---|---|
| `--tool {kerbrute,nxc}` | spray engine (default kerbrute) |
| `--protocol {smb,ldap}` | protocol for nxc (default ldap; ignored for kerbrute) |
| `-t MINUTES` | minutes between rounds (default 35) |
| `--limit N` | passwords per round (default 2) |
| `--pth` | pass-the-hash mode (forces nxc, excludes kerbrute) |
| `--lockout-threshold N` | cumulative lockouts before interactive prompt (default 2) |
| `--lockout-burst N` | lockouts in one round that hard-stop the run (default 5) |
| `--conn-fail-limit N` | *(deprecated)* tracked for throttling; engines no longer abort on conn failures |
| `--filter-disabled` | pre-spray kerbrute userenum to drop non-existent accounts |
| `--export {none,json,csv,all}` | results export format (default none) |
| `--schedule {preset\|HH:MM-HH:MM}` | spray window: `business-hours`, `off-hours`, or range |
| `--timeline` | generate `spray-timeline.html` |
| `--feed-lines N` | raw-feed panel height (default 50) |
| `--engine-cooldown N` | rounds to skip a demoted engine before re-probe (default 3) |
| `--engine-fail-threshold N` | consecutive transient failures before demoting (default 2) |
| `--no-realm-retry` | disable kerbrute realm-variant auto-retry |
| `-v`, `--verbose` | maximum verbosity (masked commands, every realm/failover/probe event) |
| `--nxc-path`, `--kerbrute-path` | override binary paths |
| `--no-preflight` | skip DC/domain preflight (discouraged) |
| `--log-dir DIR` | output/state directory (default `./spraygun-out`) |
| `--dry-run` | emit fake tool output; no real sprays |
| `--resume` | continue from saved state |

---

## Failover memory & engine health

Engines are tracked for health across the run. When an engine aborts:

- **Permanent errors** (wrong-realm, binary-not-found) demote **immediately**
- **Transient errors** (timeout, exception) demote after `--engine-fail-threshold` consecutive failures (default 2)
- A demoted engine is moved to the **end** of the per-password chain and skipped for `--engine-cooldown` rounds (exponential backoff, capped), then **re-probed**
- On a successful probe it's **restored** to the leading position

Every decision is printed (verbosity-first): each realm attempt and accept/reject, demotions with reason + cooldown, the round-by-round effective chain, per-password failover hops, and probe/restore events. `--verbose` adds full masked commands.

**Failover chains:**
- kerbrute start: `kerbrute → nxc:ldap → nxc:smb`
- nxc SMB start: `nxc:smb → kerbrute → nxc:ldap`
- nxc LDAP start: `nxc:ldap → kerbrute → nxc:smb`
- PTH mode: `nxc:<chosen> → nxc:<other>` (kerbrute excluded)

**Only two conditions pause for the operator:** lockouts hitting a threshold, and *all* engines failing for a password. Realm/KDC errors no longer pause — they're handled by retry + demotion so the run continues on the working engine.

---

## Output & state files

All output goes to `./spraygun-out/` (or `--log-dir`):

| File | Contents |
|---|---|
| `spraygun.state.json` | resume blob (cred matrix, patterns, stats, throttle, engine health, realm memory, timeline) |
| `creds.txt` | human-readable `user:password` hits |
| `locked-out.txt` | locked-out accounts |
| `used-passwords.txt` | passwords/hashes already sprayed |
| `spraygun-spray.log` | timed audit log (every raw line) |
| `active-users.txt` | filtered user list (with `--filter-disabled`) |
| `results.json` / `results.csv` | structured exports (with `--export`) |
| `timeline.json` | machine-readable event log (always generated) |
| `spray-timeline.html` | self-contained visualization (with `--timeline`) |

`--resume` is **corrupt-state safe**: if the state file is truncated/corrupt (e.g. process killed mid-write), it's backed up to `spraygun.state.json.corrupt` and the run starts fresh instead of crashing. Stale engine-health entries for engines no longer in the chain are pruned on resume.

---

## Safety features

- **Preflight**: validates DC reachability and domain matching before spraying
- **Burst lockout detection**: hard-stops if ≥ 5 accounts lock in a single round
- **Cumulative lockout threshold**: pauses for confirmation when ≥ 2 accounts lock overall
- **Credential-reuse matrix**: never re-attempts a tried (user, password) pair
- **Automatic throttling**: backs off under DC connection stress

---

## Installation

```bash
pip install rich        # only Python dependency
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
spraygun.py            # spraying orchestrator (stdlib + rich)
password_mutator.py    # variable-driven password list generator
wordlists/             # editable building blocks (seasons, months, anchors, years, suffixes, common, leet)
users.txt              # sample userlist (replace with your target's users)
passwords.txt          # sample spray list (regenerate with password_mutator.py)
spraygun.sh            # original v0.4 shell prototype (historical)
spraygun-out/          # runtime output/state (gitignored)
```

## For authorized use only

Spraygun is designed for authorized penetration testing and security assessments. Use only on systems you have explicit permission to test. Unauthorized password spraying is illegal.

## License

Same as the original spraygun.sh project.
