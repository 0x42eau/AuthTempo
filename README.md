# spraygun

Spraygun is a resilient password-spray orchestrator for authorized penetration testing. It wraps `nxc` (NetExec) and `kerbrute` with preflight checks, automatic failover between tools, lockout safety mechanisms, a live rich terminal UI, and state persistence for resumable sprays.

## Features

- **Multi-engine support**: kerbrute (default) or nxc (SMB/LDAP)
- **Automatic failover**: if an engine fails (connection storms, NetBIOS timeouts), it automatically switches to the next tool in the chain
- **Preflight validation**: checks DC reachability and domain matching before spraying
- **Lockout safety**: detects lockouts with two safety thresholds (burst hard-stop, interactive prompt)
- **Pass-the-hash mode**: spray NTLM hashes via `--pth` (nxc-only)
- **Pretty live UI**: raw tool feed + credential/lockout summary + MM:SS countdown between rounds
- **State persistence**: resume canceled runs via `--resume`
- **Dry-run mode**: test the full pipeline without a real target
- **Admin user highlighting**: red ★ icons for high-privilege credentials when nxc outputs `(Pwn3d!)` or admin indicators
- **Password mutator**: generate domain-specific password patterns (Company2026!, WelcomeOrg!)

## Password Mutator

Use the included `password_mutator.py` to generate targeted enterprise password lists based on domain/organization names:

```bash
# Generate domain-specific passwords
python3 password_mutator.py --domain contoso.local --year 2026 --count 100 -o passwords.txt

# With explicit organization name
python3 password_mutator.py --domain sevenkingdoms.local --org "Lannister Corp" -o passwords.txt
```

This generates patterns like:
- `WelcomeContoso2026!`, `PasswordContoso2026!`
- `SummerContoso2026!`, `WinterContoso2026!`
- `IloveContoso123!`, `Contoso@2026`

These are the **highest-probability** passwords in enterprise environments — company names, seasonal patterns, and current year variations.

## Installation

### Python dependency

```bash
pip install rich
```

### External tools

Install at least one of the spray engines (both recommended for full failover):

**NetExec (nxc):**
```bash
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```

**Kerbrute:**
```bash
# Download from https://github.com/ropnop/kerbrute/releases
# Or build from source
go install github.com/ropnop/kerbrute@latest
```

## Usage

### Basic password spray (kerbrute, default)

```bash
./spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 -t 35 --limit 2
```

### nxc SMB mode

```bash
./spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --tool nxc --protocol smb -t 30 --limit 1
```

### Pass-the-hash mode

```bash
./spraygun.py -u users.txt -p hashes.txt -d LAB -dc-ip 10.10.10.10 --pth --tool nxc --protocol smb
```

### With password mutator (generate domain-specific passwords)

```bash
# Generate targeted password list, then spray
python3 password_mutator.py --domain contoso.local --year 2026 --count 50 -o passwords.txt
./spraygun.py -u users.txt -p passwords.txt -d CONTOSO -dc-ip 10.10.10.10
```

### Dry-run (test UI/failover without a target)

```bash
./spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --dry-run
```

### Resume a canceled run

```bash
./spraygun.py -u users.txt -p passwords.txt -d LAB -dc-ip 10.10.10.10 --resume
```

## CLI Options

### Required
- `-u USERS` — userlist file (one per line)
- `-p PASSWORDS` — password or hash file (one per line)
- `-d DOMAIN` — domain name
- `-dc-ip DCIP` — domain controller IP

### Tool selection
- `--tool {kerbrute,nxc}` — spray engine (default: kerbrute)
- `--protocol {smb,ldap}` — protocol for nxc (default: ldap; ignored for kerbrute)

### Timing & policy
- `-t MINUTES` — lockout window between rounds (default: 35)
- `--limit N` — passwords sprayed per round (default: 2)

### Modes
- `--pth` — pass-the-hash mode: `-p` file contains NTLM hashes, forces nxc, excludes kerbrute

### Safety thresholds (with defaults)
- `--lockout-threshold N` — cumulative lockouts before interactive prompt (default: 2)
- `--lockout-burst N` — lockouts in a single round that hard-stop the run (default: 5)
- `--conn-fail-limit N` — connection failures before aborting an engine (default: 10)

### Overrides & debugging
- `--nxc-path PATH` — override path to nxc/netexec binary
- `--kerbrute-path PATH` — override path to kerbrute binary
- `--no-preflight` — skip DC/domain preflight (discouraged)
- `--log-dir DIR` — output/state directory (default: ./spraygun-out)

### Testing & resume
- `--dry-run` — emit fake tool output; no real sprays
- `--resume` — continue from saved state

## Output & State Files

All output goes to `./spraygun-out/` (or `--log-dir`):

- `spraygun.state.json` — machine-readable resume blob
- `creds.txt` — human-readable `user:password` hits
- `locked-out.txt` — locked-out accounts
- `used-passwords.txt` — passwords/hashes already sprayed
- `spraygun-spray.log` — overall timed audit log (every raw line with timestamps)

## Failover Chain

The tool automatically falls back through engines when one fails:

- **Starting with nxc SMB**: `nxc:smb` → `kerbrute` → `nxc:ldap`
- **Starting with nxc LDAP**: `nxc:ldap` → `kerbrute` → `nxc:smb`
- **Starting with kerbrute**: `kerbrute` → `nxc:ldap` → `nxc:smb`
- **PTH mode**: `nxc:<chosen protocol>` → `nxc:<other protocol>` (kerbrute excluded)

If an engine hits the connection-failure limit (default: 10 per-user timeouts in one spray), it aborts and the next tool in the chain takes over for the same password.

## Safety Features

- **Preflight**: validates DC reachability and domain matching before spraying
- **Burst lockout detection**: hard-stops if >= 5 accounts lock out in a single round
- **Cumulative lockout threshold**: pauses for confirmation when >= 2 accounts lock overall
- **Connection-storm detection**: aborts engines with NetBIOS/connection errors and fails over

## For Authorized Use Only

Spraygun is designed for authorized penetration testing and security assessments. Use only on systems you have explicit permission to test.

## License

Same as the original spraygun.sh project.
