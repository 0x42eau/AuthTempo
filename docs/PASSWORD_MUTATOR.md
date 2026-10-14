# Password mutator guide

`password_mutator.py` creates a bounded, target-specific list from values you provide. It does not guess where words split inside a compound name.

## Quick start

```bash
python3 password_mutator.py -d sevenkingdoms.local \
  --org "Seven Kingdoms" --count 150 -o passwords.txt
```

Base names come from:

1. words in `--org "Seven Kingdoms"`;
2. `-` and `_` separators in the domain;
3. explicit comma-separated `--keywords`.

Use `--show-bases` to inspect them without generating a list:

```text
$ python3 password_mutator.py -d sevenkingdoms.local --org "Seven Kingdoms" --show-bases
[*] Base names derived (3): Seven, SK*, SevenKingdoms  (* = acronym)
[*] Leetspeak: ON (use --no-leet to disable)
```

A domain label with no separator is one word. Supply `--org` or `--keywords` when you want explicit component words.

## Examples

```bash
# Add explicit target terms
python3 password_mutator.py -d contoso.local --keywords contoso,contosocorp

# Require at least 12 characters and cap the result at 200
python3 password_mutator.py -d contoso.local --length 12 --count 200

# Create more leetspeak forms per base name
python3 password_mutator.py -d contoso.org --org "Contoso" --leet-variants 12

# Use engagement-specific building blocks
python3 password_mutator.py -d contoso.local --wordlist-dir ./my_lists

# Disable leetspeak
python3 password_mutator.py -d contoso.local --no-leet
```

## Options

| Option | Meaning |
|---|---|
| `-d`, `--domain` | Active Directory domain |
| `--org` | Organization name; spaces define component words |
| `--year` | Primary target year; default is the current year |
| `--count` | Hard maximum output count; default `100` |
| `-l`, `--length` | Minimum password length; default `0` |
| `-o`, `--output` | Output file; default is stdout |
| `--keywords` | Explicit extra base terms, comma-separated |
| `--wordlist-dir` | Building-block directory; default `./wordlists` |
| `--no-leet` | Disable leetspeak forms |
| `--leet-variants` | Maximum leet forms for each base; default `8` |
| `--show-bases` | Show derived bases and exit |

## Editable building blocks

Every list is plain text, one value per line. Comments begin with `#`, except a line containing only `#` in `suffixes.txt`, which represents a literal suffix.

| File | Used for |
|---|---|
| `seasons.txt` | Seasonal forms with name and year |
| `months.txt` | Month and year forms |
| `anchors.txt` | Words attached to the target name |
| `years.txt` | Supplementary or historical years |
| `suffixes.txt` | Punctuation and separators |
| `common_passwords.txt` | Baseline common enterprise candidates |
| `leet.txt` | Character substitution map |

Missing files fall back to built-in defaults, so a partial custom directory remains usable.
