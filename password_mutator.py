#!/usr/bin/env python3
"""
password_mutator.py — Domain-based password mutator for spraygun

Generates common enterprise password patterns based on domain/organization names.
Integrates with spraygun.py or can be used standalone.

Usage:
    python3 password_mutator.py --domain contoso.local --org "Contoso Corp"
    python3 password_mutator.py --domain sevenkingdoms.local --year 2026
"""

import argparse
import re
import sys
from itertools import combinations
from pathlib import Path
from typing import List, Set, Optional, Tuple, Dict

# ---------------------------------------------------------------------------
# Word lists — single source of truth for generic corporate vocabulary.
# Used both to strip trailing suffix words (org path) and to split domain
# labels that have no spaces (domain-only fallback). NOT used to guess word
# boundaries when an explicit spaced org name is supplied — the spaces do that.
# ---------------------------------------------------------------------------
GENERIC_SUFFIX_WORDS: Set[str] = {
    # corporate-form suffixes
    "company", "companies", "corp", "corporation", "inc", "incorporated",
    "llc", "ltd", "limited", "co", "group", "holdings", "partners",
    "enterprises", "solutions", "services", "technologies", "technology",
    "tech", "systems", "global", "international", "consulting", "advisory",
    "foundation", "association", "authority", "bureau", "office", "department",
    "enterprises", "trading", "imports", "exports",
    # industry / sector words (often the generic tail of a name)
    "security", "secure", "cyber", "digital", "defense", "defence",
    "network", "networks", "software", "labs", "works", "dynamics",
    "energy", "financial", "finance", "bank", "banking", "media",
    "health", "healthcare", "motors", "foods", "airlines", "express",
    # misc common tails seen in real org names
    "bros", "kingdoms",
}

# Leading words to drop ("The Acme Corp" -> ["Acme", "Corp"])
GENERIC_LEADING_WORDS: Set[str] = {"the"}

# TLDs / pseudo-TLDs to drop when deriving a base name from a domain
TLDS: Set[str] = {
    "local", "com", "net", "org", "int", "io", "co", "dev", "internal",
    "lan", "corp", "ad", "intra", "test", "example", "pvt",
}

# Default location of the editable building-block files.
WORDLIST_DIR_DEFAULT: Path = Path(__file__).resolve().parent / "wordlists"

# ---------------------------------------------------------------------------
# Built-in defaults for the editable wordlists. Used when a wordlist file is
# missing or empty, so the mutator always works out of the box. The shipped
# wordlists/*.txt mirror these exactly.
# ---------------------------------------------------------------------------
DEFAULT_SEASONS: List[str] = ["Summer", "Winter", "Spring", "Fall", "Autumn"]
DEFAULT_MONTHS: List[str] = ["January", "February", "March", "April", "May", "June",
                             "July", "August", "September", "October", "November", "December"]
DEFAULT_ANCHORS: List[str] = ["Welcome", "Password", "P@ssw0rd", "Corporate", "Company", "Ilove", "ILove"]
DEFAULT_SUFFIXES: List[str] = ["!", "!@#", "!!", "@", "-", "_", ".", "1!", "123!", "#"]
DEFAULT_COMMON: List[str] = [
    "Password123!", "Password123!@#", "P@ssw0rd123!", "Password1!", "P@ssw0rd!",
    "Welcome123!", "Welcome123!@#", "Welcome1!", "Welcome!", "Changeme!", "ChangeMe!",
    "Changeme1!", "Corporate123!", "Company123!", "Office365!",
    "password", "password1", "password123!", "P@ssw0rd", "Welcome123",
    "admin", "administrator", "123456",
]
# Leet map: char -> [primary_replacement, alternates...]
DEFAULT_LEET: Dict[str, List[str]] = {
    "a": ["4", "@"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
    "s": ["5", "$"], "t": ["7"], "g": ["9"], "b": ["8"],
}


def _load_wordlist(path: Path, default: List[str]) -> List[str]:
    """Load a newline-delimited wordlist, ignoring blanks and '#'-comments. Falls back to default."""
    try:
        if not path.exists():
            return list(default)
        items = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            items.append(line)
        return items if items else list(default)
    except OSError:
        return list(default)


def _load_leet_map(path: Path, default: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Load a 'char=repl1,repl2' leet map. Falls back to default."""
    try:
        if not path.exists():
            return {k: list(v) for k, v in default.items()}
        out: Dict[str, List[str]] = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            ch, _, repls = line.partition("=")
            ch = ch.strip().lower()
            vals = [r.strip() for r in repls.split(",") if r.strip()]
            if ch and vals:
                out[ch] = vals
        return out if out else {k: list(v) for k, v in default.items()}
    except OSError:
        return {k: list(v) for k, v in default.items()}


class PasswordMutator:
    """Generate enterprise-style password mutations from domain/org names."""

    def __init__(self, domain: str = "", org: str = "", year: int = 2026,
                 wordlist_dir: Optional[str] = None,
                 leet: bool = True, leet_variants: int = 8,
                 keywords: Optional[List[str]] = None):
        """
        Initialize mutator with domain and organization info.

        Args:
            domain: Active Directory domain (e.g., "contoso.local")
            org: Organization name (e.g., "Contoso Corporation")
            year: Target year for seasonal passwords (default: 2026)
            wordlist_dir: directory of editable building-block files
                          (default: ./wordlists next to this script)
            leet: generate leetspeak variants of the org/domain name (default True)
            leet_variants: max leet forms per base name (default 8)
            keywords: extra operator-signified base tokens to mutate on
                      (e.g. ["seven", "sevenkingdoms"]). Word boundaries in a
                      keyword come from spaces, exactly like --org.
        """
        self.domain = domain.strip()
        self.org = org.strip() if org else ""
        self.year = year
        self.leet_enabled = leet
        self.leet_variants = leet_variants
        self.keywords: List[str] = [k.strip() for k in (keywords or []) if k and k.strip()]

        # Load editable building blocks (fall back to built-in defaults).
        wl = Path(wordlist_dir) if wordlist_dir else WORDLIST_DIR_DEFAULT
        self.seasons = _load_wordlist(wl / "seasons.txt", DEFAULT_SEASONS)
        self.months = _load_wordlist(wl / "months.txt", DEFAULT_MONTHS)
        self.anchors = _load_wordlist(wl / "anchors.txt", DEFAULT_ANCHORS)
        self.suffixes = _load_wordlist(wl / "suffixes.txt", DEFAULT_SUFFIXES)
        self.hist_years = _load_wordlist(wl / "years.txt",
                                         [str(self.year - i) for i in range(1, 5)])
        self.common_floor = _load_wordlist(wl / "common_passwords.txt", DEFAULT_COMMON)
        self.leet_map = _load_leet_map(wl / "leet.txt", DEFAULT_LEET) if leet else {}

        # Derive base names once: ordered list of (priority, canonical_name, is_acronym).
        # Lower priority number = emitted earlier (higher probability).
        self.base_names: List[Tuple[int, str, bool]] = self._derive_base_names()

    # ===================================================================
    # Tokenization — observed variables, not keyword guessing
    # ===================================================================

    def _tokenize_org(self, org: str) -> List[str]:
        """Split an explicit org name on whitespace into clean words."""
        if not org:
            return []
        # Collapse internal whitespace, strip leading/trailing
        raw = [w.strip() for w in re.split(r"\s+", org.strip()) if w.strip()]
        words = []
        for w in raw:
            # Strip surrounding punctuation (quotes, commas) but keep internal chars
            w = w.strip("\"\t,;:.()[]{}").strip()
            if w:
                words.append(w)
        # Drop a single leading generic word ("The Acme" -> "Acme")
        if len(words) > 1 and words[0].lower() in GENERIC_LEADING_WORDS:
            words = words[1:]
        return words

    def _strip_generic_suffix(self, words: List[str]) -> List[str]:
        """Drop trailing generic corporate words, always keeping >= 1 word."""
        out = list(words)
        while len(out) > 1 and out[-1].lower() in GENERIC_SUFFIX_WORDS:
            out.pop()
        return out

    @staticmethod
    def _camel_from_words(words: List[str]) -> str:
        """Build camelCase from explicit words: ['Praeven','Security'] -> 'PraevenSecurity'."""
        return "".join(w[:1].upper() + w[1:].lower() for w in words if w)

    @staticmethod
    def _acronym(words: List[str]) -> Optional[str]:
        """First letters of significant words. Only when >= 2 words."""
        sig = [w for w in words if w]
        if len(sig) < 2:
            return None
        return "".join(w[0].upper() for w in sig)

    def _domain_labels(self, domain: str) -> List[str]:
        """Domain labels minus TLDs and trivial tokens (no spaces expected)."""
        if not domain:
            return []
        parts = [p.strip().lower() for p in domain.split(".") if p.strip()]
        return [p for p in parts if p not in TLDS and len(p) > 2]

    def _split_domain_label(self, label: str) -> List[str]:
        """
        Split a domain label ONLY on explicit separators (hyphen / underscore).
        A space-less label is kept as ONE word — the operator signifies compound
        boundaries via --org ("Seven Kingdoms") or --keywords, not by the tool
        guessing. No suffix/vowel heuristics.

        'seven-kingdoms' -> ['Seven','Kingdoms'] ; 'sevenkingdoms' -> ['Sevenkingdoms']
        """
        if not label:
            return []
        low = label.lower()
        if re.search(r"[-_]", low):
            return [w[:1].upper() + w[1:].lower()
                    for w in re.split(r"[-_]+", low) if w]
        return [label[:1].upper() + label[1:].lower()]

    def _derive_base_names(self) -> List[Tuple[int, str, bool]]:
        """
        Produce an ordered, de-duplicated list of (priority, canonical_name, is_acronym).

        Word boundaries come ONLY from what the operator signifies: spaces in
        --org, separators (-/_) in the domain, or explicit --keywords. The tool
        never guesses compound splits from a single token.

        Priority: 1=distinctive/keyword, 2=acronym, 3=full name, 4+=domain base.
        """
        names: List[Tuple[int, str, bool]] = []
        seen: Set[str] = set()

        def add(prio: int, name: Optional[str], is_acronym: bool = False):
            if not name:
                return
            key = name.lower()
            if key in seen or key == "":
                return
            seen.add(key)
            names.append((prio, name, is_acronym))

        def add_word_group(words: List[str], base_prio: int):
            """Full pipeline for an explicitly-signified word group."""
            if not words:
                return
            # Distinctive name (trailing generic suffix stripped)
            stripped = self._strip_generic_suffix(words)
            add(base_prio, self._camel_from_words(stripped))
            # Acronym (only if >= 2 significant words)
            add(base_prio + 1, self._acronym(words), is_acronym=True)
            # Full name (no stripping)
            add(base_prio + 2, self._camel_from_words(words))

        org_words = self._tokenize_org(self.org)
        explicit_given = bool(org_words or self.keywords)

        # 1. Explicit org name (highest priority).
        if org_words:
            add_word_group(org_words, 1)

        # 2. Explicit keywords (operator-signified tokens, same high priority).
        for kw in self.keywords:
            kw_words = self._tokenize_org(kw)
            if kw_words:
                add_word_group(kw_words, 1)
            elif kw:
                # Single bare token (no spaces) -> one base name, no guessing.
                add(1, kw[:1].upper() + kw[1:].lower())

        # 3. Domain base(s). Supplementary (offset 3) when an org/keyword was
        # given; primary (offset 0) when the domain is the only signal.
        offset = 3 if explicit_given else 0
        for label in self._domain_labels(self.domain):
            words = self._split_domain_label(label)
            if not words:
                continue
            if len(words) > 1:
                # Separators signalled multiple words -> full pipeline.
                add_word_group(words, 1 + offset)
            else:
                # Single label -> one base name (no compound guessing).
                add(1 + offset, words[0])

        return names

    def _casing_variants(self, name: str, acronym: bool = False) -> List[str]:
        """
        Casing variants of a canonical name.
        Acronyms stay uppercase only; full names get {as-given, UPPER, lower}.
        """
        if acronym:
            return [name.upper()]
        variants = [name]
        if len(name) > 1:
            variants.append(name.upper())
            variants.append(name.lower())
        # Order-preserving dedupe
        out: List[str] = []
        for v in variants:
            if v not in out:
                out.append(v)
        return out

    def _leet_variants(self, name: str, max_variants: int = 8) -> List[str]:
        """
        Bounded combinatorial leetspeak of a name.

        For each leetable char (per self.leet_map), choose substitute-or-not
        across the power set of positions, preferring larger (more complete)
        substitutions first. Uses the PRIMARY replacement per char so output is
        deterministic. Capped at max_variants. e.g. Praeven ->
        Pr43v3n, Pra3v3n, Pr4even, Praev3n, Pra3ven, Pr43ven, Pr4ev3n.

        Does NOT mutate acronyms. Returns [] if leet disabled or no leetable char.
        """
        if not self.leet_enabled or not self.leet_map or len(name) < 3:
            return []
        low = name.lower()
        # Positions of leetable chars and their primary replacement.
        positions = [(i, c, self.leet_map[c][0])
                     for i, c in enumerate(low) if c in self.leet_map and self.leet_map[c]]
        if not positions:
            return []

        variants: List[str] = []
        seen: Set[str] = set()
        n = len(positions)
        # Iterate subset sizes from largest (full leet) down to 1, so the most
        # "complete" leet forms come first within the cap.
        for size in range(n, 0, -1):
            for combo in combinations(positions, size):
                arr = list(name)
                for i, _c, repl in combo:
                    arr[i] = repl
                candidate = "".join(arr)
                # Preserve leading capital on the camelCase form.
                if candidate and candidate[0].isalpha():
                    candidate = candidate[0].upper() + candidate[1:]
                if candidate.lower() not in seen and candidate.lower() != low:
                    seen.add(candidate.lower())
                    variants.append(candidate)
                    if len(variants) >= max_variants:
                        return variants
        return variants

    def generate(self, count: int = 100) -> List[str]:
        """
        Generate password mutations ordered by probability.

        Base names are derived from observed variables (spaced org words /
        domain labels), never keyword-guessed. A floor of common enterprise
        passwords is always included even when count is small.

        Returns:
            List of generated passwords (duplicates removed)
        """
        # (priority, password, force_include?) - lower priority = higher probability
        passwords: List[Tuple[int, str, bool]] = []

        # Single non-alphanumeric suffixes double as name<->year separators.
        separators = [s for s in self.suffixes if len(s) == 1 and not s.isalnum()]
        primary_finale = self.suffixes[0] if self.suffixes else "!"
        top_anchors = self.anchors[:3]

        def add(prio: int, pwd: str, force: bool = False):
            passwords.append((prio, pwd, force))

        # Per-base-name CORE forms guaranteed to appear regardless of --count,
        # so EVERY observed variable is mutated (seven AND sevenkingdoms).
        core_forced: List[str] = []

        # ---- Org/domain-derived patterns -----------------------------------
        # Each base name's priority comes from _derive_base_names; pattern
        # templates add a small offset so the distinctive name leads.
        for base_prio, name, is_acronym in self.base_names:
            variants = self._casing_variants(name, acronym=is_acronym)
            # Guarantee core forms for this base name (all casings).
            for variant in variants:
                core_forced.append(f"{variant}{self.year}{primary_finale}")
                core_forced.append(f"{variant}{primary_finale}")
            core_forced.append(f"Welcome{name}{self.year}{primary_finale}")
            # Guarantee the densest leet form too (leet otherwise gets truncated
            # at small --count by priority sorting).
            if self.leet_enabled and not is_acronym:
                leets = self._leet_variants(name, self.leet_variants)
                if leets:
                    core_forced.append(f"{leets[0]}{self.year}{primary_finale}")
                    core_forced.append(f"{leets[0]}{primary_finale}")
            # Full template fanout.
            for variant in variants:
                p = base_prio
                # anchor + name + year (WelcomePraeven2026!)
                for anchor in self.anchors:
                    add(p, f"{anchor}{variant}{self.year}{primary_finale}")
                    add(p, f"{anchor}{variant}{self.year}")
                # name + year + finale (each finale)
                for suf in self.suffixes:
                    add(p, f"{variant}{self.year}{suf}")
                add(p, f"{variant}{self.year}")
                # name + finale
                for suf in self.suffixes:
                    add(p, f"{variant}{suf}")
                # name + separator + year (Praeven@2026)
                for sep in separators:
                    add(p, f"{variant}{sep}{self.year}")
                # season + name
                for season in self.seasons:
                    add(p, f"{season}{variant}{primary_finale}")
                    add(p, f"{season}{variant}{self.year}{primary_finale}")
                # name + common-password combos (longer, lower tier)
                add(p + 2, f"{variant}Password123!")
                add(p + 2, f"Password{variant}{self.year}!")
                add(p + 2, f"{variant}{self.year}Password!")

        # ---- Leetspeak variants of distinctive/full names -----------------
        # Reduced template set at one tier below the plain name to bound size.
        for base_prio, name, is_acronym in self.base_names:
            if is_acronym:
                continue
            for leet in self._leet_variants(name, self.leet_variants):
                p = base_prio + 1
                for suf in self.suffixes:
                    add(p, f"{leet}{self.year}{suf}")
                add(p, f"{leet}{self.year}")
                for suf in self.suffixes:
                    add(p, f"{leet}{suf}")
                for anchor in top_anchors:
                    add(p, f"{anchor}{leet}{self.year}{primary_finale}")

        # ---- Seasonal / monthly + year (no org) ----------------------------
        for season in self.seasons:
            add(2, f"{season}{self.year}!")
            add(2, f"{season}{self.year}")
        for month in self.months:
            add(2, f"{month}{self.year}!")
            add(2, f"{month}{self.year}")

        # ---- Common enterprise passwords (FORCE-INCLUDED floor) ------------
        for pwd in self.common_floor:
            add(3, pwd, force=True)

        # ---- Prior years (from wordlists/years.txt) ------------------------
        for y in self.hist_years:
            add(4, f"Welcome{y}!")
            add(4, f"Summer{y}!")
            add(4, f"Winter{y}!")
            add(4, f"Password{y}!")
            for _prio, name, is_acronym in self.base_names:
                if is_acronym:
                    continue
                add(4, f"{name}{y}!")

        # ---- Dedupe (case-sensitive to keep casing variants) + sort -------
        seen: Set[str] = set()
        unique: List[Tuple[int, str, bool]] = []
        for prio, pwd, force in passwords:
            if pwd in seen:
                continue
            seen.add(pwd)
            unique.append((prio, pwd, force))

        def sort_key(x):
            prio, pwd, _ = x
            # Secondary sort: Welcome/Seasonal/Month prefix patterns first
            prefix = pwd.startswith(("Welcome", "Spring", "Summer", "Winter",
                                     "Fall", "Autumn")) or pwd[:3] in {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
            return (prio, 0 if prefix else 1, len(pwd))

        unique.sort(key=sort_key)

        result = [pwd for _, pwd, _ in unique][:count]

        # ---- Enforce floors: common passwords + per-base-name core forms ---
        present = set(result)
        for pwd in self.common_floor + core_forced:
            if pwd not in present:
                result.append(pwd)
                present.add(pwd)

        return result

    def generate_list(self, count: int = 100, min_length: int = 0) -> List[str]:
        """
        Generate and return password list.

        Args:
            count: Maximum passwords to return
            min_length: Minimum password length (filters out shorter passwords)

        Returns:
            List of generated passwords. If min_length > 0, generates the full
            set of patterns and filters to those meeting the minimum length.
        """
        if min_length == 0:
            # No filtering, generate exactly what was requested
            return self.generate(count)

        # With minimum length filter: generate ALL patterns, filter by length, then limit
        # Generate a large number to get all unique patterns
        all_passwords = self.generate(5000)
        # Filter by minimum length
        filtered = [pwd for pwd in all_passwords if len(pwd) >= min_length]
        # Return up to count (may be fewer if not enough patterns meet the length requirement)
        return filtered[:count]


def main():
    parser = argparse.ArgumentParser(
        description="Generate enterprise password mutations from domain/organization names",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate passwords for contoso.local domain
  python3 password_mutator.py --domain contoso.local

  # Generate with explicit organization name
  python3 password_mutator.py --domain sevenkingdoms.local --org "Lannister Corp"

  # Generate for a specific year
  python3 password_mutator.py --domain contoso.local --year 2025 --count 50

  # Output directly to a file
  python3 password_mutator.py --domain contoso.local -o passwords_generated.txt

  # Filter by minimum length (password policy compliance)
  python3 password_mutator.py --domain contoso.local --length 12 --count 100

  # Leetspeak variants (Praeven -> Pr43v3n, Praev3n, ...)
  python3 password_mutator.py --domain praeven.org --org "Praeven" --leet-variants 12

  # Use a custom set of building-block files
  python3 password_mutator.py --domain contoso.local --wordlist-dir ./my_lists

  # Disable leetspeak
  python3 password_mutator.py --domain contoso.local --no-leet

  # Explicit extra base tokens to mutate (operator signifies the words)
  python3 password_mutator.py --domain sevenkingdoms.local --keywords seven,sevenkingdoms

  # Check exactly which base names the mutator derived, without generating
  python3 password_mutator.py --domain sevenkingdoms.local --org "Seven Kingdoms" --show-bases
        """
    )

    parser.add_argument("-d", "--domain", help="Active Directory domain (e.g., contoso.local)")
    parser.add_argument("--org", help="Organization name (e.g., 'Contoso Corporation')")
    parser.add_argument("--year", type=int, default=2026, help="Target year (default: 2026)")
    parser.add_argument("--count", type=int, default=100, help="Max passwords to generate (default: 100)")
    parser.add_argument("-l", "--length", type=int, default=0, help="Minimum password length (default: 0, no filter)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")
    parser.add_argument("--wordlist-dir", default=None,
                        help="Directory of editable building-block files (default: ./wordlists)")
    parser.add_argument("--no-leet", action="store_true",
                        help="Disable leetspeak variants of the org/domain name")
    parser.add_argument("--leet-variants", type=int, default=8,
                        help="Max leet forms per base name (default: 8)")
    parser.add_argument("--keywords", default="",
                        help="Extra base tokens to mutate on, comma-separated "
                             "(e.g. --keywords seven,sevenkingdoms). Spaces inside "
                             "a token split it into words, like --org.")
    parser.add_argument("--show-bases", action="store_true",
                        help="Print the derived base names and exit (dry check)")

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        print("\n[!] Error: --domain is required", file=sys.stderr)
        sys.exit(1)

    keywords = [k for k in (args.keywords.split(",") if args.keywords else []) if k.strip()]

    # Generate passwords
    mutator = PasswordMutator(domain=args.domain, org=args.org, year=args.year,
                              wordlist_dir=args.wordlist_dir,
                              leet=not args.no_leet, leet_variants=max(0, args.leet_variants),
                              keywords=keywords)

    # Always show the operator exactly which base names were derived (to stderr,
    # so stdout stays clean for piping). This is the guidance surface: if the
    # parsed bases are wrong, fix --org / --keywords / domain separators.
    has_acronym = any(a for _p, _n, a in mutator.base_names)
    bases = [f"{n}{'*' if a else ''}" for _p, n, a in mutator.base_names]
    if bases:
        legend = "  (* = acronym)" if has_acronym else ""
        print(f"[*] Base names derived ({len(bases)}): {', '.join(bases)}{legend}",
              file=sys.stderr)
        if keywords:
            print(f"[*] Keywords: {', '.join(keywords)}", file=sys.stderr)
        if not args.no_leet and any(not a for _p, n, a in mutator.base_names):
            print("[*] Leetspeak: ON (use --no-leet to disable)", file=sys.stderr)
        if not has_acronym and not args.org and not keywords:
            print("[*] Tip: domain treated as one word. To split a compound "
                  "(e.g. seven + sevenkingdoms), use --org \"Seven Kingdoms\" "
                  "or --keywords seven,sevenkingdoms", file=sys.stderr)

    if args.show_bases:
        sys.exit(0)

    passwords = mutator.generate_list(count=args.count, min_length=args.length)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            for pwd in passwords:
                f.write(pwd + "\n")
        print(f"[+] Generated {len(passwords)} passwords -> {args.output}")
    else:
        for pwd in passwords:
            print(pwd)


if __name__ == "__main__":
    main()
