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
from typing import List, Set


class PasswordMutator:
    """Generate enterprise-style password mutations from domain/org names."""

    def __init__(self, domain: str = "", org: str = "", year: int = 2026):
        """
        Initialize mutator with domain and organization info.

        Args:
            domain: Active Directory domain (e.g., "contoso.local")
            org: Organization name (e.g., "Contoso Corporation")
            year: Target year for seasonal passwords (default: 2026)
        """
        self.domain = domain.lower()
        self.org = org
        self.year = year

        # Extract organization names from domain
        self.org_names = self._extract_org_names(domain, org)

    def _extract_org_names(self, domain: str, org: str) -> Set[str]:
        """Extract organization name variations from domain/org."""
        names = set()

        # Add explicit org name if provided
        if org:
            # Clean org name: remove suffixes and spaces, convert to single word
            org_clean = re.sub(r'\s+(Corporation|Corp|Incorporated|Inc|LLC|Ltd)\b.*', '', org, flags=re.IGNORECASE)
            org_clean = re.sub(r'\s+', '', org_clean)  # Remove all spaces
            names.add(org_clean)

        # Extract from domain (e.g., "contoso.local" -> "contoso")
        if domain:
            domain_base = domain.split(".")[0]  # First part before dot
            names.add(domain_base)

            # Handle multi-part domains (e.g., "sevenkingdoms.local" -> "sevenkingdoms")
            if "." in domain:
                parts = domain.split(".")
                for part in parts:
                    if part not in ["local", "com", "net", "org", "int"]:
                        names.add(part)

        return names

    def _capitalize_variants(self, name: str) -> List[str]:
        """Generate capitalization variants of a name."""
        variants = [name]
        if len(name) > 1:
            variants.append(name.capitalize())  # contoso -> Contoso
            variants.append(name.upper())  # contoso -> CONTOSO
            variants.append(name.lower())  # Contoso -> contoso
        return list(set(variants))

    def generate(self, count: int = 100) -> List[str]:
        """
        Generate password mutations ordered by probability.

        Returns:
            List of generated passwords (duplicates removed)
        """
        passwords: List[tuple[int, str]] = []  # (priority, password) - lower priority = higher probability

        # Priority 1: Org + current year patterns (HIGHEST PROBABILITY)
        for org_name in self.org_names:
            for variant in self._capitalize_variants(org_name):
                # WelcomeOrg2026! (most realistic enterprise pattern)
                passwords.append((1, f"Welcome{variant}{self.year}!"))
                passwords.append((1, f"Welcome{variant}{self.year}"))
                passwords.append((1, f"Welcome{variant}!"))

                # Org2026!, Org2026 (clean org + year)
                passwords.append((1, f"{variant}{self.year}!"))
                passwords.append((1, f"{variant}{self.year}"))
                passwords.append((1, f"{variant}!"))

                # Org@2026, Org!2026 (realistic separators)
                passwords.append((1, f"{variant}@{self.year}"))
                passwords.append((1, f"{variant}!{self.year}"))

        # Priority 1: Seasonal + org name (HIGH PROBABILITY)
        for org_name in self.org_names:
            for variant in self._capitalize_variants(org_name):
                for season in ["Summer", "Winter", "Spring", "Fall", "Autumn"]:
                    passwords.append((1, f"{season}{variant}!"))
                    passwords.append((1, f"{season}{variant}{self.year}!"))

        # Priority 2: Seasonal + year (HIGH - but without org, so slightly lower)
        for season in ["Summer", "Winter", "Spring", "Fall", "Autumn"]:
            passwords.append((2, f"{season}{self.year}!"))
            passwords.append((2, f"{season}{self.year}"))

        for month in ["January", "February", "March", "April", "May", "June",
                      "July", "August", "September", "October", "November", "December"]:
            passwords.append((2, f"{month}{self.year}!"))
            passwords.append((2, f"{month}{self.year}"))

        # Priority 2: Ilove/org patterns (moved down from Priority 1)
        for org_name in self.org_names:
            for variant in self._capitalize_variants(org_name):
                passwords.append((2, f"Ilove{variant}123!"))
                passwords.append((2, f"Ilove{variant}{self.year}!"))
                passwords.append((2, f"ILove{variant}123!"))

        # Priority 3: Common corporate patterns (MODERATE PROBABILITY)
        passwords.extend([
            (3, "Password123!"),
            (3, "P@ssw0rd123!"),
            (3, "Welcome123!"),
            (3, "Welcome123!@#"),
            (3, "Password1!"),
            (3, "P@ssw0rd!"),
            (3, "Welcome1!"),
            (3, "Welcome!"),
            (3, "Changeme!"),
            (3, "ChangeMe!"),
            (3, "Changeme1!"),
            (3, "Corporate123!"),
            (3, "Company123!"),
            (3, "Office365!"),
        ])

        # Priority 4: Year variations 2023-2025
        passwords.extend([
            (4, "Welcome2023!"),
            (4, "Summer2023!"),
            (4, "Winter2023!"),
            (4, "Password2023!"),
            (4, "Welcome2022!"),
            (4, "Password2022!"),
            (4, "Welcome2021!"),
            (4, "Password2021!"),
        ])

        # Priority 5: Generic patterns (LOWEST PROBABILITY - always include)
        passwords.extend([
            (5, "password"),
            (5, "password1"),
            (5, "password123!"),
            (5, "P@ssw0rd"),
            (5, "Welcome123"),
            (5, "admin"),
            (5, "administrator"),
            (5, "123456"),
        ])

        # Remove duplicates and sort by priority
        seen = set()
        unique_passwords = []
        for priority, pwd in passwords:
            pwd_lower = pwd.lower()
            if pwd_lower not in seen:
                seen.add(pwd_lower)
                unique_passwords.append((priority, pwd))

        # Sort by priority (lower number = higher probability)
        # Within same priority, Welcome/Seasonal/Month prefix gets priority
        def sort_key(x):
            priority, pwd = x
            # Secondary sort: Welcome/Seasonal/Month prefix patterns get priority
            if re.match(r"^(Welcome|Spring|Summer|Winter|Fall|Autumn|January|February|March|April|May|June|July|August|September|October|November|December)", pwd, re.IGNORECASE):
                return (priority, 0, len(pwd))  # Prefix patterns first
            return (priority, 1, len(pwd))  # Then by length
        unique_passwords.sort(key=sort_key)

        # Return just the passwords (not the priorities)
        result = [pwd for _, pwd in unique_passwords]
        return result[:count]

    def generate_list(self, count: int = 100) -> List[str]:
        """Generate and return password list."""
        return self.generate(count)


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
        """
    )

    parser.add_argument("--domain", help="Active Directory domain (e.g., contoso.local)")
    parser.add_argument("--org", help="Organization name (e.g., 'Contoso Corporation')")
    parser.add_argument("--year", type=int, default=2026, help="Target year (default: 2026)")
    parser.add_argument("--count", type=int, default=100, help="Max passwords to generate (default: 100)")
    parser.add_argument("-o", "--output", help="Output file (default: stdout)")

    args = parser.parse_args()

    if not args.domain:
        parser.print_help()
        print("\n[!] Error: --domain is required", file=sys.stderr)
        sys.exit(1)

    # Generate passwords
    mutator = PasswordMutator(domain=args.domain, org=args.org, year=args.year)
    passwords = mutator.generate_list(count=args.count)

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
