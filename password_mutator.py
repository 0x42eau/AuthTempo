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

    # Common corporate password prefixes
    PREFIXES = [
        "Welcome", "Password", "Company", "Corporate", "Office",
        "Summer", "Winter", "Spring", "Fall", "Autumn",
        "January", "February", "March", "April", "May", "June",
        "July", "August", "September", "October", "November", "December",
        "Change", "ChangeMe", "Changeme", "Ilove", "ILove",
    ]

    # Common suffixes and separators
    SUFFIXES = [
        "!", "!@#", "!@#$", "!@#$%", "@", "#", "123", "123!", "1234", "12345",
        "2024", "2025", "2026", "2023", "2022", "2021", "1", "2", "3", "0",
        "Admin", "User", "Staff", "Team", "Office", "Home",
    ]

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
            # Clean org name: remove suffixes like Corp, Inc, LLC
            org_clean = re.sub(r'\s+(Corporation|Corp|Incorporated|Inc|LLC|Ltd)\b.*', '', org, flags=re.IGNORECASE)
            names.add(org_clean)
            names.add(org_clean.replace(" ", ""))
            names.add(org_clean.replace(" ", "."))

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
            # Title case for multi-word
            if " " in name or "-" in name or "_" in name:
                variants.append(name.title().replace("_", " ").replace("-", " "))
        return list(set(variants))

    def generate(self, count: int = 100) -> List[str]:
        """
        Generate password mutations.

        Args:
            count: Maximum number of passwords to generate

        Returns:
            List of generated passwords (duplicates removed)
        """
        passwords: Set[str] = set()

        # Priority 1: Organization name + current year patterns (HIGHEST PROBABILITY)
        for org_name in self.org_names:
            for variant in self._capitalize_variants(org_name):
                # WelcomeOrg2026!, CompanyOrg2026!, etc.
                for prefix in ["Welcome", "Password", "Company"]:
                    passwords.add(f"{prefix}{variant}{self.year}!")
                    passwords.add(f"{prefix}{variant}{self.year}")
                    passwords.add(f"{prefix}{variant}!")

                # Org2026!, Org2026
                passwords.add(f"{variant}{self.year}!")
                passwords.add(f"{variant}{self.year}")

                # IloveOrg123!
                passwords.add(f"Ilove{variant}123!")
                passwords.add(f"Ilove{variant}{self.year}!")
                passwords.add(f"ILove{variant}123!")

                # Org@2026
                passwords.add(f"{variant}@{self.year}")
                passwords.add(f"{variant}!{self.year}")

        # Priority 2: Seasonal + current year (HIGH PROBABILITY)
        months = ["January", "February", "March", "April", "May", "June",
                  "July", "August", "September", "October", "November", "December"]
        seasons = ["Summer", "Winter", "Spring", "Fall", "Autumn"]

        for month in months:
            passwords.add(f"{month}{self.year}!")
            passwords.add(f"{month}{self.year}")

        for season in seasons:
            passwords.add(f"{season}{self.year}!")
            passwords.add(f"{season}{self.year}")

        # Priority 3: Seasonal + org name (MODERATE PROBABILITY)
        for org_name in self.org_names:
            for variant in self._capitalize_variants(org_name):
                for season in ["Summer", "Winter", "Spring"]:
                    passwords.add(f"{season}{variant}!")
                    passwords.add(f"{season}{variant}{self.year}!")

        # Priority 4: Common corporate patterns (MODERATE PROBABILITY)
        passwords.update([
            "Password123!",
            "P@ssw0rd123!",
            "Welcome123!",
            "Welcome123!@#",
            "Password1!",
            "P@ssw0rd!",
            "Welcome1!",
            "Welcome!",
            "Changeme!",
            "ChangeMe!",
            "Corporate123!",
            "Company123!",
            "Office365!",
            "letmein",
            "letmein123!",
        ])

        # Priority 5: Generic patterns (LOWER PROBABILITY - always include)
        passwords.update([
            "password",
            "password1",
            "password123!",
            "P@ssw0rd",
            "Welcome123",
            "admin",
            "administrator",
            "123456",
        ])

        # Convert to list and limit count
        result = list(passwords)
        result.sort()  # Sort for consistent output

        # Order by probability (approximate)
        # High-probability patterns first
        priority_keywords = [
            f"{self.year}!",
            f"{self.year}",
            "Welcome",
            "Password",
            "Company",
            "Summer",
            "Winter",
            "Spring",
        ]
        result.sort(key=lambda x: (
            sum(1 for kw in priority_keywords if kw.lower() in x.lower()),
            len(x)  # Shorter passwords generally more common
        ), reverse=True)

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
