# wordlists/  —  editable building blocks for password_mutator.py
#
# The mutator combines the org/domain name with the tokens in these files.
# Every file is optional: if missing or empty, the mutator falls back to a
# sensible built-in default, so it always works out of the box.
#
# Rules for every file:
#   - one token per line
#   - blank lines and lines starting with '#' are ignored
#
# Files:
#   seasons.txt          seasonal words combined with name+year (Summer, Winter, ...)
#   months.txt           months combined with year standalone (January..December)
#   anchors.txt          words ATTACHED to the name (Welcome, Password, Ilove, ...)
#   years.txt            supplementary/historical years (2025, 2024, ...); the
#                        primary year comes from --year (default 2026)
#   suffixes.txt         finales & separators appended/inserted (!, !@#, @, -)
#   common_passwords.txt always-included common passwords (the floor)
#   leet.txt             leetspeak substitution map (a=4,@  e=3  ... )
#
# Point the mutator at a different directory with:  --wordlist-dir ./my_lists
