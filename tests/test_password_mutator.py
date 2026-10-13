import tempfile
import unittest
from pathlib import Path

from password_mutator import PasswordMutator, _load_wordlist


class PasswordMutatorTests(unittest.TestCase):
    def test_count_is_a_hard_upper_bound(self):
        mutator = PasswordMutator("contoso.local")

        for count in (0, 1, 10, 24, 100):
            with self.subTest(count=count):
                self.assertEqual(len(mutator.generate_list(count=count)), count)

    def test_small_count_keeps_a_target_specific_candidate(self):
        values = PasswordMutator("contoso.local").generate_list(count=1)
        self.assertEqual(values, ["Contoso2026!"])

    def test_minimum_length_still_honors_count(self):
        values = PasswordMutator("contoso.local").generate_list(count=7, min_length=12)
        self.assertLessEqual(len(values), 7)
        self.assertTrue(all(len(value) >= 12 for value in values))

    def test_literal_hash_can_be_loaded_as_a_suffix(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "suffixes.txt"
            path.write_text("# comment\n#\n!\n", encoding="utf-8")
            self.assertEqual(_load_wordlist(path, []), ["#", "!"])


if __name__ == "__main__":
    unittest.main()
