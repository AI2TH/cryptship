import subprocess
import sys
import unittest

import cryptship_harden


@unittest.skipUnless(sys.platform.startswith("linux"), "PR_SET_DUMPABLE is Linux-only")
class SetNonDumpableTest(unittest.TestCase):
    def test_sets_flag(self):
        # Run in a child so this test process keeps its own flag.
        code = (
            "import cryptship_harden as h\n"
            "assert h.is_dumpable()\n"
            "assert h.set_non_dumpable() is True\n"
            "assert not h.is_dumpable()\n"
            "print('ok')\n"
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             cwd=__import__("os").path.dirname(__file__) or ".")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "ok")


if __name__ == "__main__":
    unittest.main()
