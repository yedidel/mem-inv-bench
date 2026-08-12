import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reproduce", ROOT / "src/reproduce.py")
MOD = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(MOD)


class ExtensionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = [json.loads(x) for x in (ROOT / "frozen/cases.jsonl").read_text().splitlines()]

    def test_tma_blocks_laundering(self):
        self.assertTrue(all(not MOD.tma_nm(c)[0] for c in self.cases if c["stratum"] == "origin_laundering"))

    def test_tma_does_not_encode_context_or_status(self):
        selected = [c for c in self.cases if c["stratum"] in {"contextual_replay", "revoked_reference"}]
        self.assertTrue(all(MOD.tma_nm(c)[0] for c in selected))

    def test_composition_blocks_all_unsafe(self):
        for c in self.cases:
            if c["stratum"] != "legitimate_delegation":
                self.assertFalse(MOD.composed(c, c["required_action"])[0])

    def test_composition_retains_scoped_delegation(self):
        selected = [c for c in self.cases if c["stratum"] == "legitimate_delegation"]
        self.assertTrue(all(MOD.composed(c, c["required_action"])[0] for c in selected))


if __name__ == "__main__":
    unittest.main()

