"""Negative cases for the public audit evidence boundary."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("audit_registry", ROOT / "scripts/check-audit-registry.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class AuditRegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = json.loads((ROOT / ".github/audit-registry.json").read_text())

    def test_open_scopes_do_not_imply_a_completed_audit(self):
        self.assertEqual(audit.validate(self.registry), 5)

    def test_completed_status_requires_report_and_full_commit_identity(self):
        value = copy.deepcopy(self.registry)
        value["audits"][0]["status"] = "completed"
        with self.assertRaises(ValueError):
            audit.validate(value)
        value["audits"][0]["report"] = "SECURITY.md"
        value["audits"][0]["accepted_commit"] = "short"
        with self.assertRaises(ValueError):
            audit.validate(value)

    def test_private_and_outside_report_references_fail(self):
        for path in (".local/report.md", ".LOCAL/report.md", ".GIT/report.md", "../report.md", "/tmp/report.md"):
            value = copy.deepcopy(self.registry)
            value["audits"][0]["report"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.validate(value)

    def test_symlink_escape_and_duplicate_keys_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "public"
            root.mkdir()
            outside = Path(directory) / "private.md"
            outside.write_text("Private evidence")
            (root / "report.md").symlink_to(outside)
            with self.assertRaises(ValueError):
                audit.public_path(root, "report.md")
            private = root / ".local"
            private.mkdir()
            (private / "report.md").write_text("Private evidence")
            (root / "private-alias.md").symlink_to(private / "report.md")
            with self.assertRaises(ValueError):
                audit.public_path(root, "private-alias.md")
        with self.assertRaises(ValueError):
            json.loads('{"status":"planned","status":"completed"}', object_pairs_hook=audit.unique_pairs)


if __name__ == "__main__":
    unittest.main()
