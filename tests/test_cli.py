import tempfile
import unittest
from pathlib import Path

from hash_collision_detector.cli import FileDigest, find_collisions, main, scan


class CollisionDetectorTests(unittest.TestCase):
    def test_different_contents_with_same_digest_are_detected(self):
        records = [
            FileDigest("a.bin", "deadbeef", 1, "content-a"),
            FileDigest("b.bin", "deadbeef", 1, "content-b"),
        ]
        collisions = find_collisions(records)
        self.assertEqual(collisions["deadbeef"][0].path, "a.bin")
        self.assertEqual(len(collisions["deadbeef"]), 2)

    def test_identical_files_are_not_reported_as_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_bytes(b"same")
            (root / "two.txt").write_bytes(b"same")
            records = scan([root], algorithm="md5")
            self.assertEqual(find_collisions(records), {})

    def test_cli_json_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.txt").write_bytes(b"hello")
            self.assertEqual(main([str(root), "--algorithm", "md5", "--json"]), 0)


if __name__ == "__main__":
    unittest.main()
