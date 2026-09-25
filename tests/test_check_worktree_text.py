import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local" / "check-worktree-text.ps1"


def run(command, cwd):
    return subprocess.run(command, cwd=cwd, check=True, text=True, capture_output=True)


def init_repo(path: Path):
    run(["git", "init", "--quiet"], path)
    run(["git", "config", "user.email", "lab@example.invalid"], path)
    run(["git", "config", "user.name", "Lab"], path)


def run_checker(path: Path):
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SCRIPT),
            "-Root",
            str(path),
        ],
        text=True,
        capture_output=True,
    )


def parse_report(result):
    return json.loads(result.stdout)


class CheckWorktreeTextTests(unittest.TestCase):
    def test_checker_reads_tracked_and_untracked_unicode_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            init_repo(repo)
            tracked = repo / "tracked space.md"
            untracked = repo / "unicodé path" / "nuevo.txt"
            untracked.parent.mkdir()
            tracked.write_text("ok\n", encoding="utf-8")
            untracked.write_text("ok\n", encoding="utf-8")
            run(["git", "add", "tracked space.md"], repo)

            result = run_checker(repo)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            report = parse_report(result)
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["selected_files"], 2)
            self.assertEqual(report["read_files"], 2)
            self.assertEqual(report["git_names"], 2)

    def test_checker_fails_when_git_command_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_checker(Path(tmp))

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("git ls-files -z failed", result.stderr)

    def test_checker_fails_when_selected_tracked_file_disappeared(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            init_repo(repo)
            tracked = repo / "gone.md"
            tracked.write_text("ok\n", encoding="utf-8")
            run(["git", "add", "gone.md"], repo)
            tracked.unlink()

            result = run_checker(repo)

            self.assertNotEqual(result.returncode, 0)
            report = parse_report(result)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["disappeared_files"], ["gone.md"])
            self.assertIn(
                "gone.md: selected by git but not readable as a file",
                report["errors"],
            )

    def test_checker_omits_unselected_files_without_counting_them_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            init_repo(repo)
            source = repo / "checked.md"
            binary = repo / "asset.bin"
            source.write_text("ok\n", encoding="utf-8")
            binary.write_bytes(b"\x00\x01")

            result = run_checker(repo)

            self.assertEqual(result.returncode, 0, result.stderr)
            report = parse_report(result)
            self.assertEqual(report["selected_files"], 1)
            self.assertEqual(report["read_files"], 1)
            self.assertEqual(report["omitted_files"], 1)


if __name__ == "__main__":
    unittest.main()
