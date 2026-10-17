"""Exercise the real Bash supervisor with disposable offline child processes.

The PATH fixtures replace only Tor and the worker executable. They never open a
network connection or import the collector runtime. Process groups are cleaned
up by the test even when it deliberately simulates denied signal permissions.
"""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ENTRYPOINT = Path(os.environ.get("GUARDOVA_TEST_ENTRYPOINT", str(Path(__file__).resolve().parents[1] / "guardova-entrypoint.sh")))
CHILD = r'''
import os
from pathlib import Path
import signal
import sys
import time

name = "tor" if Path(sys.argv[0]).name == "tor" else "worker"
state = Path(os.environ["GUARDOVA_TEST_STATE"])
mode = os.environ.get("GUARDOVA_TEST_" + name.upper() + "_MODE", "hold")

def stop(signum, _frame):
    (state / (name + ".signal")).write_text(str(signum))
    if mode != "ignore":
        raise SystemExit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
(state / (name + ".pid")).write_text(str(os.getpid()))
while True:
    if (state / (name + ".exit")).exists():
        raise SystemExit(int(os.environ.get("GUARDOVA_TEST_EXIT_CODE", "7")))
    time.sleep(0.02)
'''


class EntrypointLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="guardova-entrypoint-")
        self.root = Path(self.directory.name)
        self.executables = self.root / "bin"
        self.executables.mkdir()
        for name in ("tor", "python"):
            executable = self.executables / name
            executable.write_text("#!" + sys.executable + "\n" + CHILD)
            executable.chmod(0o700)
        self.process = None
        self.environment = {
            **os.environ,
            "PATH": str(self.executables) + os.pathsep + "/usr/bin:/bin",
            "GUARDOVA_TEST_STATE": str(self.root),
            "GUARDOVA_STOP_GRACE_SECONDS": "1",
        }
        self.environment.pop("BASH_ENV", None)
        self.environment.pop("ENV", None)

    def tearDown(self):
        if self.process is not None:
            # Also terminate any deliberately unsignallable fixture children
            # after the supervisor has reported its bounded cleanup failure.
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=5)
        self.directory.cleanup()

    def start(self, **environment):
        self.environment.update(environment)
        with (self.root / "stdout").open("w") as stdout, (self.root / "stderr").open("w") as stderr:
            self.process = subprocess.Popen(
                ["/bin/bash", str(ENTRYPOINT)], env=self.environment,
                stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.fail("supervisor exited before both fixtures started: " + self.output())
            if all((self.root / (name + ".pid")).exists() for name in ("tor", "worker")):
                return
            time.sleep(0.02)
        self.fail("fixture startup timeout")

    def output(self):
        return (self.root / "stderr").read_text()

    def assert_children_reaped(self):
        for name in ("tor", "worker"):
            pid = int((self.root / (name + ".pid")).read_text())
            with self.assertRaises(ProcessLookupError, msg=name + " remains alive or unreaped"):
                os.kill(pid, 0)

    def test_planned_term_stops_and_reaps_both_children_with_zero_exit(self):
        self.start()
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=5), 0, self.output())
        self.assert_children_reaped()
        self.assertNotIn("supervisor_child_exited", self.output())
        for name in ("tor", "worker"):
            self.assertEqual((self.root / (name + ".signal")).read_text(), str(signal.SIGTERM))

    def test_planned_int_stops_cleanly(self):
        self.start()
        self.process.send_signal(signal.SIGINT)
        self.assertEqual(self.process.wait(timeout=5), 0, self.output())
        self.assert_children_reaped()

    def test_tor_exit_stops_worker_and_fails_even_when_tor_exits_zero(self):
        self.start(GUARDOVA_TEST_EXIT_CODE="0")
        (self.root / "tor.exit").touch()
        self.assertEqual(self.process.wait(timeout=5), 1, self.output())
        self.assertIn("supervisor_child_exited child=tor", self.output())
        self.assert_children_reaped()

    def test_worker_exit_stops_tor_and_fails(self):
        self.start()
        (self.root / "worker.exit").touch()
        self.assertEqual(self.process.wait(timeout=5), 1, self.output())
        self.assertIn("supervisor_child_exited child=worker", self.output())
        self.assert_children_reaped()

    def test_term_ignoring_child_is_killed_after_bounded_grace(self):
        self.start(GUARDOVA_TEST_WORKER_MODE="ignore")
        started = time.monotonic()
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=7), 0, self.output())
        self.assertLess(time.monotonic() - started, 6)
        self.assertIn("supervisor_force_kill child=worker", self.output())
        self.assert_children_reaped()

    def test_denied_signals_are_reported_and_cleanup_does_not_wait_forever(self):
        # Bash's builtin is replaced only in this disposable test shell. The
        # external test process retains the ability to remove its own fixtures.
        bash_environment = self.root / "deny-signals.bash"
        bash_environment.write_text("kill() { return 1; }\n")
        self.start(BASH_ENV=str(bash_environment))
        started = time.monotonic()
        self.process.send_signal(signal.SIGTERM)
        self.assertEqual(self.process.wait(timeout=8), 1, self.output())
        self.assertLess(time.monotonic() - started, 7)
        self.assertIn("supervisor_signal_failed child=worker signal=TERM", self.output())
        self.assertIn("supervisor_signal_failed child=tor signal=KILL", self.output())
        self.assertIn("supervisor_cleanup_timeout", self.output())

    def test_invalid_grace_is_rejected_before_children_start(self):
        for value in ("0", "181", "-1", "1.5", "invalid", "999999999999999999999999999999"):
            with self.subTest(value=value):
                result = subprocess.run(["/bin/bash", str(ENTRYPOINT)],
                                        env={**self.environment, "GUARDOVA_STOP_GRACE_SECONDS": value},
                                        capture_output=True, text=True, timeout=3)
                self.assertEqual(result.returncode, 2)
                self.assertIn("supervisor_invalid_stop_grace", result.stderr)
                self.assertFalse((self.root / "tor.pid").exists())


if __name__ == "__main__":
    unittest.main()
