"""Run one hook command, printing a start timestamp and the elapsed time.

Usage: timed.py NAME CMD... -- CMD runs through the shell, so `&&` chains work.
"""

import subprocess
import sys
import time
from datetime import datetime


def stamp() -> str:
    return datetime.now().strftime("%H:%M:%S")


def main() -> int:
    name, cmd = sys.argv[1], " ".join(sys.argv[2:])
    print(f"[{stamp()}] > {name}", flush=True)
    start = time.perf_counter()
    code = subprocess.run(cmd, shell=True, check=False).returncode  # noqa: S602 -- commands from our own hook config
    print(
        f"[{stamp()}] < {name}  {time.perf_counter() - start:.2f}s (exit {code})",
        flush=True,
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
