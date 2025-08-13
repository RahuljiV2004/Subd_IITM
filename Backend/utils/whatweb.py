import subprocess
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from config import get_tool_path


def run_whatweb_scan(subdomain):
    """
    Runs WhatWeb with --log-json=- for the given subdomain.
    Parses valid JSON lines and returns them as a list.
    Raises RuntimeError if WhatWeb fails.
    """
    whatweb_script = get_tool_path("whatweb")
    cmd = ["ruby", whatweb_script, "--log-json=-", subdomain]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"WhatWeb failed: {result.stderr}\n{result.stdout}")

    parsed = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    if not parsed:
        raise RuntimeError(f"No valid JSON output: {result.stdout}")

    return parsed
