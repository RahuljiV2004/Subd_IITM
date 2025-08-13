import subprocess
import re
from datetime import datetime
from .db_utils import append_tool_result

# Regex to match ANSI escape sequences (colors, etc.)
ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def run_testssl_scan(target_url, scan_id=None):
    import sys
    import os

    sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
    from config import get_tool_path

    testssl_path = get_tool_path("testssl")
    if not testssl_path:
        return {"error": "testssl.sh not found"}

    # Pipe 'yes' to automatically confirm if testssl asks for user input
    cmd = f"yes yes | {testssl_path} --fast {target_url}"
    full_cmd = f'wsl bash -c "{cmd}"'

    print("🚀 Running testssl.sh...\n")

    try:
        result = subprocess.run(
            full_cmd, shell=True, capture_output=True, text=True, timeout=200
        )

        # Combine stdout and stderr
        output = result.stdout
        error_output = result.stderr
        full_output = output + ("\n" + error_output if error_output else "")

        # Remove ANSI escape sequences (colors)
        clean_output = ansi_escape.sub("", full_output)

        print("📝 testssl.sh Output:\n", clean_output or "No output received.")

        # Save to DB if scan_id provided
        if scan_id:
            append_tool_result(
                scan_id=scan_id,
                tool_name="testssl",
                command=cmd,
                output=clean_output,
            )

        return clean_output

    except subprocess.TimeoutExpired:
        error_msg = "testssl.sh scan timed out after 200 seconds"
        print(f"⏰ {error_msg}")
        if scan_id:
            append_tool_result(
                scan_id=scan_id, tool_name="testssl", command=cmd, output=error_msg
            )
        return error_msg

    except Exception as e:
        error_msg = f"Error running testssl.sh: {e}"
        print(f"❌ {error_msg}")
        if scan_id:
            append_tool_result(
                scan_id=scan_id, tool_name="testssl", command=cmd, output=error_msg
            )
        return error_msg
