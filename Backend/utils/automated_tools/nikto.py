import subprocess
import time
import threading
import re
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
from config import get_tool_path, get_wsl_path

ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def run_nikto_scan(target_url):
    print("🚀 Running Nikto...")

    # Get Nikto path from config
    nikto_path = get_tool_path("nikto")

    # Build Nikto command inside WSL
    nikto_cmd = f"perl {nikto_path} -h {target_url}"
    full_cmd = f'wsl bash -c "{nikto_cmd}"'

    # Start the WSL process
    process = subprocess.Popen(
        full_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True
    )

    def kill_process_after_timeout(proc, timeout):
        time.sleep(timeout)
        if proc.poll() is None:  # Still running
            print("⏱️ Timeout: Killing process...")
            # 🛑 Try to kill all related processes inside WSL
            subprocess.run("wsl pkill -f nikto", shell=True)  # Uses WSL's pkill

    # Start a watchdog thread
    timeout_thread = threading.Thread(
        target=kill_process_after_timeout, args=(process, 60)
    )
    timeout_thread.start()

    # Wait for the process to complete
    stdout, stderr = process.communicate()

    full_output = stdout + ("\n" + stderr if stderr else "")
    clean_output = ansi_escape.sub("", full_output)

    print("📤 Output:", clean_output)
    return clean_output
