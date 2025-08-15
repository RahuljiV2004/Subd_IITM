#!/usr/bin/env python3
"""
Windows-compatible Nikto web vulnerability scanner
Runs Nikto using native Windows commands without WSL dependency
"""

import subprocess
import time
import threading
import re
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))
from config import get_tool_path

ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def run_nikto_scan(target_url):
    """
    Run Nikto web vulnerability scan on Windows
    """
    print(f"🚀 Running Nikto scan on {target_url}...")

    try:
        # Get Nikto path from config
        tools_dir = os.path.join(os.getcwd(), "tools")
        nikto_path = os.path.join(tools_dir, "nikto", "program", "nikto.pl")

        # Check if Nikto exists
        if not os.path.exists(nikto_path):
            print(f"❌ Nikto not found at {nikto_path}")
            return f"❌ Nikto scanner not available at {nikto_path}"

        # Build Nikto command for Windows (using system Perl)
        cmd = [
            "perl",
            nikto_path,
            "-h",
            target_url,
            "-Format",
            "txt",
            "-timeout",
            "30",
            "-maxtime",
            "300",  # 5 minutes max
        ]

        print(f"🔧 Executing: {' '.join(cmd)}")

        # Start the process
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=tools_dir,
        )

        def kill_process_after_timeout(proc, timeout):
            """Kill process after timeout"""
            time.sleep(timeout)
            if proc.poll() is None:  # Still running
                print("⏱️ Timeout: Terminating Nikto process...")
                proc.terminate()
                time.sleep(5)
                if proc.poll() is None:
                    proc.kill()

        # Start a watchdog thread (5 minutes timeout)
        timeout_thread = threading.Thread(
            target=kill_process_after_timeout, args=(process, 300)
        )
        timeout_thread.daemon = True
        timeout_thread.start()

        # Wait for the process to complete
        try:
            stdout, stderr = process.communicate(timeout=320)  # 5 min 20 sec
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()

        # Combine output
        full_output = stdout + ("\n" + stderr if stderr else "")
        clean_output = ansi_escape.sub("", full_output)

        print(f"✅ Nikto scan completed for {target_url}")
        return clean_output

    except FileNotFoundError:
        error_msg = f"❌ Perl not found. Please install Perl to run Nikto scans."
        print(error_msg)
        return error_msg
    except Exception as e:
        error_msg = f"❌ Nikto scan failed: {str(e)}"
        print(error_msg)
        return error_msg


def run_nikto_scan_simple(target_url):
    """
    Simplified Nikto scan using available tools
    """
    try:
        # Try using system curl for basic web analysis as fallback
        tools_dir = os.path.join(os.getcwd(), "tools")

        # Basic HTTP response analysis
        cmd = ["curl", "-I", "-L", "--max-time", "30", target_url]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)

        if result.returncode == 0:
            headers = result.stdout
            analysis = f"=== Basic Web Analysis for {target_url} ===\n"
            analysis += f"HTTP Headers:\n{headers}\n"

            # Basic security header analysis
            security_issues = []
            if "X-Frame-Options" not in headers:
                security_issues.append(
                    "Missing X-Frame-Options header (Clickjacking protection)"
                )
            if "X-Content-Type-Options" not in headers:
                security_issues.append("Missing X-Content-Type-Options header")
            if "X-XSS-Protection" not in headers:
                security_issues.append("Missing X-XSS-Protection header")
            if "Strict-Transport-Security" not in headers:
                security_issues.append("Missing HSTS header")

            if security_issues:
                analysis += "\n=== Security Issues Found ===\n"
                for issue in security_issues:
                    analysis += f"- {issue}\n"
            else:
                analysis += "\n✅ Basic security headers present\n"

            return analysis
        else:
            return f"❌ Failed to analyze {target_url}: {result.stderr}"

    except Exception as e:
        return f"❌ Web analysis failed: {str(e)}"


if __name__ == "__main__":
    # Test the scanner
    test_url = "https://www.iitm.ac.in"
    result = run_nikto_scan(test_url)
    print("Result:", result)
