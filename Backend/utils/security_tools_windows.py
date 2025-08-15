#!/usr/bin/env python3
"""
Windows-compatible security tools wrapper
Uses available Windows executables for FFUF, Nuclei, DNSx, HTTPx, Subfinder
"""

import subprocess
import json
import os
import sys
from typing import Dict, List, Any

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))


def run_ffuf_windows(target_url: str, wordlist_path: str = None) -> Dict[str, Any]:
    """
    Run FFUF directory/file discovery using Windows executable
    """
    print(f"🔍 Running FFUF directory discovery on {target_url}...")

    try:
        tools_dir = os.path.join(os.getcwd(), "tools")
        ffuf_exe = os.path.join(tools_dir, "ffuf.exe")

        if not os.path.exists(ffuf_exe):
            return {"error": f"FFUF executable not found at {ffuf_exe}"}

        # Default wordlist (create a basic one if needed)
        if not wordlist_path:
            wordlist_path = create_basic_wordlist()

        # Parse target URL
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        # Ensure URL ends with FUZZ placeholder
        if not target_url.endswith("/"):
            target_url += "/"
        target_url += "FUZZ"

        cmd = [
            ffuf_exe,
            "-u",
            target_url,
            "-w",
            wordlist_path,
            "-fc",
            "404",  # Filter out 404s
            "-t",
            "10",  # 10 threads
            "-timeout",
            "30",
            "-o",
            "ffuf_output.json",
            "-of",
            "json",
        ]

        print(f"🔧 Executing FFUF: {' '.join(cmd[:4])}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes
            cwd=tools_dir,
        )

        # Try to read JSON output
        output_file = os.path.join(tools_dir, "ffuf_output.json")
        if os.path.exists(output_file):
            try:
                with open(output_file, "r") as f:
                    ffuf_data = json.load(f)
                os.remove(output_file)  # Clean up
                return ffuf_data
            except:
                pass

        # Fallback to parsing stdout
        if result.stdout:
            return {"raw_output": result.stdout, "stderr": result.stderr}
        else:
            return {"error": f"FFUF failed: {result.stderr}"}

    except subprocess.TimeoutExpired:
        return {"error": "FFUF scan timed out"}
    except Exception as e:
        return {"error": f"FFUF scan failed: {str(e)}"}


def run_nuclei_windows(target_url: str) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner using Windows executable
    """
    print(f"🔍 Running Nuclei vulnerability scan on {target_url}...")

    try:
        tools_dir = os.path.join(os.getcwd(), "tools")
        nuclei_exe = os.path.join(tools_dir, "nuclei.exe")

        if not os.path.exists(nuclei_exe):
            return {"error": f"Nuclei executable not found at {nuclei_exe}"}

        cmd = [
            nuclei_exe,
            "-target",
            target_url,
            "-json",
            "-severity",
            "low,medium,high,critical",
            "-timeout",
            "30",
            "-retries",
            "1",
            "-rate-limit",
            "10",
        ]

        print(f"🔧 Executing Nuclei: {' '.join(cmd[:3])}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes
            cwd=tools_dir,
        )

        if result.returncode == 0 and result.stdout:
            # Parse JSON lines
            vulnerabilities = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue

            return {"vulnerabilities": vulnerabilities, "count": len(vulnerabilities)}
        else:
            return {"error": f"Nuclei failed: {result.stderr}", "vulnerabilities": []}

    except subprocess.TimeoutExpired:
        return {"error": "Nuclei scan timed out", "vulnerabilities": []}
    except Exception as e:
        return {"error": f"Nuclei scan failed: {str(e)}", "vulnerabilities": []}


def run_httpx_windows(target: str) -> Dict[str, Any]:
    """
    Run HTTPx for HTTP analysis using Windows executable
    """
    print(f"🔍 Running HTTPx analysis on {target}...")

    try:
        tools_dir = os.path.join(os.getcwd(), "tools")
        httpx_exe = os.path.join(tools_dir, "httpx.exe")

        if not os.path.exists(httpx_exe):
            return {"error": f"HTTPx executable not found at {httpx_exe}"}

        cmd = [
            httpx_exe,
            "-target",
            target,
            "-json",
            "-status-code",
            "-content-length",
            "-title",
            "-tech-detect",
            "-timeout",
            "30",
        ]

        print(f"🔧 Executing HTTPx: {' '.join(cmd[:3])}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=tools_dir
        )

        if result.returncode == 0 and result.stdout:
            # Parse JSON lines
            http_data = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        http_data.append(data)
                    except json.JSONDecodeError:
                        continue

            return {"http_data": http_data, "count": len(http_data)}
        else:
            return {"error": f"HTTPx failed: {result.stderr}", "http_data": []}

    except subprocess.TimeoutExpired:
        return {"error": "HTTPx scan timed out", "http_data": []}
    except Exception as e:
        return {"error": f"HTTPx scan failed: {str(e)}", "http_data": []}


def run_dnsx_windows(target: str) -> Dict[str, Any]:
    """
    Run DNSx for DNS resolution using Windows executable
    """
    print(f"🔍 Running DNSx DNS analysis on {target}...")

    try:
        tools_dir = os.path.join(os.getcwd(), "tools")
        dnsx_exe = os.path.join(tools_dir, "dnsx.exe")

        if not os.path.exists(dnsx_exe):
            return {"error": f"DNSx executable not found at {dnsx_exe}"}

        cmd = [
            dnsx_exe,
            "-d",
            target,
            "-json",
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-txt",
            "-retry",
            "2",
            "-timeout",
            "10",
        ]

        print(f"🔧 Executing DNSx: {' '.join(cmd[:3])}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=tools_dir
        )

        if result.returncode == 0 and result.stdout:
            # Parse JSON lines
            dns_data = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        dns_data.append(data)
                    except json.JSONDecodeError:
                        continue

            return {"dns_data": dns_data, "count": len(dns_data)}
        else:
            return {"error": f"DNSx failed: {result.stderr}", "dns_data": []}

    except subprocess.TimeoutExpired:
        return {"error": "DNSx scan timed out", "dns_data": []}
    except Exception as e:
        return {"error": f"DNSx scan failed: {str(e)}", "dns_data": []}


def create_basic_wordlist() -> str:
    """
    Create a basic wordlist for FFUF if none exists
    """
    tools_dir = os.path.join(os.getcwd(), "tools")
    wordlist_path = os.path.join(tools_dir, "basic_wordlist.txt")

    if not os.path.exists(wordlist_path):
        basic_words = [
            "admin",
            "administrator",
            "login",
            "dashboard",
            "panel",
            "config",
            "setup",
            "install",
            "test",
            "api",
            "docs",
            "help",
            "support",
            "backup",
            "uploads",
            "files",
            "images",
            "css",
            "js",
            "assets",
            "wp-admin",
            "wp-content",
            "wp-includes",
            "phpmyadmin",
            "robots.txt",
            "sitemap.xml",
            ".htaccess",
            "web.config",
        ]

        try:
            with open(wordlist_path, "w") as f:
                for word in basic_words:
                    f.write(f"{word}\n")
            print(f"✅ Created basic wordlist at {wordlist_path}")
        except Exception as e:
            print(f"❌ Failed to create wordlist: {e}")
            return None

    return wordlist_path


if __name__ == "__main__":
    # Test the tools
    test_target = "www.iitm.ac.in"

    print("Testing Windows-compatible security tools:")
    print("=" * 50)

    # Test HTTPx
    httpx_result = run_httpx_windows(test_target)
    print(f"HTTPx result: {httpx_result}")

    print("=" * 50)
