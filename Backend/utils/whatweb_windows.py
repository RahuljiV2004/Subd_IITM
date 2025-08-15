#!/usr/bin/env python3
"""
Windows-compatible WhatWeb technology fingerprinting scanner
Uses the available WhatWeb tool without WSL dependency
"""

import subprocess
import json
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), "..", ".."))


def run_whatweb_scan(target_url):
    """
    Run WhatWeb technology fingerprinting scan on Windows
    """
    print(f"🔍 Running WhatWeb technology scan on {target_url}...")

    try:
        tools_dir = os.path.join(os.getcwd(), "tools")
        whatweb_script = os.path.join(tools_dir, "whatweb", "whatweb")

        # Check if WhatWeb exists
        if not os.path.exists(whatweb_script):
            print(f"❌ WhatWeb not found at {whatweb_script}")
            return run_simple_web_analysis(target_url)

        # Try using Ruby to run WhatWeb
        cmd = [
            "ruby",
            whatweb_script,
            "--log-json=-",
            "--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            target_url,
        ]

        print(f"🔧 Executing: {' '.join(cmd[:3])}")

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60, cwd=tools_dir
        )

        if result.returncode == 0 and result.stdout:
            # Parse JSON output
            parsed_results = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        data = json.loads(line)
                        parsed_results.append(data)
                    except json.JSONDecodeError:
                        continue

            if parsed_results:
                print(f"✅ WhatWeb scan completed for {target_url}")
                return format_whatweb_results(target_url, parsed_results)
            else:
                print("⚠️ No valid JSON output from WhatWeb, using fallback")
                return run_simple_web_analysis(target_url)
        else:
            print(f"⚠️ WhatWeb execution failed, using fallback analysis")
            print(f"Return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return run_simple_web_analysis(target_url)

    except FileNotFoundError:
        print("❌ Ruby not found, using simple web analysis")
        return run_simple_web_analysis(target_url)
    except subprocess.TimeoutExpired:
        print("⏱️ WhatWeb scan timed out, using fallback")
        return run_simple_web_analysis(target_url)
    except Exception as e:
        print(f"❌ WhatWeb scan failed: {e}")
        return run_simple_web_analysis(target_url)


def format_whatweb_results(target_url, results):
    """Format WhatWeb JSON results into readable output"""
    output = f"=== WhatWeb Technology Analysis for {target_url} ===\n"

    technologies = []
    plugins_info = {}

    for result in results:
        target = result.get("target", target_url)
        plugins = result.get("plugins", {})

        output += f"Target: {target}\n"
        output += f"HTTP Status: {result.get('http_status', 'Unknown')}\n"
        output += f"Request Time: {result.get('request_config', {}).get('timeout', 'Unknown')}s\n\n"

        if plugins:
            output += "=== Technologies Detected ===\n"
            for plugin_name, plugin_data in plugins.items():
                technologies.append(plugin_name)

                if isinstance(plugin_data, dict):
                    version = (
                        plugin_data.get("version", [""])[0]
                        if plugin_data.get("version")
                        else ""
                    )
                    string = (
                        plugin_data.get("string", [""])[0]
                        if plugin_data.get("string")
                        else ""
                    )

                    tech_info = plugin_name
                    if version:
                        tech_info += f" {version}"
                    if string and string != version:
                        tech_info += f" ({string})"

                    output += f"- {tech_info}\n"
                    plugins_info[plugin_name] = plugin_data
                else:
                    output += f"- {plugin_name}\n"

        else:
            output += "⚠️ No technologies detected\n"

    if len(technologies) > 0:
        output += f"\n=== Summary ===\n"
        output += f"Total technologies detected: {len(technologies)}\n"
        output += f"Technologies: {', '.join(technologies[:10])}"
        if len(technologies) > 10:
            output += f" (and {len(technologies) - 10} more)"
        output += "\n"

    return output


def run_simple_web_analysis(target_url):
    """
    Simple web technology analysis using curl and basic detection
    """
    print(f"🔧 Running simple web analysis on {target_url}...")

    try:
        # Get HTTP headers and basic response
        cmd = [
            "curl",
            "-I",
            "-L",
            "-A",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "--max-time",
            "30",
            target_url,
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)

        if result.returncode == 0:
            headers = result.stdout.lower()

            output = f"=== Simple Web Analysis for {target_url} ===\n"
            output += f"HTTP Headers Analysis:\n{result.stdout}\n"

            # Basic technology detection from headers
            technologies = []

            if "server:" in headers:
                server_line = [
                    line
                    for line in result.stdout.split("\n")
                    if "server:" in line.lower()
                ]
                if server_line:
                    server = server_line[0].split(":", 1)[1].strip()
                    technologies.append(f"Server: {server}")

            if "x-powered-by:" in headers:
                powered_by_line = [
                    line
                    for line in result.stdout.split("\n")
                    if "x-powered-by:" in line.lower()
                ]
                if powered_by_line:
                    powered_by = powered_by_line[0].split(":", 1)[1].strip()
                    technologies.append(f"X-Powered-By: {powered_by}")

            # Detect common technologies from headers
            if "php" in headers:
                technologies.append("PHP")
            if "apache" in headers:
                technologies.append("Apache")
            if "nginx" in headers:
                technologies.append("Nginx")
            if "iis" in headers:
                technologies.append("IIS")
            if "cloudflare" in headers:
                technologies.append("Cloudflare")

            if technologies:
                output += f"\n=== Technologies Detected ===\n"
                for tech in technologies:
                    output += f"- {tech}\n"
            else:
                output += f"\n⚠️ No obvious technologies detected from headers\n"

            return output
        else:
            return f"❌ Failed to analyze {target_url}: {result.stderr}"

    except Exception as e:
        return f"❌ Web analysis failed: {str(e)}"


if __name__ == "__main__":
    # Test the scanner
    test_url = "https://www.iitm.ac.in"
    result = run_whatweb_scan(test_url)
    print("Result:", result)
