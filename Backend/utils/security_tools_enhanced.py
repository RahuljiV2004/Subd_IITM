"""
Enhanced Security Tools Manager - Windows + WSL Support
Provides comprehensive fallback mechanisms for maximum compatibility
"""

import os
import sys
import json
import subprocess
import platform
import shutil
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import logging
import tempfile

logger = logging.getLogger(__name__)


class SecurityToolsManager:
    """
    Comprehensive security tools manager supporting both Windows native and WSL tools
    """

    def __init__(self, tools_dir: str = "tools"):
        self.tools_dir = Path(tools_dir)
        self.windows_tools = {}
        self.wsl_tools = {}
        self.wsl_available = self._check_wsl_available()
        self.setup_tools()

    def _check_wsl_available(self) -> bool:
        """Check if WSL is available and working"""
        try:
            result = subprocess.run(
                ["wsl", "--status"], capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception as e:
            logger.debug(f"WSL not available: {e}")
            return False

    def setup_tools(self):
        """Setup tool paths for both Windows and WSL"""
        # Get the project root directory (go up from Backend/utils to project root)
        project_root = Path(__file__).parent.parent.parent
        tools_dir = project_root / "tools"

        # Windows native tools
        self.windows_tools = {
            "ffuf": tools_dir / "ffuf.exe",
            "nuclei": tools_dir / "nuclei.exe",
            "httpx": tools_dir / "httpx.exe",
            "dnsx": tools_dir / "dnsx.exe",
            "subfinder": tools_dir / "subfinder.exe",
            "nikto": tools_dir / "nikto" / "program" / "nikto.pl",
            "whatweb": tools_dir / "whatweb" / "whatweb",
            "testssl": tools_dir / "testssl" / "testssl.sh",
        }

        # WSL tools (using standard Linux paths)
        self.wsl_tools = {
            "ffuf": "ffuf",
            "nuclei": "nuclei",
            "httpx": "httpx",
            "dnsx": "dnsx",
            "subfinder": "subfinder",
            "nikto": "nikto",
            "whatweb": "whatweb",
            "testssl": "~/tools/testssl/testssl.sh",
            "nmap": "nmap",
        }

    def _run_windows_command(self, cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run Windows native command"""
        try:
            logger.debug(f"Running Windows command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, shell=False
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "method": "windows_native",
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"Command timed out after {timeout} seconds",
                "method": "windows_native",
            }
        except Exception as e:
            return {"success": False, "error": str(e), "method": "windows_native"}

    def _run_wsl_command(self, cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run command via WSL"""
        if not self.wsl_available:
            return {"success": False, "error": "WSL not available", "method": "wsl"}

        try:
            # Construct WSL command with Ubuntu distribution
            wsl_cmd = ["wsl", "-d", "Ubuntu"] + cmd
            logger.debug(f"Running WSL command: {' '.join(wsl_cmd)}")

            result = subprocess.run(
                wsl_cmd, capture_output=True, text=True, timeout=timeout, shell=False
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "method": "wsl",
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": f"WSL command timed out after {timeout} seconds",
                "method": "wsl",
            }
        except Exception as e:
            return {"success": False, "error": str(e), "method": "wsl"}

    def run_ffuf(
        self, target: str, wordlist: Optional[str] = None, **kwargs
    ) -> Dict[str, Any]:
        """Run FFUF with Windows/WSL fallback"""

        # Prepare basic wordlist if none provided
        if not wordlist:
            wordlist = self._create_basic_wordlist()

        base_args = [
            "-u",
            f"{target}/FUZZ",
            "-w",
            wordlist,
            "-o",
            "-",
            "-of",
            "json",
            "-t",
            "10",
            "-timeout",
            "10",
        ]

        # Try Windows first
        windows_path = self.windows_tools["ffuf"]
        if windows_path.exists():
            cmd = [str(windows_path)] + base_args
            result = self._run_windows_command(cmd, timeout=60)
            if result["success"]:
                return self._parse_ffuf_output(result["stdout"], result["method"])

        # Fallback to WSL
        if self.wsl_available:
            cmd = [self.wsl_tools["ffuf"]] + base_args
            result = self._run_wsl_command(cmd, timeout=60)
            if result["success"]:
                return self._parse_ffuf_output(result["stdout"], result["method"])

        return {"error": "FFUF not available via Windows or WSL", "results": []}

    def run_nuclei(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run Nuclei with Windows/WSL fallback"""

        base_args = ["-target", target, "-json", "-silent", "-timeout", "10"]

        # Add template selection if specified
        if "templates" in kwargs:
            base_args.extend(["-t", kwargs["templates"]])

        # Try Windows first
        windows_path = self.windows_tools["nuclei"]
        if windows_path.exists():
            cmd = [str(windows_path)] + base_args
            result = self._run_windows_command(cmd, timeout=120)
            if result["success"]:
                return self._parse_nuclei_output(result["stdout"], result["method"])

        # Fallback to WSL
        if self.wsl_available:
            cmd = [self.wsl_tools["nuclei"]] + base_args
            result = self._run_wsl_command(cmd, timeout=120)
            if result["success"]:
                return self._parse_nuclei_output(result["stdout"], result["method"])

        return {"error": "Nuclei not available via Windows or WSL", "results": []}

    def run_httpx(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run HTTPx with Windows/WSL fallback"""

        base_args = [
            "-target",
            target,
            "-json",
            "-silent",
            "-timeout",
            "10",
            "-retries",
            "2",
        ]

        # Try Windows first
        windows_path = self.windows_tools["httpx"]
        if windows_path.exists():
            cmd = [str(windows_path)] + base_args
            result = self._run_windows_command(cmd, timeout=30)
            if result["success"]:
                return self._parse_httpx_output(result["stdout"], result["method"])

        # Fallback to WSL
        if self.wsl_available:
            cmd = [self.wsl_tools["httpx"]] + base_args
            result = self._run_wsl_command(cmd, timeout=30)
            if result["success"]:
                return self._parse_httpx_output(result["stdout"], result["method"])

        return {"error": "HTTPx not available via Windows or WSL", "results": []}

    def run_nikto(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run Nikto with Windows/WSL fallback"""

        base_args = ["-h", target, "-Format", "txt"]

        # Try Windows (Perl) first
        windows_path = self.windows_tools["nikto"]
        if windows_path.exists() and shutil.which("perl"):
            cmd = ["perl", str(windows_path)] + base_args
            result = self._run_windows_command(cmd, timeout=180)
            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "method": result["method"],
                    "tool_version": "nikto_perl",
                }

        # Fallback to WSL
        if self.wsl_available:
            cmd = [self.wsl_tools["nikto"]] + base_args
            result = self._run_wsl_command(cmd, timeout=180)
            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "method": result["method"],
                    "tool_version": "nikto_wsl",
                }

        # Last resort: simple HTTP analysis
        return self._run_simple_http_analysis(target)

    def run_whatweb(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run WhatWeb with Windows/WSL fallback"""

        base_args = [target, "--format", "json"]

        # Try Windows (Ruby) first
        windows_path = self.windows_tools["whatweb"]
        if windows_path.exists() and shutil.which("ruby"):
            cmd = ["ruby", str(windows_path)] + base_args
            result = self._run_windows_command(cmd, timeout=30)
            if result["success"]:
                return self._parse_whatweb_output(result["stdout"], result["method"])

        # Fallback to WSL
        if self.wsl_available:
            cmd = [self.wsl_tools["whatweb"]] + base_args
            result = self._run_wsl_command(cmd, timeout=30)
            if result["success"]:
                return self._parse_whatweb_output(result["stdout"], result["method"])

        # Last resort: header analysis
        return self._run_simple_header_analysis(target)

    def run_testssl(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run testssl.sh with WSL fallback to Python SSL analysis"""

        # Try WSL first for testssl.sh
        if self.wsl_available:
            base_args = [self.wsl_tools["testssl"], target]
            result = self._run_wsl_command(base_args, timeout=120)
            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "method": result["method"],
                    "tool_version": "testssl_wsl",
                }

        # Fallback to Windows testssl.sh (if available)
        windows_path = self.windows_tools["testssl"]
        if windows_path.exists():
            if self.wsl_available:
                # Try to run via WSL even if it's Windows path
                cmd = ["wsl", "bash", str(windows_path), target]
                result = self._run_windows_command(cmd, timeout=120)
                if result["success"]:
                    return {
                        "success": True,
                        "output": result["stdout"],
                        "method": "windows_wsl_hybrid",
                        "tool_version": "testssl_bash",
                    }

        # Final fallback: Python SSL analysis
        return self._run_python_ssl_analysis(target)

    def run_nmap(self, target: str, **kwargs) -> Dict[str, Any]:
        """Run Nmap (WSL preferred, Windows if available)"""

        scan_type = kwargs.get("scan_type", "basic")

        if scan_type == "basic":
            base_args = ["-sV", "-sC", "--top-ports", "1000", target]
        elif scan_type == "fast":
            base_args = ["-F", target]
        else:
            base_args = ["-sV", "-A", target]

        # Try WSL first (usually better for Nmap)
        if self.wsl_available:
            cmd = [self.wsl_tools["nmap"]] + base_args
            result = self._run_wsl_command(cmd, timeout=300)
            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "method": result["method"],
                    "tool_version": "nmap_wsl",
                }

        # Try Windows Nmap if available
        if shutil.which("nmap"):
            cmd = ["nmap"] + base_args
            result = self._run_windows_command(cmd, timeout=300)
            if result["success"]:
                return {
                    "success": True,
                    "output": result["stdout"],
                    "method": result["method"],
                    "tool_version": "nmap_windows",
                }

        return {"error": "Nmap not available via Windows or WSL", "results": []}

    # Helper methods for parsing outputs
    def _parse_ffuf_output(self, output: str, method: str) -> Dict[str, Any]:
        """Parse FFUF JSON output"""
        try:
            results = []
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue

            return {
                "success": True,
                "results": results,
                "method": method,
                "tool_version": "ffuf",
            }
        except Exception as e:
            return {"error": f"Failed to parse FFUF output: {e}", "results": []}

    def _parse_nuclei_output(self, output: str, method: str) -> Dict[str, Any]:
        """Parse Nuclei JSON output"""
        try:
            results = []
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue

            return {
                "success": True,
                "results": results,
                "method": method,
                "tool_version": "nuclei",
            }
        except Exception as e:
            return {"error": f"Failed to parse Nuclei output: {e}", "results": []}

    def _parse_httpx_output(self, output: str, method: str) -> Dict[str, Any]:
        """Parse HTTPx JSON output"""
        try:
            results = []
            for line in output.strip().split("\n"):
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append(data)
                    except json.JSONDecodeError:
                        continue

            return {
                "success": True,
                "results": results,
                "method": method,
                "tool_version": "httpx",
            }
        except Exception as e:
            return {"error": f"Failed to parse HTTPx output: {e}", "results": []}

    def _parse_whatweb_output(self, output: str, method: str) -> Dict[str, Any]:
        """Parse WhatWeb JSON output"""
        try:
            data = json.loads(output)
            return {
                "success": True,
                "results": data if isinstance(data, list) else [data],
                "method": method,
                "tool_version": "whatweb",
            }
        except Exception as e:
            return {"error": f"Failed to parse WhatWeb output: {e}", "results": []}

    def _create_basic_wordlist(self) -> str:
        """Create a basic wordlist for FFUF"""
        common_paths = [
            "admin",
            "api",
            "backup",
            "config",
            "login",
            "panel",
            "test",
            "dev",
            "staging",
            "debug",
            "tmp",
            "logs",
            "uploads",
            "download",
            "wp-admin",
            "administrator",
            "phpmyadmin",
            ".git",
            ".env",
        ]

        wordlist_path = Path(tempfile.gettempdir()) / "basic_wordlist.txt"
        with open(wordlist_path, "w") as f:
            for path in common_paths:
                f.write(f"{path}\n")

        return str(wordlist_path)

    def _run_simple_http_analysis(self, target: str) -> Dict[str, Any]:
        """Simple HTTP analysis as Nikto fallback"""
        try:
            import requests

            response = requests.get(target, timeout=10, verify=False)

            analysis = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "server": response.headers.get("Server", "Unknown"),
                "powered_by": response.headers.get("X-Powered-By", "Unknown"),
                "content_length": len(response.content),
            }

            return {
                "success": True,
                "output": f"Simple HTTP Analysis Results:\n{json.dumps(analysis, indent=2)}",
                "method": "python_requests",
                "tool_version": "simple_http_analysis",
            }
        except Exception as e:
            return {"error": f"Simple HTTP analysis failed: {e}", "results": []}

    def _run_simple_header_analysis(self, target: str) -> Dict[str, Any]:
        """Simple header analysis as WhatWeb fallback"""
        try:
            import requests

            response = requests.get(target, timeout=10, verify=False)

            technologies = []

            # Basic technology detection
            server = response.headers.get("Server", "").lower()
            if "nginx" in server:
                technologies.append("Nginx")
            if "apache" in server:
                technologies.append("Apache")
            if "iis" in server:
                technologies.append("IIS")

            powered_by = response.headers.get("X-Powered-By", "").lower()
            if "php" in powered_by:
                technologies.append("PHP")
            if "asp.net" in powered_by:
                technologies.append("ASP.NET")

            return {
                "success": True,
                "results": [
                    {
                        "target": target,
                        "plugins": {
                            "HTTPServer": [server] if server else [],
                            "PoweredBy": [powered_by] if powered_by else [],
                            "Technologies": technologies,
                        },
                    }
                ],
                "method": "python_requests",
                "tool_version": "simple_header_analysis",
            }
        except Exception as e:
            return {"error": f"Simple header analysis failed: {e}", "results": []}

    def _run_python_ssl_analysis(self, target: str) -> Dict[str, Any]:
        """Python SSL analysis as testssl.sh fallback"""
        try:
            import ssl
            import socket
            from urllib.parse import urlparse

            parsed = urlparse(
                target if target.startswith("http") else f"https://{target}"
            )
            hostname = parsed.hostname or target
            port = parsed.port or 443

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

            analysis = {
                "hostname": hostname,
                "port": port,
                "ssl_version": version,
                "cipher": cipher,
                "certificate": {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "serial_number": cert.get("serialNumber"),
                },
            }

            return {
                "success": True,
                "output": f"Python SSL Analysis Results:\n{json.dumps(analysis, indent=2)}",
                "method": "python_ssl",
                "tool_version": "python_ssl_analysis",
            }
        except Exception as e:
            return {"error": f"Python SSL analysis failed: {e}", "results": []}

    def get_tool_status(self) -> Dict[str, Any]:
        """Get comprehensive tool availability status"""
        status = {
            "wsl_available": self.wsl_available,
            "windows_tools": {},
            "wsl_tools": {},
            "summary": {
                "total_available": 0,
                "windows_available": 0,
                "wsl_available": 0,
            },
        }

        # Check Windows tools
        for tool_name, tool_path in self.windows_tools.items():
            if isinstance(tool_path, Path):
                available = tool_path.exists()
            else:
                available = bool(shutil.which(str(tool_path)))

            status["windows_tools"][tool_name] = {
                "available": available,
                "path": str(tool_path),
            }

            if available:
                status["summary"]["windows_available"] += 1
                status["summary"]["total_available"] += 1

        # Check WSL tools
        if self.wsl_available:
            for tool_name, tool_cmd in self.wsl_tools.items():
                try:
                    result = subprocess.run(
                        ["wsl", "-d", "Ubuntu", "which", tool_cmd],
                        capture_output=True,
                        timeout=5,
                    )
                    available = result.returncode == 0
                except Exception:
                    available = False

                status["wsl_tools"][tool_name] = {
                    "available": available,
                    "command": tool_cmd,
                }

                if available:
                    status["summary"]["wsl_available"] += 1
                    if tool_name not in [
                        t
                        for t, info in status["windows_tools"].items()
                        if info["available"]
                    ]:
                        status["summary"]["total_available"] += 1

        return status


# Global instance for easy access
security_tools = SecurityToolsManager()


# Convenience functions for backward compatibility
def run_ffuf_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_ffuf(target, **kwargs)


def run_nuclei_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_nuclei(target, **kwargs)


def run_httpx_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_httpx(target, **kwargs)


def run_nikto_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_nikto(target, **kwargs)


def run_whatweb_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_whatweb(target, **kwargs)


def run_testssl_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_testssl(target, **kwargs)


def run_nmap_enhanced(target: str, **kwargs) -> Dict[str, Any]:
    return security_tools.run_nmap(target, **kwargs)


def get_tools_status() -> Dict[str, Any]:
    return security_tools.get_tool_status()


if __name__ == "__main__":
    # Test script
    print("🔧 Security Tools Manager - Comprehensive Test")
    print("=" * 50)

    # Show tool status
    status = get_tools_status()
    print(f"WSL Available: {status['wsl_available']}")
    print(f"Total Tools Available: {status['summary']['total_available']}")
    print(f"Windows Tools: {status['summary']['windows_available']}")
    print(f"WSL Tools: {status['summary']['wsl_available']}")

    # Test with a sample target (if provided)
    if len(sys.argv) > 1:
        target = sys.argv[1]
        print(f"\n🎯 Testing tools with target: {target}")

        # Test each tool
        tools_to_test = [
            ("HTTPx", run_httpx_enhanced),
            ("WhatWeb", run_whatweb_enhanced),
            ("Nuclei", run_nuclei_enhanced),
        ]

        for tool_name, tool_func in tools_to_test:
            print(f"\n🔍 Testing {tool_name}...")
            try:
                result = tool_func(target)
                if result.get("success"):
                    print(
                        f"✅ {tool_name} worked via {result.get('method', 'unknown')}"
                    )
                else:
                    print(
                        f"❌ {tool_name} failed: {result.get('error', 'unknown error')}"
                    )
            except Exception as e:
                print(f"❌ {tool_name} exception: {e}")
    else:
        print("\n💡 To test tools, run: python security_tools_enhanced.py <target_url>")
