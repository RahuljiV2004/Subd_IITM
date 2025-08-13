#!/usr/bin/env python3

"""
Tool verification script for Subdomain Scanner
This script checks if all required tools are properly installed and configured
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

# Add the backend directory to Python path
backend_dir = Path(__file__).parent / "Backend"
sys.path.append(str(backend_dir))

try:
    from config import TOOL_PATHS, get_tool_path

    print("✅ Configuration loaded successfully")
except ImportError as e:
    print(f"❌ Failed to load configuration: {e}")
    sys.exit(1)


def run_command(command, shell=False):
    """Run a command and return success status and output"""
    try:
        if isinstance(command, str):
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=10
            )
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timeout"
    except Exception as e:
        return False, str(e)


def check_python_packages():
    """Check if required Python packages are installed"""
    print("\n🐍 Checking Python packages...")

    required_packages = [
        "flask",
        "pymongo",
        "requests",
        "celery",
        "redis",
        "bcrypt",
        "flask-cors",
        "flask-jwt-extended",
        "python-owasp-zap-v2.4",
        "python-nmap",
        "flask-mail",
        "dnspython",
        "cohere",
    ]

    missing_packages = []
    for package in required_packages:
        try:
            __import__(package.replace("-", "_").replace(".", "_"))
            print(f"   ✅ {package}")
        except ImportError:
            print(f"   ❌ {package}")
            missing_packages.append(package)

    if missing_packages:
        print(f"\n⚠️ Missing packages: {', '.join(missing_packages)}")
        print("   Install with: pip install " + " ".join(missing_packages))
    return len(missing_packages) == 0


def check_docker():
    """Check if Docker is running and accessible"""
    print("\n🐳 Checking Docker...")

    success, output = run_command("docker --version")
    if not success:
        print("   ❌ Docker not found or not running")
        return False

    print(f"   ✅ Docker installed: {output.strip()}")

    # Check if Docker is running
    success, output = run_command("docker ps")
    if not success:
        print("   ⚠️ Docker daemon might not be running")
        print("   Start Docker Desktop and try again")
        return False

    print("   ✅ Docker daemon is running")
    return True


def check_wsl_tool(tool_name, command):
    """Check if a WSL-based tool is accessible"""
    tool_path = get_tool_path(tool_name)

    # Test direct path
    if os.path.exists(tool_path.replace("/mnt/c/", "C:\\")):
        wsl_command = f'wsl bash -c "{command}"'
        success, output = run_command(wsl_command)
        if success:
            print(f"   ✅ {tool_name}: {tool_path}")
            return True
        else:
            print(f"   ❌ {tool_name}: Path exists but command failed")
            print(f"      Error: {output[:100]}...")
            return False
    else:
        print(f"   ❌ {tool_name}: Path not found - {tool_path}")
        return False


def check_windows_tool(tool_name, command):
    """Check if a Windows-based tool is accessible"""
    tool_path = get_tool_path(tool_name)

    if os.path.exists(tool_path):
        success, output = run_command(command)
        if success:
            print(f"   ✅ {tool_name}: {tool_path}")
            return True
        else:
            print(f"   ❌ {tool_name}: Path exists but command failed")
            print(f"      Error: {output[:100]}...")
            return False
    else:
        print(f"   ❌ {tool_name}: Path not found - {tool_path}")
        return False


def check_system_tool(tool_name, command):
    """Check if a system tool is in PATH"""
    success, output = run_command(command)
    if success:
        print(f"   ✅ {tool_name}: Available in system PATH")
        return True
    else:
        print(f"   ❌ {tool_name}: Not found in system PATH")
        return False


def main():
    print("🔍 Subdomain Scanner - Tool Verification")
    print("=" * 50)

    all_checks_passed = True

    # Check Python packages
    if not check_python_packages():
        all_checks_passed = False

    # Check Docker
    if not check_docker():
        all_checks_passed = False

    # Check WSL tools
    print("\n🐧 Checking WSL-based tools...")
    wsl_tools = [
        ("nikto", "perl --version"),
        ("testssl", "bash --version"),
    ]

    for tool_name, test_command in wsl_tools:
        if not check_wsl_tool(tool_name, test_command):
            all_checks_passed = False

    # Check Windows tools
    print("\n🪟 Checking Windows-based tools...")
    windows_tools = [
        ("whatweb", "ruby --version"),
    ]

    for tool_name, test_command in windows_tools:
        if not check_windows_tool(tool_name, test_command):
            all_checks_passed = False

    # Check system tools
    print("\n🛠️ Checking system tools...")
    system_tools = [
        ("nmap", "nmap --version"),
        ("wpscan", "wpscan --version"),
    ]

    for tool_name, command in system_tools:
        if not check_system_tool(tool_name, command):
            all_checks_passed = False

    # Check project tools
    print("\n📦 Checking project tools...")
    project_tools = ["subfinder", "dnsx", "httpx"]

    for tool_name in project_tools:
        tool_path = get_tool_path(tool_name)
        if os.path.exists(tool_path):
            print(f"   ✅ {tool_name}: {tool_path}")
        else:
            print(f"   ❌ {tool_name}: Not found - {tool_path}")
            all_checks_passed = False

    # Summary
    print("\n" + "=" * 50)
    if all_checks_passed:
        print("🎉 All tools are properly configured!")
        print("You can now run the application with: docker-compose up")
    else:
        print("⚠️ Some tools need attention. Please:")
        print("1. Run the installation scripts if you haven't already")
        print("2. Check the SETUP_GUIDE.md for detailed instructions")
        print("3. Update the config.py file with correct paths")
        print("4. Ensure WSL, Docker, and all dependencies are properly installed")

    return all_checks_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
