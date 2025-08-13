#!/usr/bin/env python3
"""
Path Verification Script
Verifies that all tool paths are dynamic and work properly across environments
"""

import os
import sys
import platform
import subprocess
from pathlib import Path

# Add Backend directory to Python path
backend_dir = Path(__file__).parent / "Backend"
sys.path.insert(0, str(backend_dir))

try:
    from config import (
        USERNAME,
        HOME_DIR,
        BASE_WSL_PATH,
        BASE_WINDOWS_PATH,
        SECURITY_TOOLS_DIR,
        PROJECT_ROOT,
        PROJECT_TOOLS_DIR,
        TOOL_PATHS,
        get_tool_path,
        get_wsl_path,
    )
except ImportError as e:
    print(f"❌ Failed to import config: {e}")
    sys.exit(1)


def log_message(level, message):
    """Enhanced logging with colors"""
    colors = {
        "INFO": "\033[36m",  # Cyan
        "SUCCESS": "\033[32m",  # Green
        "WARN": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "RESET": "\033[0m",  # Reset
    }
    color = colors.get(level, colors["INFO"])
    reset = colors["RESET"]
    print(f"{color}[{level}] {message}{reset}")


def check_command_available(command):
    """Check if a command is available in system PATH"""
    try:
        subprocess.run(
            [command, "--version"], capture_output=True, check=False, timeout=10
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def check_file_exists(filepath):
    """Check if file exists with proper path resolution"""
    if not filepath:
        return False
    try:
        return os.path.exists(filepath) and os.path.isfile(filepath)
    except (OSError, TypeError):
        return False


def verify_environment():
    """Verify the current environment configuration"""
    log_message("INFO", "=== Environment Verification ===")

    log_message("INFO", f"Platform: {platform.system()}")
    log_message("INFO", f"Username: {USERNAME}")
    log_message("INFO", f"Home Directory: {HOME_DIR}")
    log_message("INFO", f"Project Root: {PROJECT_ROOT}")
    log_message("INFO", f"Project Tools Dir: {PROJECT_TOOLS_DIR}")
    log_message("INFO", f"Security Tools Dir: {SECURITY_TOOLS_DIR}")

    # Verify directories
    directories_to_check = {
        "Home Directory": HOME_DIR,
        "Project Root": PROJECT_ROOT,
        "Project Tools Directory": PROJECT_TOOLS_DIR,
        "Security Tools Directory": SECURITY_TOOLS_DIR,
    }

    for name, path in directories_to_check.items():
        if os.path.exists(path):
            log_message("SUCCESS", f"{name}: EXISTS - {path}")
        else:
            log_message("WARN", f"{name}: NOT FOUND - {path}")

    return True


def verify_tool_paths():
    """Verify all configured tool paths"""
    log_message("INFO", "=== Tool Path Verification ===")

    tools_found = 0
    tools_total = len(TOOL_PATHS)

    for tool_name, configured_path in TOOL_PATHS.items():
        log_message("INFO", f"Checking {tool_name}...")

        # Get the dynamic path
        dynamic_path = get_tool_path(tool_name)

        # Check if file exists at configured path
        file_exists = check_file_exists(configured_path)

        # Check if command is available in PATH
        command_available = check_command_available(tool_name)

        # Check dynamic path resolution
        dynamic_exists = (
            check_file_exists(dynamic_path) if dynamic_path != tool_name else False
        )

        if file_exists:
            log_message("SUCCESS", f"  ✅ File exists: {configured_path}")
            tools_found += 1
        elif command_available:
            log_message("SUCCESS", f"  ✅ Available in PATH: {tool_name}")
            tools_found += 1
        elif dynamic_exists:
            log_message("SUCCESS", f"  ✅ Dynamic path works: {dynamic_path}")
            tools_found += 1
        else:
            log_message("WARN", f"  ⚠️ Not found: {tool_name}")
            log_message("INFO", f"    Configured: {configured_path}")
            log_message("INFO", f"    Dynamic: {dynamic_path}")

    success_rate = (tools_found / tools_total) * 100 if tools_total > 0 else 0
    log_message(
        "INFO", f"Tool availability: {tools_found}/{tools_total} ({success_rate:.1f}%)"
    )

    return success_rate >= 70  # Consider 70% success rate as acceptable


def verify_path_conversion():
    """Verify path conversion functions"""
    log_message("INFO", "=== Path Conversion Verification ===")

    test_cases = [
        "C:\\Users\\testuser\\file.txt",
        "C:\\Program Files\\tool\\executable.exe",
        "/home/user/tool",
        "relative/path/tool",
    ]

    for test_path in test_cases:
        wsl_path = get_wsl_path(test_path)
        log_message("INFO", f"Windows: {test_path}")
        log_message("INFO", f"WSL:     {wsl_path}")
        log_message("INFO", "---")

    return True


def verify_dynamic_detection():
    """Verify that paths are truly dynamic (not hardcoded)"""
    log_message("INFO", "=== Dynamic Detection Verification ===")

    # Check if paths contain hardcoded usernames (but not substrings)
    hardcoded_users = ["vedad"]  # Only check for actual hardcoded names, not substrings
    issues_found = 0

    paths_to_check = [
        ("BASE_WSL_PATH", BASE_WSL_PATH),
        ("BASE_WINDOWS_PATH", BASE_WINDOWS_PATH),
        ("SECURITY_TOOLS_DIR", SECURITY_TOOLS_DIR),
        ("PROJECT_TOOLS_DIR", PROJECT_TOOLS_DIR),
    ]

    for name, path in paths_to_check:
        path_str = str(path)
        # Split path and check for exact username matches in path components
        path_components = path_str.replace("\\", "/").split("/")
        found_hardcoded = False

        for hardcoded_user in hardcoded_users:
            if hardcoded_user in path_components and hardcoded_user != USERNAME:
                log_message(
                    "ERROR",
                    f"{name} contains hardcoded user '{hardcoded_user}': {path}",
                )
                issues_found += 1
                found_hardcoded = True
                break

        if not found_hardcoded:
            log_message("SUCCESS", f"{name} looks dynamic: {path}")

    # Check USERNAME detection
    if USERNAME and USERNAME != "defaultuser":
        log_message("SUCCESS", f"Username detected dynamically: {USERNAME}")
    else:
        log_message("WARN", f"Username detection may have issues: {USERNAME}")
        issues_found += 1

    return issues_found == 0


def verify_docker_compatibility():
    """Verify Docker environment compatibility"""
    log_message("INFO", "=== Docker Compatibility Verification ===")

    # Check if we're in a Docker environment
    docker_indicators = [
        "/.dockerenv",
        "/proc/1/cgroup",  # Docker containers usually have docker in cgroup
    ]

    in_docker = False
    for indicator in docker_indicators:
        if os.path.exists(indicator):
            in_docker = True
            break

    if in_docker:
        log_message("INFO", "Docker environment detected")

        # In Docker, tools should be in /usr/local/bin or similar
        docker_tool_paths = ["/usr/local/bin", "/usr/bin", "/bin"]
        for path in docker_tool_paths:
            if os.path.exists(path):
                log_message("SUCCESS", f"Docker tool path exists: {path}")
            else:
                log_message("WARN", f"Docker tool path not found: {path}")
    else:
        log_message("INFO", "Not in Docker environment")

    return True


def main():
    """Main verification function"""
    log_message("INFO", "🔍 Starting Path Verification...")
    log_message("INFO", "=" * 50)

    tests = [
        ("Environment", verify_environment),
        ("Tool Paths", verify_tool_paths),
        ("Path Conversion", verify_path_conversion),
        ("Dynamic Detection", verify_dynamic_detection),
        ("Docker Compatibility", verify_docker_compatibility),
    ]

    passed_tests = 0
    total_tests = len(tests)

    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                log_message("SUCCESS", f"✅ {test_name}: PASSED")
                passed_tests += 1
            else:
                log_message("ERROR", f"❌ {test_name}: FAILED")
        except Exception as e:
            log_message("ERROR", f"❌ {test_name}: ERROR - {e}")

        log_message("INFO", "-" * 30)

    # Final summary
    log_message("INFO", "=" * 50)
    success_rate = (passed_tests / total_tests) * 100
    if success_rate >= 80:
        log_message(
            "SUCCESS",
            f"🎉 Overall: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)",
        )
        log_message("SUCCESS", "✅ Path configuration appears to be working correctly!")
    else:
        log_message(
            "WARN",
            f"⚠️ Overall: {passed_tests}/{total_tests} tests passed ({success_rate:.1f}%)",
        )
        log_message("WARN", "Some issues were found. Check the logs above.")

    # Provide next steps
    log_message("INFO", "\n📋 Next Steps:")
    log_message("INFO", "1. Run installation scripts if tools are missing")
    log_message("INFO", "2. Check Docker deployment: docker-compose up")
    log_message("INFO", "3. Test the application functionality")

    return success_rate >= 80


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        log_message("INFO", "\nVerification interrupted by user")
        sys.exit(1)
    except Exception as e:
        log_message("ERROR", f"Verification failed with error: {e}")
        sys.exit(1)
