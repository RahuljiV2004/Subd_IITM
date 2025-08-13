"""
Configuration file for paths and tool locations
Adjust these paths according to your system setup
"""

import os
import platform

# User-specific paths - Auto-detect username and system paths
USERNAME = os.getenv("USER") or os.getenv("USERNAME") or "defaultuser"
HOME_DIR = os.path.expanduser("~")

# Dynamic path detection based on environment
if platform.system() == "Windows":
    BASE_WSL_PATH = f"/mnt/c/Users/{USERNAME}"
    BASE_WINDOWS_PATH = f"C:\\Users\\{USERNAME}"
    SECURITY_TOOLS_DIR = f"{BASE_WINDOWS_PATH}\\security-tools"
else:
    # For Docker/Linux environments
    BASE_WSL_PATH = HOME_DIR
    BASE_WINDOWS_PATH = HOME_DIR
    SECURITY_TOOLS_DIR = f"{HOME_DIR}/security-tools"

# Project root directory detection
# Get the parent directory of the Backend folder (which should be the project root)
CURRENT_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_FILE_DIR)
PROJECT_TOOLS_DIR = os.path.join(PROJECT_ROOT, "tools")


# Tool installation paths - Auto-detected based on environment
def get_tool_executable(tool_name, prefer_system=True):
    """Get tool executable with proper extension for current platform"""
    if platform.system() == "Windows" and not tool_name.endswith(".exe"):
        return f"{tool_name}.exe"
    return tool_name


TOOL_PATHS = {
    # Tools that should be installed in WSL/Linux environments
    "nikto": f"{BASE_WSL_PATH}/security-tools/nikto/program/nikto.pl",
    "testssl": f"{BASE_WSL_PATH}/security-tools/testssl.sh/testssl.sh",
    "nmap": "nmap",  # Should be available in system PATH after installation
    # Tools that can be installed on Windows
    "whatweb": os.path.join(SECURITY_TOOLS_DIR, "WhatWeb-master", "whatweb"),
    "wpscan": "wpscan",  # If installed via gem
    # Tools in project directory (platform-aware)
    "subfinder": os.path.join(PROJECT_TOOLS_DIR, get_tool_executable("subfinder")),
    "dnsx": os.path.join(PROJECT_TOOLS_DIR, get_tool_executable("dnsx")),
    "httpx": os.path.join(PROJECT_TOOLS_DIR, get_tool_executable("httpx")),
    # Additional tools that might be installed
    "ffuf": os.path.join(PROJECT_TOOLS_DIR, get_tool_executable("ffuf")),
    "nuclei": os.path.join(PROJECT_TOOLS_DIR, get_tool_executable("nuclei")),
}

# Database configuration
MONGO_CONFIG = {
    "uri": os.getenv("MONGO_URI", "mongodb://localhost:27017/"),
    "database": "subdomain_scanner",
    "collections": {"users": "users", "scan_results": "scan_results_subfinder"},
}

# Redis configuration
REDIS_CONFIG = {
    "url": os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    "host": "localhost",
    "port": 6379,
    "db": 0,
}


def get_tool_path(tool_name):
    """Get the full path for a tool with fallback options"""
    # Check if tool is in TOOL_PATHS
    if tool_name in TOOL_PATHS:
        tool_path = TOOL_PATHS[tool_name]
        if os.path.exists(tool_path):
            return tool_path

    # Check if tool is available in system PATH
    executable_name = get_tool_executable(tool_name)
    if platform.system() == "Windows":
        # For Windows, check both with and without .exe
        for name in [executable_name, tool_name]:
            try:
                import shutil

                if shutil.which(name):
                    return name
            except Exception:
                pass
    else:
        # For Linux/Docker
        try:
            import shutil

            if shutil.which(tool_name):
                return tool_name
        except Exception:
            pass

    # Return the configured path as fallback
    return TOOL_PATHS.get(tool_name, tool_name)


def get_wsl_path(windows_path):
    """Convert Windows path to WSL path"""
    if not windows_path or not isinstance(windows_path, str):
        return windows_path

    if platform.system() != "Windows" and not windows_path.startswith("C:\\"):
        return windows_path

    wsl_path = windows_path.replace("C:\\", "/mnt/c/").replace("\\", "/")
    return wsl_path


def get_project_tools_dir():
    """Get the project tools directory path"""
    return PROJECT_TOOLS_DIR


def ensure_tools_directory():
    """Ensure the tools directory exists"""
    os.makedirs(PROJECT_TOOLS_DIR, exist_ok=True)
    return PROJECT_TOOLS_DIR
