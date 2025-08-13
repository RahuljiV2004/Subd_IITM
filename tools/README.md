# Security Tools Directory

This directory contains security testing tools used by the vulnerability scanner.

## Tool Installation

The tools are automatically installed using the provided scripts:

- **Windows**: `.\install_tools_windows_docker.ps1` or `.\fix_missing_tools.ps1`
- **WSL/Linux**: `./install_tools_wsl.sh`

## Included Tools

- **nuclei** - Fast vulnerability scanner
- **ffuf** - Fast web fuzzer  
- **nikto** - Web vulnerability scanner
- **testssl** - SSL/TLS tester
- **httpx** - HTTP toolkit
- **dnsx** - DNS toolkit
- **subfinder** - Subdomain discovery tool

## Note

Binary files are excluded from git due to size limits. Run the installation scripts to download and set up all tools automatically.
