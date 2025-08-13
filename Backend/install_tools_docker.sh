#!/bin/bash

# Security Tools Installation Script for WSL (Ubuntu)
# Docker-ready automation script for full tool installation
# Run this script in WSL to install all required security tools

set -e  # Exit on any error

# Configuration
SILENT=${1:-false}
DOCKER_MODE=${2:-false}
TOOLS_DIR="$HOME/security-tools"
LOG_FILE="/tmp/install_tools.log"

# Logging function
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [[ "$SILENT" != "true" ]]; then
        case $level in
            "ERROR")   echo -e "\033[31m[$timestamp] ERROR: $message\033[0m" ;;
            "WARN")    echo -e "\033[33m[$timestamp] WARN: $message\033[0m" ;;
            "SUCCESS") echo -e "\033[32m[$timestamp] SUCCESS: $message\033[0m" ;;
            *)         echo -e "\033[36m[$timestamp] INFO: $message\033[0m" ;;
        esac
    fi
    echo "[$timestamp] $level: $message" >> "$LOG_FILE"
}

# Error handling function
handle_error() {
    local exit_code=$?
    local line_number=$1
    log_message "ERROR" "Script failed at line $line_number with exit code $exit_code"
    exit $exit_code
}

trap 'handle_error ${LINENO}' ERR

log_message "INFO" "Starting WSL security tools installation..."

# Check if running in WSL
if ! grep -q Microsoft /proc/version 2>/dev/null && ! grep -q WSL /proc/version 2>/dev/null; then
    log_message "WARN" "This script is designed for WSL. Proceeding anyway..."
fi

# Function to install package with retry logic
install_package() {
    local package=$1
    local max_retries=${2:-3}
    
    for ((i=1; i<=max_retries; i++)); do
        log_message "INFO" "Installing $package (attempt $i/$max_retries)..."
        if apt-get install -y "$package" >> "$LOG_FILE" 2>&1; then
            log_message "SUCCESS" "$package installed successfully"
            return 0
        else
            log_message "WARN" "Attempt $i failed for $package"
            if [[ $i -lt $max_retries ]]; then
                sleep 3
            fi
        fi
    done
    
    log_message "ERROR" "Failed to install $package after $max_retries attempts"
    return 1
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Update system packages
log_message "INFO" "Updating system packages..."
apt-get update >> "$LOG_FILE" 2>&1
if [[ "$DOCKER_MODE" != "true" ]]; then
    apt-get upgrade -y >> "$LOG_FILE" 2>&1
fi

# Install basic dependencies
log_message "INFO" "Installing basic dependencies..."
basic_packages=(
    "curl" "wget" "git" "build-essential" "python3" "python3-pip" 
    "ruby" "ruby-dev" "perl" "openssl" "ca-certificates" "gnupg" "lsb-release"
    "unzip" "zip" "jq" "dnsutils" "net-tools"
)

for package in "${basic_packages[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        install_package "$package" || log_message "WARN" "Failed to install $package, continuing..."
    else
        log_message "SUCCESS" "$package already installed"
    fi
done

# Create security tools directory
log_message "INFO" "Creating security tools directory: $TOOLS_DIR"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

# Install Nikto
log_message "INFO" "Installing Nikto..."
if [[ ! -d "nikto" ]]; then
    if git clone https://github.com/sullo/nikto.git >> "$LOG_FILE" 2>&1; then
        chmod +x nikto/program/nikto.pl
        log_message "SUCCESS" "Nikto installed successfully"
    else
        log_message "ERROR" "Failed to install Nikto"
    fi
else
    log_message "SUCCESS" "Nikto already installed"
fi

# Install testssl.sh
log_message "INFO" "Installing testssl.sh..."
if [[ ! -d "testssl.sh" ]]; then
    if git clone --depth 1 https://github.com/drwetter/testssl.sh.git >> "$LOG_FILE" 2>&1; then
        chmod +x testssl.sh/testssl.sh
        log_message "SUCCESS" "testssl.sh installed successfully"
    else
        log_message "ERROR" "Failed to install testssl.sh"
    fi
else
    log_message "SUCCESS" "testssl.sh already installed"
fi

# Install nmap (if not already installed)
log_message "INFO" "Checking nmap installation..."
if ! command_exists nmap; then
    install_package "nmap" || log_message "ERROR" "Failed to install nmap"
else
    log_message "SUCCESS" "nmap already installed"
fi

# Install Go (needed for some tools)
log_message "INFO" "Installing Go..."
if ! command_exists go; then
    GO_VERSION="1.21.5"
    wget "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz" >> "$LOG_FILE" 2>&1
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> "$HOME/.bashrc"
    echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    
    log_message "SUCCESS" "Go installed successfully"
else
    log_message "SUCCESS" "Go already installed"
fi

# Install additional security tools
log_message "INFO" "Installing additional security tools..."

# Install sqlmap
if ! command_exists sqlmap; then
    if pip3 install sqlmap >> "$LOG_FILE" 2>&1; then
        log_message "SUCCESS" "sqlmap installed"
    else
        log_message "WARN" "Failed to install sqlmap"
    fi
fi

# Install dirb
if ! command_exists dirb; then
    install_package "dirb" || log_message "WARN" "Failed to install dirb"
fi

# Install gobuster
if ! command_exists gobuster; then
    install_package "gobuster" || log_message "WARN" "Failed to install gobuster"
fi

# Create symbolic links for easier access
log_message "INFO" "Creating symbolic links..."
mkdir -p /usr/local/bin

# Link nikto
if [[ -f "$TOOLS_DIR/nikto/program/nikto.pl" ]]; then
    ln -sf "$TOOLS_DIR/nikto/program/nikto.pl" /usr/local/bin/nikto
    log_message "SUCCESS" "Nikto linked to /usr/local/bin/nikto"
fi

# Link testssl
if [[ -f "$TOOLS_DIR/testssl.sh/testssl.sh" ]]; then
    ln -sf "$TOOLS_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl
    log_message "SUCCESS" "testssl linked to /usr/local/bin/testssl"
fi
echo "🐹 Installing Go..."
if ! command -v go &> /dev/null; then
    # Download and install Go
    GO_VERSION=$(curl -s https://golang.org/VERSION?m=text)
    wget "https://go.dev/dl/${GO_VERSION}.linux-amd64.tar.gz"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "${GO_VERSION}.linux-amd64.tar.gz"
    rm "${GO_VERSION}.linux-amd64.tar.gz"
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    source ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    echo "✅ Go installed"
else
    echo "ℹ️ Go already installed"
fi

# Install subfinder (Go-based)
echo "🔍 Installing subfinder..."
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    echo "✅ subfinder installed"
else
    echo "ℹ️ subfinder already installed"
fi

# Install httpx (Go-based)
echo "🌐 Installing httpx..."
if ! command -v httpx &> /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    echo "✅ httpx installed"
else
    echo "ℹ️ httpx already installed"
fi

# Install dnsx (Go-based)
echo "🏷️ Installing dnsx..."
if ! command -v dnsx &> /dev/null; then
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    echo "✅ dnsx installed"
else
    echo "ℹ️ dnsx already installed"
fi

# Create symbolic links for easy access
echo "🔗 Creating symbolic links..."
ln -sf "$TOOLS_DIR/nikto/program/nikto.pl" /usr/local/bin/nikto.pl
ln -sf "$TOOLS_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh

# Display installation summary
echo ""
# Final verification
log_message "INFO" "Verifying installations..."
tools_to_verify=(
    "curl:curl --version"
    "wget:wget --version"
    "git:git --version"
    "python3:python3 --version"
    "ruby:ruby --version"
    "perl:perl --version"
    "nmap:nmap --version"
)

all_good=true
for tool_check in "${tools_to_verify[@]}"; do
    tool_name="${tool_check%%:*}"
    tool_command="${tool_check##*:}"
    
    if eval "$tool_command" >> "$LOG_FILE" 2>&1; then
        log_message "SUCCESS" "$tool_name: Available"
    else
        log_message "WARN" "$tool_name: Not available or failed verification"
        all_good=false
    fi
done

# Set permissions for security tools
log_message "INFO" "Setting correct permissions..."
find "$TOOLS_DIR" -type f -name "*.pl" -exec chmod +x {} \; 2>/dev/null || true
find "$TOOLS_DIR" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Update PATH in bashrc if not already done
if ! grep -q "export PATH=\$PATH:$TOOLS_DIR" "$HOME/.bashrc" 2>/dev/null; then
    echo "export PATH=\$PATH:$TOOLS_DIR/nikto/program:$TOOLS_DIR/testssl.sh" >> "$HOME/.bashrc"
    log_message "INFO" "Added tools to PATH in .bashrc"
fi

# Display installation summary
log_message "SUCCESS" "WSL security tools installation completed!"
log_message "INFO" "Tools installed in: $TOOLS_DIR"
log_message "INFO" "Log file: $LOG_FILE"

if [[ "$all_good" == "true" ]]; then
    log_message "SUCCESS" "All tools verified successfully!"
else
    log_message "WARN" "Some tools may need manual verification"
fi

if [[ "$DOCKER_MODE" != "true" ]]; then
    log_message "INFO" "Next steps:"
    log_message "INFO" "1. Source your bashrc: source ~/.bashrc"
    log_message "INFO" "2. Run verification script: python3 verify_setup.py"
    log_message "INFO" "3. Check log file for details: $LOG_FILE"
fi

log_message "INFO" "Installation script completed"
exit 0
