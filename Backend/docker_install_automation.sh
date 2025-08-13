#!/bin/bash

# Docker Automation Wrapper for Security Tools Installation
# This script can be used in Docker containers or CI/CD pipelines

set -e

DOCKER_MODE=${DOCKER_MODE:-true}
SILENT=${SILENT:-true}

# Colors for output (if not in silent mode)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    if [[ "$SILENT" != "true" ]]; then
        echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
    fi
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" >&2
}

success() {
    if [[ "$SILENT" != "true" ]]; then
        echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] SUCCESS: $1${NC}"
    fi
}

warn() {
    if [[ "$SILENT" != "true" ]]; then
        echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARN: $1${NC}"
    fi
}

# Function to install tools for different environments
install_tools() {
    local environment=$1
    
    case $environment in
        "wsl"|"ubuntu"|"debian"|"linux")
            log "Installing WSL/Linux security tools..."
            if [[ -f "./install_tools_wsl.sh" ]]; then
                chmod +x ./install_tools_wsl.sh
                ./install_tools_wsl.sh "$SILENT" "$DOCKER_MODE"
            else
                error "WSL installation script not found"
                return 1
            fi
            ;;
        "windows")
            log "Installing Windows security tools..."
            if [[ -f "./install_tools_windows_docker.ps1" ]]; then
                powershell.exe -ExecutionPolicy Bypass -File "./install_tools_windows_docker.ps1" -Silent:$$SILENT -DockerMode:$$DOCKER_MODE
            else
                error "Windows installation script not found"
                return 1
            fi
            ;;
        "both"|"hybrid")
            log "Installing tools for hybrid Windows/WSL environment..."
            install_tools "windows"
            install_tools "wsl"
            ;;
        *)
            error "Unknown environment: $environment"
            error "Supported environments: wsl, ubuntu, debian, linux, windows, both, hybrid"
            return 1
            ;;
    esac
}

# Function to verify installation
verify_installation() {
    log "Running verification..."
    if [[ -f "./verify_setup.py" ]]; then
        python3 verify_setup.py
    else
        warn "Verification script not found"
    fi
}

# Function to setup Docker environment
setup_docker_env() {
    log "Setting up Docker environment..."
    
    # Create necessary directories
    mkdir -p /app/tools
    mkdir -p /app/security-tools
    
    # Set environment variables for Docker
    export PYTHONPATH="/app:$PYTHONPATH"
    export PATH="/app/tools:/app/security-tools:$PATH"
    
    # Create symbolic links if needed
    if [[ ! -L "/usr/local/bin/verify_setup" && -f "/app/verify_setup.py" ]]; then
        ln -s /app/verify_setup.py /usr/local/bin/verify_setup
    fi
}

# Main execution
main() {
    local environment=${1:-"wsl"}
    local run_verification=${2:-"true"}
    
    log "Starting Docker automation for security tools installation"
    log "Environment: $environment"
    log "Docker Mode: $DOCKER_MODE"
    log "Silent Mode: $SILENT"
    
    # Setup Docker environment if in Docker mode
    if [[ "$DOCKER_MODE" == "true" ]]; then
        setup_docker_env
    fi
    
    # Install tools
    if install_tools "$environment"; then
        success "Tools installation completed successfully"
    else
        error "Tools installation failed"
        exit 1
    fi
    
    # Run verification if requested
    if [[ "$run_verification" == "true" ]]; then
        verify_installation
    fi
    
    success "Docker automation completed successfully"
}

# Help function
show_help() {
    cat << EOF
Docker Automation Wrapper for Security Tools Installation

Usage: $0 [ENVIRONMENT] [VERIFY]

ENVIRONMENT:
    wsl, ubuntu, debian, linux  - Install WSL/Linux tools
    windows                     - Install Windows tools
    both, hybrid               - Install both Windows and WSL tools

VERIFY:
    true   - Run verification after installation (default)
    false  - Skip verification

Environment Variables:
    DOCKER_MODE - Set to true for Docker container mode (default: true)
    SILENT      - Set to true for silent mode (default: true)

Examples:
    $0 wsl true              # Install WSL tools and verify
    $0 windows false         # Install Windows tools, skip verification
    $0 both                  # Install both, verify by default
    
    SILENT=false $0 ubuntu   # Install Ubuntu tools with verbose output
    DOCKER_MODE=false $0     # Run in non-Docker mode

EOF
}

# Parse arguments
case "${1:-}" in
    -h|--help|help)
        show_help
        exit 0
        ;;
    *)
        main "$@"
        ;;
esac
