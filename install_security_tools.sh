#!/bin/bash

# Security Tools Installation Script for Linux Environment
# This script downloads and installs the latest versions of security tools

set -e  # Exit on any error

echo "🚀 Starting security tools installation..."

# Create tools directory
mkdir -p /app/tools
cd /tmp

# Function to download and install a tool
install_tool() {
    local tool_name=$1
    local download_url=$2
    local binary_name=$3
    
    echo "📥 Installing $tool_name..."
    
    # Download
    curl -L "$download_url" -o "${tool_name}.tar.gz"
    
    # Extract
    tar -xzf "${tool_name}.tar.gz"
    
    # Move to tools directory
    if [ -f "$binary_name" ]; then
        mv "$binary_name" "/app/tools/"
    else
        echo "⚠️  Binary $binary_name not found after extraction"
        ls -la
    fi
    
    # Clean up
    rm -f "${tool_name}.tar.gz"
    
    echo "✅ $tool_name installed successfully"
}

# Install ProjectDiscovery tools
install_tool "subfinder" \
    "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_Linux_amd64.tar.gz" \
    "subfinder"

install_tool "dnsx" \
    "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_Linux_amd64.tar.gz" \
    "dnsx"

install_tool "httpx" \
    "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_Linux_amd64.tar.gz" \
    "httpx"

install_tool "nuclei" \
    "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_Linux_amd64.tar.gz" \
    "nuclei"

# Make all tools executable
chmod +x /app/tools/*

echo "🔧 Setting up permissions and PATH..."

# Verify installations
echo "🔍 Verifying tool installations..."
for tool in subfinder dnsx httpx nuclei; do
    if [ -x "/app/tools/$tool" ]; then
        echo "✅ $tool: $(/app/tools/$tool -version 2>&1 | head -1 || echo 'Version check failed')"
    else
        echo "❌ $tool: Not found or not executable"
    fi
done

echo "🎉 Security tools installation completed!"
echo "📁 Tools installed in: /app/tools/"
ls -la /app/tools/
