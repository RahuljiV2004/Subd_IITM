# Security Tools Installation Script for Windows
# Docker-ready automation script for full tool installation
# Run this PowerShell script as Administrator

param(
    [switch]$Silent = $false,
    [switch]$DockerMode = $false
)

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if (!$Silent) {
        switch ($Level) {
            "ERROR" { Write-Host "[$timestamp] ERROR: $Message" -ForegroundColor Red }
            "WARN"  { Write-Host "[$timestamp] WARN: $Message" -ForegroundColor Yellow }
            "SUCCESS" { Write-Host "[$timestamp] SUCCESS: $Message" -ForegroundColor Green }
            default { Write-Host "[$timestamp] INFO: $Message" -ForegroundColor Cyan }
        }
    }
}

Write-Log "Starting Windows security tools installation..."

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Log "This script must be run as Administrator!" "ERROR"
    if (!$Silent -and !$DockerMode) { pause }
    exit 1
}

# Set execution policy
Write-Log "Setting execution policy..."
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Function to refresh environment variables
function Refresh-Environment {
    $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User")
    
    # Add common tool paths
    $commonPaths = @(
        "C:\ProgramData\chocolatey\bin",
        "C:\tools\ruby31\bin",
        "C:\tools\ruby32\bin",
        "C:\Program Files\Git\bin",
        "C:\Program Files (x86)\Nmap",
        "C:\Program Files\Nmap",
        "C:\Go\bin",
        "$env:USERPROFILE\go\bin",
        "C:\Program Files\nodejs"
    )
    
    foreach ($path in $commonPaths) {
        if ((Test-Path $path) -and ($env:PATH -notlike "*$path*")) {
            $env:PATH += ";$path"
        }
    }
}

# Function to install or update package with Chocolatey
function Install-ChocoPackage {
    param([string]$PackageName, [string]$CommandName, [int]$MaxRetries = 3)
    
    # First check if the command is already available
    if (Get-Command $CommandName -ErrorAction SilentlyContinue) {
        Write-Log "$PackageName already installed and available" "SUCCESS"
        
        # Try to update it if possible
        try {
            Write-Log "Checking for updates to $PackageName..."
            choco upgrade $PackageName -y --no-progress --limit-output
            if ($LASTEXITCODE -eq 0) {
                Write-Log "$PackageName updated successfully" "SUCCESS"
            }
        } catch {
            Write-Log "Update check failed for $PackageName, but it's working" "WARN"
        }
        return $true
    }
    
    # If command not available, try to install
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            Write-Log "Installing $PackageName (attempt $i/$MaxRetries)..."
            choco install $PackageName -y --no-progress --ignore-checksums
            if ($LASTEXITCODE -eq 0) {
                Refresh-Environment
                
                # Verify installation worked
                if (Get-Command $CommandName -ErrorAction SilentlyContinue) {
                    Write-Log "$PackageName installed and verified successfully" "SUCCESS"
                    return $true
                } else {
                    Write-Log "$PackageName installed but command not found, will retry..." "WARN"
                }
            }
        } catch {
            Write-Log "Attempt $i failed for $PackageName`: $($_.Exception.Message)" "WARN"
        }
        if ($i -lt $MaxRetries) { 
            Start-Sleep -Seconds 5 
            Refresh-Environment
        }
    }
    Write-Log "Failed to install $PackageName after $MaxRetries attempts" "ERROR"
    return $false
}

# Function to fix Chocolatey installation
function Repair-ChocolateyInstallation {
    Write-Log "Attempting to repair Chocolatey installation..."
    
    # Check if Chocolatey directory exists but command is not available
    $chocoPath = "C:\ProgramData\chocolatey"
    if (Test-Path $chocoPath) {
        Write-Log "Found existing Chocolatey directory at $chocoPath"
        
        # Add Chocolatey to PATH manually
        $chocoExe = "$chocoPath\bin\choco.exe"
        if (Test-Path $chocoExe) {
            Write-Log "Found choco.exe, adding to PATH..."
            $env:PATH = "$chocoPath\bin;$env:PATH"
            [Environment]::SetEnvironmentVariable("PATH", $env:PATH, "User")
            
            # Try to upgrade/repair Chocolatey
            try {
                & $chocoExe upgrade chocolatey -y --no-progress
                Write-Log "Chocolatey upgraded successfully" "SUCCESS"
                return $true
            } catch {
                Write-Log "Failed to upgrade Chocolatey: $($_.Exception.Message)" "WARN"
            }
        }
        
        # If repair failed, remove broken installation
        Write-Log "Removing broken Chocolatey installation..." "WARN"
        try {
            Remove-Item -Path $chocoPath -Recurse -Force -ErrorAction Stop
            Write-Log "Removed broken Chocolatey installation" "SUCCESS"
        } catch {
            Write-Log "Failed to remove broken installation: $($_.Exception.Message)" "ERROR"
            return $false
        }
    }
    
    return $false
}

# Install or repair Chocolatey
Write-Log "Checking Chocolatey installation..."
$chocoAvailable = Get-Command choco -ErrorAction SilentlyContinue

if (!$chocoAvailable) {
    # Try to repair existing installation first
    if (!(Repair-ChocolateyInstallation)) {
        Write-Log "Installing fresh Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        try {
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Log "Chocolatey installation completed" "SUCCESS"
        } catch {
            Write-Log "Chocolatey installation failed: $($_.Exception.Message)" "ERROR"
            exit 1
        }
    }
} else {
    Write-Log "Chocolatey already installed and working" "SUCCESS"
    try {
        choco upgrade chocolatey -y --no-progress
        Write-Log "Chocolatey updated to latest version" "SUCCESS"
    } catch {
        Write-Log "Failed to update Chocolatey, continuing with existing version" "WARN"
    }
}

# Refresh environment and wait for Chocolatey
Refresh-Environment
$retryCount = 0
while (!(Get-Command choco -ErrorAction SilentlyContinue) -and $retryCount -lt 15) {
    Start-Sleep -Seconds 3
    Refresh-Environment
    $retryCount++
    Write-Log "Waiting for Chocolatey to be available... (attempt $retryCount/15)"
}

if (!(Get-Command choco -ErrorAction SilentlyContinue)) {
    Write-Log "Chocolatey command not available after installation attempts" "ERROR"
    Write-Log "Please manually install Chocolatey and run this script again" "ERROR"
    exit 1
}

# Install required packages
$packages = @(
    @{Name="ruby"; Command="ruby"},
    @{Name="git"; Command="git"},
    @{Name="nmap"; Command="nmap"},
    @{Name="golang"; Command="go"},
    @{Name="python"; Command="python"},
    @{Name="nodejs"; Command="node"}
)

Write-Log "Installing/updating required packages..."
foreach ($package in $packages) {
    Install-ChocoPackage -PackageName $package.Name -CommandName $package.Command
    Refresh-Environment
}

# Create tools directories
Write-Log "Creating tools directories..."
$toolsDir = "$env:USERPROFILE\security-tools"

# Dynamically determine project tools directory
$currentDir = Get-Location
$projectToolsDir = Join-Path $currentDir "tools"

# If running from a different location, try to find the project root
if (!(Test-Path (Join-Path $currentDir "docker-compose.yml"))) {
    # Look for common project indicators
    $possibleRoots = @(
        "$env:USERPROFILE\Documents\My Files\Programes\IITM\Subd_IITM",
        "$currentDir\Subd_IITM",
        "$currentDir\..\Subd_IITM",
        "$currentDir\..\..\Subd_IITM"
    )
    
    foreach ($root in $possibleRoots) {
        if (Test-Path (Join-Path $root "docker-compose.yml")) {
            $projectToolsDir = Join-Path $root "tools"
            Write-Log "Found project root at: $root" "SUCCESS"
            break
        }
    }
}

@($toolsDir, $projectToolsDir) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Log "Created directory: $_" "SUCCESS"
    }
}

# Install WhatWeb
Write-Log "Installing WhatWeb..."
$whatwebDir = "$toolsDir\WhatWeb-master"
if (!(Test-Path $whatwebDir)) {
    try {
        Set-Location $toolsDir
        Invoke-WebRequest -Uri "https://github.com/urbanadventurer/WhatWeb/archive/master.zip" -OutFile "WhatWeb-master.zip"
        Expand-Archive -Path "WhatWeb-master.zip" -DestinationPath $toolsDir -Force
        Remove-Item "WhatWeb-master.zip"
        Write-Log "WhatWeb installed" "SUCCESS"
    } catch {
        Write-Log "WhatWeb installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "WhatWeb already installed" "SUCCESS"
}

# Install Nikto
Write-Log "Installing Nikto..."
$niktoDir = "$toolsDir\nikto"
if (!(Test-Path "$niktoDir\program\nikto.pl")) {
    try {
        if (Test-Path $niktoDir) { Remove-Item $niktoDir -Recurse -Force }
        Set-Location $toolsDir
        git clone https://github.com/sullo/nikto.git
        Write-Log "Nikto installed successfully" "SUCCESS"
    } catch {
        Write-Log "Nikto installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Nikto already installed" "SUCCESS"
}

# Install TestSSL
Write-Log "Installing TestSSL..."
$testsslDir = "$toolsDir\testssl.sh"
if (!(Test-Path "$testsslDir\testssl.sh")) {
    try {
        if (Test-Path $testsslDir) { Remove-Item $testsslDir -Recurse -Force }
        Set-Location $toolsDir
        git clone --depth 1 https://github.com/drwetter/testssl.sh.git
        Write-Log "TestSSL installed successfully" "SUCCESS"
    } catch {
        Write-Log "TestSSL installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "TestSSL already installed" "SUCCESS"
}

# Install Ruby gems
Write-Log "Installing Ruby gems..."
Refresh-Environment
if (Get-Command gem -ErrorAction SilentlyContinue) {
    try {
        gem install wpscan --no-document
        Write-Log "WPScan installed" "SUCCESS"
    } catch {
        Write-Log "WPScan installation failed" "WARN"
    }
} else {
    Write-Log "Ruby gem command not available" "WARN"
}

# Install Go-based tools
Write-Log "Installing Go-based security tools..."
Refresh-Environment
if (Get-Command go -ErrorAction SilentlyContinue) {
    $goTools = @(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "github.com/ffuf/ffuf@latest",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    
    foreach ($tool in $goTools) {
        try {
            Write-Log "Installing Go tool: $tool"
            go install -v $tool
            Write-Log "Go tool installed: $tool" "SUCCESS"
        } catch {
            Write-Log "Failed to install Go tool: $tool" "ERROR"
        }
    }
    
    # Copy Go tools to project directory
    Write-Log "Copying Go tools to project directory..."
    $goBinPath = "$env:USERPROFILE\go\bin"
    if (Test-Path $goBinPath) {
        Get-ChildItem "$goBinPath\*.exe" | ForEach-Object {
            try {
                Copy-Item $_.FullName $projectToolsDir -Force
                Write-Log "Copied $($_.Name) to project tools" "SUCCESS"
            } catch {
                Write-Log "Failed to copy $($_.Name)" "WARN"
            }
        }
    }
} else {
    Write-Log "Go command not available" "WARN"
}

# Create WSL wrapper scripts for cross-platform compatibility
Write-Log "Creating WSL wrapper scripts..."

# Nikto wrapper
$niktoWrapper = @"
#!/bin/bash
perl "/mnt/c/Users/$env:USERNAME/security-tools/nikto/program/nikto.pl" `$@
"@
$niktoWrapper | Out-File -FilePath "$projectToolsDir\nikto" -Encoding UTF8 -Force

# TestSSL wrapper  
$testsslWrapper = @"
#!/bin/bash
"/mnt/c/Users/$env:USERNAME/security-tools/testssl.sh/testssl.sh" `$@
"@
$testsslWrapper | Out-File -FilePath "$projectToolsDir\testssl" -Encoding UTF8 -Force

# WhatWeb wrapper
$whatwebWrapper = @"
#!/bin/bash
ruby "/mnt/c/Users/$env:USERNAME/security-tools/WhatWeb-master/whatweb" `$@
"@
$whatwebWrapper | Out-File -FilePath "$projectToolsDir\whatweb" -Encoding UTF8 -Force

Write-Log "WSL wrapper scripts created" "SUCCESS"

# Final verification
Write-Log "Verifying installations..."
$tools = @(
    @{Name="Ruby"; Command="ruby --version"},
    @{Name="Git"; Command="git --version"},
    @{Name="Nmap"; Command="nmap --version"},
    @{Name="Go"; Command="go version"},
    @{Name="Python"; Command="python --version"},
    @{Name="Node.js"; Command="node --version"}
)

foreach ($tool in $tools) {
    try {
        Invoke-Expression $tool.Command 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Log "$($tool.Name): Available" "SUCCESS"
        } else {
            Write-Log "$($tool.Name): Not available" "WARN"
        }
    } catch {
        Write-Log "$($tool.Name): Not available" "WARN"
    }
}

# Display summary
Write-Log "Windows tools installation completed!" "SUCCESS"
Write-Log "Tools directory: $toolsDir"
Write-Log "Project tools directory: $projectToolsDir"
Write-Log "WhatWeb location: $whatwebDir\whatweb"

if (!$DockerMode) {
    Write-Log "Next steps:"
    Write-Log "1. Run WSL installation script: install_tools_wsl.sh"
    Write-Log "2. Restart terminal to refresh PATH variables"
    Write-Log "3. Run verification: python verify_setup.py"
    
    if (!$Silent) {
        Write-Host "`nPress any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

exit 0
