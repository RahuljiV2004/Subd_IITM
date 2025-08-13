# Fix Missing Security Tools Script
# Installs missing tools: nikto, testssl, ffuf, nuclei, wpscan

param(
    [switch]$Silent = $false
)

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

Write-Log "Fixing missing security tools..."

$toolsDir = "$env:USERPROFILE\security-tools"
$projectToolsDir = "$env:USERPROFILE\Documents\My Files\Programes\IITM\Subd_IITM\tools"

# Ensure directories exist
@($toolsDir, $projectToolsDir) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Log "Created directory: $_"
    }
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

# Install FFUF (try to download binary)
Write-Log "Installing FFUF..."
$ffufPath = "$projectToolsDir\ffuf.exe"
if (!(Test-Path $ffufPath)) {
    try {
        # Try to install via Go first
        if (Get-Command go -ErrorAction SilentlyContinue) {
            Write-Log "Installing FFUF via Go..."
            go install github.com/ffuf/ffuf@latest
            
            # Copy from Go bin to project tools
            $goBinPath = "$env:USERPROFILE\go\bin\ffuf.exe"
            if (Test-Path $goBinPath) {
                Copy-Item $goBinPath $ffufPath -Force
                Write-Log "FFUF installed via Go successfully" "SUCCESS"
            }
        } else {
            Write-Log "Go not available, skipping FFUF installation" "WARN"
        }
    } catch {
        Write-Log "FFUF installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "FFUF already installed" "SUCCESS"
}

# Install Nuclei
Write-Log "Installing Nuclei..."
$nucleiPath = "$projectToolsDir\nuclei.exe"
if (!(Test-Path $nucleiPath)) {
    try {
        if (Get-Command go -ErrorAction SilentlyContinue) {
            Write-Log "Installing Nuclei via Go..."
            go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
            
            # Copy from Go bin to project tools
            $goBinPath = "$env:USERPROFILE\go\bin\nuclei.exe"
            if (Test-Path $goBinPath) {
                Copy-Item $goBinPath $nucleiPath -Force
                Write-Log "Nuclei installed successfully" "SUCCESS"
            }
        } else {
            Write-Log "Go not available, cannot install Nuclei" "ERROR"
        }
    } catch {
        Write-Log "Nuclei installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Nuclei already installed" "SUCCESS"
}

# Install WPScan (check for Ruby first)
Write-Log "Installing WPScan..."
if (Get-Command gem -ErrorAction SilentlyContinue) {
    try {
        gem install wpscan --no-document
        Write-Log "WPScan installed successfully" "SUCCESS"
    } catch {
        Write-Log "WPScan installation failed: $($_.Exception.Message)" "ERROR"
    }
} else {
    Write-Log "Ruby gem command not available, cannot install WPScan" "WARN"
}

# Create wrapper scripts for WSL compatibility
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

Write-Log "WSL wrapper scripts created" "SUCCESS"

Write-Log "Tool installation/fixing completed!" "SUCCESS"
Write-Log ""
Write-Log "Run verification with: python verify_setup.py"
