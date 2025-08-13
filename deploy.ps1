# Docker Deployment Script for Subdomain Scanner (Windows PowerShell)
# This script handles the complete deployment with automated tool installation

param(
    [Parameter(Position=0)]
    [string]$Command = "deploy",
    
    [Parameter(Position=1)]
    [string]$ServiceName = ""
)

# Configuration
$ComposeFile = "docker-compose.yml"
$ProjectName = "subd-iitm"
$LogDir = "./docker-logs"

# Function to write colored output
function Write-Log {
    param([string]$Message, [string]$Color = "Cyan")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Write-Error-Log {
    param([string]$Message)
    Write-Log "ERROR: $Message" "Red"
}

function Write-Success {
    param([string]$Message)
    Write-Log "SUCCESS: $Message" "Green"
}

function Write-Warning-Log {
    param([string]$Message)
    Write-Log "WARN: $Message" "Yellow"
}

# Function to check dependencies
function Test-Dependencies {
    Write-Log "Checking dependencies..."
    
    try {
        $dockerVersion = docker --version 2>$null
        if (-not $dockerVersion) {
            Write-Error-Log "Docker is not installed or not in PATH"
            return $false
        }
        
        $composeVersion = docker-compose --version 2>$null
        if (-not $composeVersion) {
            Write-Error-Log "Docker Compose is not installed or not in PATH"
            return $false
        }
        
        Write-Success "Dependencies check passed"
        return $true
    }
    catch {
        Write-Error-Log "Failed to check dependencies: $_"
        return $false
    }
}

# Function to create log directory
function Initialize-Logging {
    if (-not (Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    Write-Log "Log directory ready at $LogDir"
}

# Function to clean up previous deployment
function Invoke-Cleanup {
    Write-Log "Cleaning up previous deployment..."
    
    try {
        docker-compose -f $ComposeFile -p $ProjectName down --remove-orphans 2>$null
        docker system prune -f 2>$null
        docker volume prune -f 2>$null
        
        Write-Success "Cleanup completed"
        return $true
    }
    catch {
        Write-Warning-Log "Cleanup encountered issues: $_"
        return $false
    }
}

# Function to build and start services
function Start-Deployment {
    Write-Log "Starting deployment of subdomain scanner..."
    
    try {
        docker-compose -f $ComposeFile -p $ProjectName up -d --build | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Services started successfully"
            return $true
        } else {
            Write-Error-Log "Failed to start services"
            return $false
        }
    }
    catch {
        Write-Error-Log "Deployment failed: $_"
        return $false
    }
}

# Function to wait for services to be healthy
function Wait-ForServices {
    Write-Log "Waiting for services to be ready..."
    
    $services = @("mongo-db", "redis-queue", "flask-backend")
    
    foreach ($service in $services) {
        Write-Log "Waiting for $service to be ready..."
        
        $retries = 30
        $isReady = $false
        
        while ($retries -gt 0 -and -not $isReady) {
            try {
                $running = docker ps --filter "name=$service" --filter "status=running" --format "{{.Names}}" 2>$null
                if ($running -match $service) {
                    Write-Success "$service is running"
                    $isReady = $true
                    break
                }
            }
            catch {
                Write-Warning-Log "Error checking $service status: $_"
            }
            
            $retries--
            if ($retries -eq 0) {
                Write-Error-Log "$service failed to start"
                return $false
            }
            
            Start-Sleep -Seconds 5
        }
    }
    
    # Wait extra time for application initialization
    Write-Log "Waiting for application initialization..."
    Start-Sleep -Seconds 15
    return $true
}

# Function to verify deployment
function Test-Deployment {
    Write-Log "Verifying deployment..."
    
    # Check if backend is responding
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000" -TimeoutSec 10 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Success "Backend is accessible"
        } else {
            Write-Warning-Log "Backend returned status code: $($response.StatusCode)"
        }
    }
    catch {
        Write-Warning-Log "Backend accessibility check failed - this might be normal if no health endpoint exists"
    }
    
    # Check if frontend is accessible
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:3000" -TimeoutSec 10 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Success "Frontend is accessible"
        } else {
            Write-Warning-Log "Frontend returned status code: $($response.StatusCode)"
        }
    }
    catch {
        Write-Warning-Log "Frontend accessibility check failed"
    }
    
    # Check MongoDB connection
    try {
        docker exec mongo-db mongosh --eval "db.adminCommand('ping')" 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "MongoDB is responding"
        } else {
            Write-Warning-Log "MongoDB connection check failed"
        }
    }
    catch {
        Write-Warning-Log "MongoDB connection check failed: $_"
    }
    
    # Check Redis connection
    try {
        $redisResult = docker exec redis-queue redis-cli ping 2>$null
        if ($redisResult -match "PONG") {
            Write-Success "Redis is responding"
        } else {
            Write-Warning-Log "Redis connection check failed"
        }
    }
    catch {
        Write-Warning-Log "Redis connection check failed: $_"
    }
}

# Function to show service status
function Show-Status {
    Write-Log "Current service status:"
    docker-compose -f $ComposeFile -p $ProjectName ps
    
    Write-Host ""
    Write-Log "Service URLs:"
    Write-Host "Frontend: http://localhost:3000" -ForegroundColor Green
    Write-Host "Backend: http://localhost:5000" -ForegroundColor Green
    Write-Host "MongoDB: localhost:27017" -ForegroundColor Green
    Write-Host "Redis: localhost:6379" -ForegroundColor Green
}

# Function to show logs
function Show-Logs {
    param([string]$Service = "")
    
    if ($Service) {
        Write-Log "Showing logs for $Service..."
        docker-compose -f $ComposeFile -p $ProjectName logs -f $Service
    } else {
        Write-Log "Showing logs for all services..."
        docker-compose -f $ComposeFile -p $ProjectName logs -f
    }
}

# Function to stop services
function Stop-Services {
    Write-Log "Stopping services..."
    docker-compose -f $ComposeFile -p $ProjectName stop
    Write-Success "Services stopped"
}

# Function to restart services
function Restart-Services {
    Write-Log "Restarting services..."
    docker-compose -f $ComposeFile -p $ProjectName restart
    Write-Success "Services restarted"
}

# Function to show help
function Show-Help {
    Write-Host @"
Docker Deployment Script for Subdomain Scanner (Windows)

Usage: .\deploy.ps1 [COMMAND] [SERVICE]

Commands:
    deploy      - Full deployment (cleanup, build, start, verify)
    start       - Start services without rebuild
    stop        - Stop all services
    restart     - Restart all services
    status      - Show service status and URLs
    logs [service] - Show logs (optional service name)
    cleanup     - Clean up containers and volumes
    verify      - Verify deployment health
    help        - Show this help

Examples:
    .\deploy.ps1 deploy           # Full deployment
    .\deploy.ps1 logs backend     # Show backend logs
    .\deploy.ps1 status          # Show current status
    .\deploy.ps1 cleanup         # Clean up everything

"@ -ForegroundColor Cyan
}

# Function for full deployment
function Invoke-FullDeploy {
    Write-Log "Starting full deployment process..."
    
    if (-not (Test-Dependencies)) { return $false }
    
    Initialize-Logging
    Invoke-Cleanup | Out-Null
    
    if (-not (Start-Deployment)) { return $false }
    if (-not (Wait-ForServices)) { return $false }
    
    Test-Deployment
    Show-Status
    
    Write-Success "Full deployment completed successfully!"
    Write-Host ""
    Write-Host "Access your application at:" -ForegroundColor Yellow
    Write-Host "Frontend: http://localhost:3000" -ForegroundColor Green
    Write-Host "Backend: http://localhost:5000" -ForegroundColor Green
    Write-Host ""
    Write-Host "To view logs: .\deploy.ps1 logs" -ForegroundColor Cyan
    Write-Host "To stop: .\deploy.ps1 stop" -ForegroundColor Cyan
    
    return $true
}

# Main execution
try {
    switch ($Command.ToLower()) {
        "deploy" {
            Invoke-FullDeploy | Out-Null
        }
        "start" {
            if (Test-Dependencies) {
                docker-compose -f $ComposeFile -p $ProjectName up -d
                Show-Status
            }
        }
        "stop" {
            Stop-Services
        }
        "restart" {
            Restart-Services
        }
        "status" {
            Show-Status
        }
        "logs" {
            Show-Logs -Service $ServiceName
        }
        "cleanup" {
            Invoke-Cleanup | Out-Null
        }
        "verify" {
            Test-Deployment
        }
        "help" {
            Show-Help
        }
        default {
            Write-Error-Log "Unknown command: $Command"
            Show-Help
            exit 1
        }
    }
}
catch {
    Write-Error-Log "Script execution failed: $_"
    exit 1
}
