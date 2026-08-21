# Define log file
$logFile = "C:\Temp\Acronis_Install_Log.txt"

# Function to log errors
function Log-Error {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - ERROR: $message" | Out-File -FilePath $logFile -Append
}

# Ensure script is running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Log-Error "Script not run as Administrator. Please restart with elevated privileges."
    Write-Host "Script must be run as Administrator. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host "Script running with Administrator privileges." -ForegroundColor Green

# Define variables
$env:token
$baseUrl = "https://us5-cloud.acronis.com/"

# Verify if C:\Temp exists, create if not
$tempPath = "C:\Temp"
if (-Not (Test-Path $tempPath)) {
    try {
        New-Item -ItemType Directory -Path $tempPath -Force | Out-Null
        Write-Host "C:\Temp directory created successfully." -ForegroundColor Green
    } catch {
        Log-Error "Failed to create C:\Temp directory: $_"
        Write-Host "Failed to create C:\Temp directory. Check log for details." -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "C:\Temp directory already exists." -ForegroundColor Green
}

# Set path and download installer
$installerUrl = "https://us5-cloud.acronis.com/bc/api/ams/links/agents/redirect?language=multi&channel=CURRENT&system=windows&productType=enterprise&login=1376d7cb-cc67-4ddd-be12-8406910d2d47&white_labeled=0"
$installerPath = "$tempPath\Acronis_Cyber_Protection_Agent_for_Windows_web.exe"

try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
    Write-Host "Installer downloaded successfully to $installerPath" -ForegroundColor Green
} catch {
    Log-Error "Failed to download installer: $_"
    Write-Host "Failed to download installer. Check log for details." -ForegroundColor Red
    exit 1
}

# Run the installer silently
try {
    Start-Process -FilePath $installerPath -ArgumentList "--quiet --add-components=agentForWindows --registration by-token --reg-token $env:token --reg-address $baseUrl" -Wait -NoNewWindow
    Write-Host "Acronis installation completed successfully." -ForegroundColor Green
} catch {
    Log-Error "Installation failed: $_"
    Write-Host "Installation failed. Check log for details." -ForegroundColor Red
    exit 1
}

Write-Host "Installation process finished. Check logs for details if needed." -ForegroundColor Cyan
