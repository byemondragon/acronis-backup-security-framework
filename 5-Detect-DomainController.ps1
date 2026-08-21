#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Detects if this machine is a Domain Controller and automatically sets the
    NinjaOne Custom Field "isActiveDirectoryAgent" accordingly.

.DESCRIPTION
    This script is the ENTRY POINT of the Acronis Backup Security Framework.
    It should be deployed fleet-wide on all managed machines before any other
    script in the framework is run.

    Detection logic (three independent methods, all must agree):

    Method 1 -- WMI Domain Role:
        Win32_ComputerSystem.DomainRole values:
        4 = Backup Domain Controller
        5 = Primary Domain Controller
        Any value of 4 or 5 = Domain Controller

    Method 2 -- Active Directory Domain Services service:
        Checks if the "NTDS" (NT Directory Services) Windows service exists
        and is in Running state. NTDS only runs on Domain Controllers.

    Method 3 -- SYSVOL share:
        Checks if the SYSVOL network share exists on this machine.
        SYSVOL is only present on Domain Controllers.

    Result:
        2 or more methods confirm DC -> isActiveDirectoryAgent = true
        Fewer than 2 methods confirm DC -> isActiveDirectoryAgent = false

    The Custom Field is written using Ninja-Property-Set, which requires
    the NinjaOne agent to be installed and the field to be defined in
    NinjaOne Administration -> Devices -> Custom Fields.

.NINJAONE CUSTOM FIELD WRITTEN
    isActiveDirectoryAgent : Boolean (true/false)
                             Custom Field type: Checkbox
                             API Name         : isActiveDirectoryAgent
                             Scope            : Device

.NINJAONE CUSTOM FIELD READ (for context logging only)
    isHyperVHost : Boolean. Logged alongside DC detection for full machine profile.

.EXIT CODES
    0 = Successfully detected machine role and set Custom Field
    1 = Detection failed or NinjaOne agent could not write the Custom Field

.NOTES
    Author  : Edson Pintado
    Version : 1.0
    Run As  : Administrator / SYSTEM
    Schedule: Deploy once on onboarding, then weekly to catch role changes
    Part of : Acronis Backup Security Framework (Script 5 of 5)

.DEPLOYMENT RECOMMENDATION
    Create a NinjaOne Policy that runs this script on ALL Windows devices
    on a weekly schedule. The Custom Field will be kept current automatically,
    ensuring Scripts 1-4 always operate with accurate machine class information.
#>

# ============================================================
# INITIALIZATION
# ============================================================

$isHVHostRaw = Ninja-Property-Get isHyperVHost 2>$null
$isHVHost    = ($isHVHostRaw -eq "true")

$LogFile = "C:\Logs\ACB-DetectDC-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework -- Script 5 of 5"
Write-Log " Detect Domain Controller & Set isActiveDirectoryAgent"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " isHyperVHost    : $isHVHost"
Write-Log " Timestamp       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Log "======================================================"


# ============================================================
# DETECTION METHOD 1 -- WMI DOMAIN ROLE
# ============================================================

Write-Log "METHOD 1: Checking WMI DomainRole..."

$method1IsDC = $false
try {
    $cs         = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop
    $domainRole = $cs.DomainRole

    $roleNames = @{
        0 = "Standalone Workstation"
        1 = "Member Workstation"
        2 = "Standalone Server"
        3 = "Member Server"
        4 = "Backup Domain Controller"
        5 = "Primary Domain Controller"
    }

    $roleName = if ($roleNames.ContainsKey([int]$domainRole)) { $roleNames[[int]$domainRole] } else { "Unknown ($domainRole)" }
    Write-Log "  DomainRole : $domainRole ($roleName)"
    Write-Log "  Domain     : $($cs.Domain)"

    if ($domainRole -eq 4 -or $domainRole -eq 5) {
        $method1IsDC = $true
        Write-Log "  Result     : DOMAIN CONTROLLER detected via WMI."
    } else {
        Write-Log "  Result     : Not a Domain Controller (DomainRole = $domainRole)."
    }
} catch {
    Write-Log "  Result     : WMI query failed. Details: $_" "WARN"
}

Write-Log "METHOD 1 COMPLETE. IsDC = $method1IsDC"


# ============================================================
# DETECTION METHOD 2 -- NTDS SERVICE
# ============================================================

Write-Log "METHOD 2: Checking for NTDS (NT Directory Services) service..."

$method2IsDC = $false
try {
    $ntds = Get-Service -Name "NTDS" -ErrorAction Stop
    Write-Log "  NTDS service found."
    Write-Log "  Status     : $($ntds.Status)"
    Write-Log "  StartType  : $($ntds.StartType)"

    if ($ntds.Status -eq "Running") {
        $method2IsDC = $true
        Write-Log "  Result     : DOMAIN CONTROLLER detected via NTDS service (Running)."
    } else {
        Write-Log "  Result     : NTDS service exists but is NOT running (Status: $($ntds.Status))."
        Write-Log "               This may indicate a DC with AD DS stopped -- treating as DC." "WARN"
        # Service exists but stopped -- still a DC, just potentially degraded
        $method2IsDC = $true
    }
} catch {
    Write-Log "  Result     : NTDS service not found -- not a Domain Controller."
}

Write-Log "METHOD 2 COMPLETE. IsDC = $method2IsDC"


# ============================================================
# DETECTION METHOD 3 -- SYSVOL SHARE
# ============================================================

Write-Log "METHOD 3: Checking for SYSVOL network share..."

$method3IsDC = $false
try {
    $sysvol = Get-WmiObject -Class Win32_Share -Filter "Name='SYSVOL'" -ErrorAction Stop
    if ($sysvol) {
        $method3IsDC = $true
        Write-Log "  SYSVOL share found at: $($sysvol.Path)"
        Write-Log "  Result     : DOMAIN CONTROLLER detected via SYSVOL share."
    } else {
        Write-Log "  Result     : SYSVOL share not found -- not a Domain Controller."
    }
} catch {
    Write-Log "  Result     : Could not query shares. Details: $_" "WARN"
}

Write-Log "METHOD 3 COMPLETE. IsDC = $method3IsDC"


# ============================================================
# CONSENSUS DECISION
# ============================================================

Write-Log "CONSENSUS: Evaluating detection results..."

$positiveCount = ($method1IsDC, $method2IsDC, $method3IsDC | Where-Object { $_ -eq $true }).Count

Write-Log "  Method 1 (WMI DomainRole) : $method1IsDC"
Write-Log "  Method 2 (NTDS Service)   : $method2IsDC"
Write-Log "  Method 3 (SYSVOL Share)   : $method3IsDC"
Write-Log "  Positive detections       : $positiveCount / 3"

# Require at least 2 of 3 methods to confirm DC status
# This prevents false positives from a single failed WMI query
$isDomainController = ($positiveCount -ge 2)

if ($isDomainController) {
    Write-Log "  CONSENSUS RESULT: This machine IS a Domain Controller."
    Write-Log "  isActiveDirectoryAgent will be set to: TRUE"
} else {
    Write-Log "  CONSENSUS RESULT: This machine is NOT a Domain Controller."
    Write-Log "  isActiveDirectoryAgent will be set to: FALSE"
}

Write-Log "CONSENSUS COMPLETE."


# ============================================================
# ADDITIONAL CONTEXT -- ACRONIS AGENT FOR AD CHECK
# ============================================================

Write-Log "ADDITIONAL CHECK: Verifying Acronis Agent for Active Directory installation..."

$acronisADAgent = $false
try {
    # Check for Acronis Agent for Active Directory in installed programs
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $acronisProducts = Get-ItemProperty $regPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like "*Acronis*" }

    if ($acronisProducts) {
        Write-Log "  Acronis products installed on this machine:"
        foreach ($p in $acronisProducts) {
            Write-Log "    - $($p.DisplayName) $($p.DisplayVersion)"
            if ($p.DisplayName -like "*Active Directory*") {
                $acronisADAgent = $true
                Write-Log "    ^ Agent for Active Directory CONFIRMED."
            }
        }
    } else {
        Write-Log "  No Acronis products found in registry."
    }

    if (-not $acronisADAgent -and $isDomainController) {
        Write-Log "  NOTE: This is a DC but Agent for Active Directory was not detected." "WARN"
        Write-Log "        The Acronis Agent for Windows may be installed instead." "WARN"
        Write-Log "        isActiveDirectoryAgent is set based on DC role, not agent type." "WARN"
        Write-Log "        Review manually if the backup method differs from expected." "WARN"
    }
} catch {
    Write-Log "  Could not check installed Acronis products. Details: $_" "WARN"
}

Write-Log "ADDITIONAL CHECK COMPLETE."


# ============================================================
# SET NINJONE CUSTOM FIELD
# ============================================================

Write-Log "SETTING NinjaOne Custom Field 'isActiveDirectoryAgent' = $isDomainController..."

$fieldValue = if ($isDomainController) { "true" } else { "false" }

try {
    Ninja-Property-Set isActiveDirectoryAgent $fieldValue
    Write-Log "Custom Field 'isActiveDirectoryAgent' set to '$fieldValue'. OK."
} catch {
    Write-Log "ERROR: Failed to set NinjaOne Custom Field. Details: $_" "ERROR"
    Write-Log "       Verify the field 'isActiveDirectoryAgent' exists in NinjaOne" "ERROR"
    Write-Log "       Administration -> Devices -> Custom Fields -> Type: Checkbox." "ERROR"
    Exit 1
}


# ============================================================
# FINAL SUMMARY
# ============================================================

$machineProfile = if ($isDomainController -and $isHVHost) {
    "Domain Controller + Hyper-V Host"
} elseif ($isDomainController) {
    "Domain Controller"
} elseif ($isHVHost) {
    "Hyper-V Host (not a DC)"
} else {
    "Standard Server / Workstation / VM Guest"
}

Write-Log "======================================================"
Write-Log " DETECTION COMPLETE -- FINAL SUMMARY"
Write-Log " Machine              : $env:COMPUTERNAME"
Write-Log " Machine Profile      : $machineProfile"
Write-Log " Is Domain Controller : $isDomainController"
Write-Log " Acronis AD Agent     : $acronisADAgent"
Write-Log " isActiveDirectoryAgent set to: $fieldValue"
Write-Log ""
Write-Log " NEXT STEPS:"
if ($isDomainController) {
    Write-Log "   Run Script 1 (Audit) -- will verify Domain Admins membership is present."
    Write-Log "   Run Script 4 (Initialize) -- will configure domain account + drive hardening."
} else {
    Write-Log "   Run Script 1 (Audit) -- will verify no privileged group memberships."
    Write-Log "   Run Script 4 (Initialize) -- will configure local account + drive hardening."
}
Write-Log " Log File             : $LogFile"
Write-Log "======================================================"

Write-Output "`nSUCCESS: Domain Controller detection complete on $env:COMPUTERNAME. isActiveDirectoryAgent = $fieldValue. Log: $LogFile"
Exit 0
