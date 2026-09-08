#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Audits the Acronis backup service account for privileged group memberships.

.DESCRIPTION
    READ-ONLY script. Makes no changes to the system.

    Checks the backup service account against all known privileged local groups
    and reports findings with clear exit codes for NinjaOne alerting.

    Handles two distinct machine classes:

    STANDARD MACHINES (servers, workstanders, VM guests):
        - svc_acronis must NOT be in any privileged group
        - Findings trigger Exit 2 (action required)

    DOMAIN CONTROLLERS with Agent for Active Directory:
        - svc_acronis MUST be in Domain Admins (Acronis requirement per KB 56202)
        - svc_acronis MUST be in Administrators and Backup Operators (Acronis requirement)
        - Script VERIFIES these required memberships are present instead of flagging them
        - Any OTHER privileged group memberships are still flagged as findings

    Exit Codes:
        0 = CLEAN    — Account state is correct for this machine class
        1 = NOTFOUND — Account does not exist on this machine
        2 = FINDINGS — Unexpected privileged group memberships detected
                       OR required memberships are MISSING on a DC

.NINJAONE CUSTOM FIELDS (read via Ninja-Property-Get)
    isActiveDirectoryAgent : Boolean (true/false).
                             Set automatically by Script 5 (Detect-DomainController.ps1).
                             true  = DC running Agent for Active Directory
                             false = standard server, workstation, or VM guest

.NINJAONE SCRIPT VARIABLES (Text Input)
    backupServiceAccount : Local/domain service account name (e.g., svc_acronis).
                           Optional — defaults to "svc_acronis" if not set.

.NOTES
    Author  : Edson Pintado
    Version : 1.2
    Run As  : Administrator / SYSTEM
    Type    : Read-Only Audit — no changes made
    Part of : Acronis Backup Security Framework (Script 1 of 5)
#>

# ============================================================
# INITIALIZATION
# ============================================================

# NinjaOne Custom Field
$isADAgentRaw = Ninja-Property-Get isActiveDirectoryAgent 2>$null
$isADAgent    = ($isADAgentRaw -eq "true")

# NinjaOne Script Variable
$ServiceAccount = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) {
    "svc_acronis"
} else {
    $env:backupServiceAccount.Trim()
}

$MachineClass = if ($isADAgent) {
    "Domain Controller — Agent for Active Directory"
} else {
    "Standard Server / Workstation / VM Guest"
}

$LogFile = "C:\Logs\ACB-Audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework — Script 1 of 5"
Write-Log " Audit: Backup Service Account Privileges"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
Write-Log " Audit Type      : READ-ONLY (no changes made)"
Write-Log "======================================================"


# ============================================================
# STEP 1 — VERIFY ACCOUNT EXISTS
# ============================================================

Write-Log "STEP 1: Checking if account '$ServiceAccount' exists..."

# On a DC, the account is a domain account — use Get-ADUser if available
$account = $null
if ($isADAgent) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $account = Get-ADUser -Filter { SamAccountName -eq $ServiceAccount } -Properties Enabled, PasswordNeverExpires, LastLogonDate -ErrorAction Stop
        Write-Log "Account '$ServiceAccount' found in Active Directory."
        Write-Log "  Enabled              : $($account.Enabled)"
        Write-Log "  Password Never Exp   : $($account.PasswordNeverExpires)"
        Write-Log "  Last Logon           : $($account.LastLogonDate)"
    } catch {
        # Fall back to local user check
        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
        if ($account) {
            Write-Log "Account '$ServiceAccount' found as local account (AD module unavailable)."
        }
    }
} else {
    $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
    if ($account) {
        Write-Log "Account '$ServiceAccount' found as local account."
        Write-Log "  Enabled              : $($account.Enabled)"
        Write-Log "  Password Never Exp   : $($account.PasswordNeverExpires)"
        Write-Log "  Last Logon           : $($account.LastLogon)"
    }
}

if ($null -eq $account) {
    Write-Log "Account '$ServiceAccount' was NOT found on this machine." "WARN"
    Write-Log "Either the account has not been created yet or uses a different name." "WARN"
    Write-Log "Next step: Run Script 4 (Initialize-AcronisBackupProtection.ps1) on this machine." "WARN"
    Write-Log "======================================================"
    Write-Log " AUDIT RESULT: ACCOUNT NOT FOUND (Exit 1)"
    Write-Log "======================================================"
    Exit 1
}

Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — AUDIT GROUP MEMBERSHIPS
# ============================================================

Write-Log "STEP 2: Auditing group memberships for machine class: $MachineClass..."

$findings        = @()   # unexpected memberships (standard) or missing required (DC)
$requiredPresent = @()   # required memberships confirmed on DC
$cleanGroups     = @()

if ($isADAgent) {
    # ---- DOMAIN CONTROLLER PATH ----
    # On a DC with Agent for AD, Acronis REQUIRES these memberships (KB 56202)
    $requiredGroups = @("Domain Admins", "Administrators", "Backup Operators")

    # These should NOT be present even on a DC
    $forbiddenGroups = @(
        "Power Users",
        "Remote Desktop Users",
        "Remote Management Users",
        "Network Configuration Operators",
        "Event Log Readers",
        "Cryptographic Operators",
        "Hyper-V Administrators",
        "Schema Admins",
        "Enterprise Admins",
        "Group Policy Creator Owners"
    )

    Write-Log "  DC Mode: Verifying REQUIRED group memberships (Acronis KB 56202)..."
    foreach ($group in $requiredGroups) {
        try {
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                       Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if ($members) {
                $requiredPresent += $group
                Write-Log "  [OK-REQ] '$ServiceAccount' IS in '$group' — required by Acronis for DC backup."
            } else {
                $findings += "MISSING REQUIRED: $group"
                Write-Log "  [ALERT] '$ServiceAccount' is NOT in '$group' — REQUIRED for Acronis Agent for AD." "WARN"
            }
        } catch {
            Write-Log "  [WARN]  Could not check group '$group'. Details: $_" "WARN"
        }
    }

    Write-Log "  DC Mode: Checking for FORBIDDEN group memberships..."
    foreach ($group in $forbiddenGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                       Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if ($members) {
                $findings += "UNEXPECTED MEMBERSHIP: $group"
                Write-Log "  [ALERT] '$ServiceAccount' IS in '$group' — not required, should be removed." "WARN"
            } else {
                $cleanGroups += $group
                Write-Log "  [OK]    '$ServiceAccount' is NOT in '$group'."
            }
        } catch {
            Write-Log "  [SKIP]  Could not check '$group' (may not exist). Details: $_"
        }
    }

} else {
    # ---- STANDARD MACHINE PATH ----
    # On standard machines, svc_acronis must NOT be in any privileged group
    $privilegedGroups = @(
        "Administrators",
        "Backup Operators",
        "Power Users",
        "Remote Desktop Users",
        "Remote Management Users",
        "Network Configuration Operators",
        "Event Log Readers",
        "Cryptographic Operators",
        "Hyper-V Administrators"
    )

    foreach ($group in $privilegedGroups) {
        $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
        if ($null -eq $groupExists) {
            Write-Log "  [SKIP]  '$group' does not exist on this machine."
            continue
        }
        try {
            $members  = Get-LocalGroupMember -Group $group -ErrorAction Stop
            $isMember = $members | Where-Object { $_.Name -like "*\$ServiceAccount" -or $_.Name -eq $ServiceAccount }
            if ($isMember) {
                $findings += $group
                Write-Log "  [ALERT] '$ServiceAccount' IS a member of '$group' — ACTION REQUIRED." "WARN"
            } else {
                $cleanGroups += $group
                Write-Log "  [OK]    '$ServiceAccount' is NOT in '$group'."
            }
        } catch {
            Write-Log "  [WARN]  Could not enumerate '$group'. Details: $_" "WARN"
        }
    }
}

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEP 3 — VERIFY SERVICE LOGON CONFIGURATION
# ============================================================

Write-Log "STEP 3: Verifying Windows services running as '$ServiceAccount'..."

$services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue |
    Where-Object { $_.StartName -like "*$ServiceAccount*" }

if ($services) {
    foreach ($svc in $services) {
        Write-Log "  [SVC] $($svc.Name) | $($svc.DisplayName) | State: $($svc.State) | StartMode: $($svc.StartMode)"
    }
} else {
    Write-Log "  [WARN] No Windows services are configured to run as '$ServiceAccount'." "WARN"
    Write-Log "         Verify the Acronis Managed Machine Service is using this account." "WARN"
}

Write-Log "STEP 3 COMPLETE."


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " AUDIT COMPLETE — FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
Write-Log " Findings        : $($findings.Count)"
Write-Log "======================================================"

if ($findings.Count -eq 0) {
    Write-Log " RESULT: CLEAN — Account state is correct for this machine class."
    if ($isADAgent -and $requiredPresent.Count -gt 0) {
        Write-Log " Required DC memberships confirmed: $($requiredPresent -join ', ')"
    }
    Write-Log "======================================================"
    Write-Output "`nAUDIT PASSED: $ServiceAccount is correctly configured on $env:COMPUTERNAME ($MachineClass). Log: $LogFile"
    Exit 0
} else {
    Write-Log " RESULT: ACTION REQUIRED — Issues detected." "WARN"
    foreach ($f in $findings) { Write-Log "  [!] $f" "WARN" }
    if ($isADAgent) {
        Write-Log " Next step: Run Script 2 (Fix-BackupServiceAccount.ps1) — DC mode will add missing required groups." "WARN"
    } else {
        Write-Log " Next step: Run Script 2 (Fix-BackupServiceAccount.ps1) — will remove unexpected memberships." "WARN"
    }
    Write-Log "======================================================"
    Write-Output "`nAUDIT FAILED: $($findings.Count) issue(s) found for $ServiceAccount on $env:COMPUTERNAME ($MachineClass). Log: $LogFile"
    Exit 2
}
