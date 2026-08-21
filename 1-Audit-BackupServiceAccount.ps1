#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Audits the Acronis backup service account for privileged group memberships.

.DESCRIPTION
    READ-ONLY script. Makes no changes to the system.
    Checks the backup service account against all known privileged local groups
    and reports findings with clear exit codes for NinjaOne alerting.

    Run this script first on any machine — new or existing — before running
    any remediation or initialization script.

    Exit Codes:
        0 = CLEAN    — Account exists, no privileged group memberships found
        1 = NOTFOUND — Account does not exist on this machine
        2 = FINDINGS — One or more privileged group memberships detected

.NINJAONE ENVIRONMENT VARIABLES (Script Variables — Text Input)
    backupServiceAccount : Local service account name (e.g., svc_acronis).
                           Optional — defaults to "svc_acronis" if not set.

.NOTES
    Author  : Edson Pintado
    Version : 1.1
    Run As  : Administrator / SYSTEM
    Type    : Read-Only Audit — no changes made
    Part of : Acronis Backup Security Framework (Script 1 of 4)
#>

# ============================================================
# INITIALIZATION
# ============================================================

$ServiceAccount = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) {
    "svc_acronis"
} else {
    $env:backupServiceAccount.Trim()
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
Write-Log " Acronis Backup Security Framework — Script 1 of 4"
Write-Log " Audit: Backup Service Account Privileges"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Service Account : .\$ServiceAccount"
Write-Log " Audit Type      : READ-ONLY (no changes made)"
Write-Log "======================================================"


# ============================================================
# STEP 1 — VERIFY ACCOUNT EXISTS
# ============================================================

Write-Log "STEP 1: Checking if account '$ServiceAccount' exists..."

$account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue

if ($null -eq $account) {
    Write-Log "Account '$ServiceAccount' was NOT found on this machine." "WARN"
    Write-Log "Either the account has not been created yet or uses a different name." "WARN"
    Write-Log "Next step: Run Script 4 (Initialize-AcronisBackupProtection.ps1) on this machine." "WARN"
    Write-Log "======================================================"
    Write-Log " AUDIT RESULT: ACCOUNT NOT FOUND (Exit 1)"
    Write-Log "======================================================"
    Exit 1
}

Write-Log "Account '$ServiceAccount' found."
Write-Log "  Enabled              : $($account.Enabled)"
Write-Log "  Password Expires     : $($account.PasswordExpires)"
Write-Log "  Password Never Exp   : $($account.PasswordNeverExpires)"
Write-Log "  Last Logon           : $($account.LastLogon)"
Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — AUDIT PRIVILEGED GROUP MEMBERSHIPS
# ============================================================

Write-Log "STEP 2: Auditing privileged group memberships..."

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

$findings   = @()
$cleanGroups = @()
$skipped    = @()

foreach ($group in $privilegedGroups) {
    $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
    if ($null -eq $groupExists) {
        $skipped += $group
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
Write-Log " Service Account : .\$ServiceAccount"
Write-Log " Groups Checked  : $($privilegedGroups.Count)"
Write-Log " Groups Skipped  : $($skipped.Count) (not present on this machine)"
Write-Log " Findings        : $($findings.Count)"
Write-Log "======================================================"

if ($findings.Count -eq 0) {
    Write-Log " RESULT: CLEAN — No privileged group memberships detected."
    Write-Log " No remediation required."
    Write-Log "======================================================"
    Write-Output "`nAUDIT PASSED: $ServiceAccount is clean on $env:COMPUTERNAME. Log: $LogFile"
    Exit 0
} else {
    Write-Log " RESULT: ACTION REQUIRED — Privileged memberships detected." "WARN"
    foreach ($f in $findings) { Write-Log "  [!] Member of: $f" "WARN" }
    Write-Log " Next step: Run Script 2 (Fix-BackupServiceAccount.ps1) on this machine." "WARN"
    Write-Log "======================================================"
    Write-Output "`nAUDIT FAILED: $ServiceAccount has $($findings.Count) privileged group membership(s) on $env:COMPUTERNAME. Log: $LogFile"
    Exit 2
}
