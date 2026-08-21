#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates the Acronis backup service account — removes privileged group memberships
    and enforces correct account configuration.

.DESCRIPTION
    Targeted account-only remediation script. Makes no changes to drives, folders,
    NTFS ACLs, AutoRun settings, or audit policies.

    Run this script when Script 1 (Audit) returns Exit 2 on an existing machine,
    indicating the service account has one or more privileged group memberships.

    Actions performed:
        - Removes service account from all privileged local groups
        - Enables the account if disabled
        - Sets PasswordNeverExpires = true
        - Creates the account if it does not exist (requires password variable)

    Does NOT touch:
        - Backup drive or ACB folder
        - NTFS ACL permissions
        - AutoRun/AutoPlay settings
        - Audit logging policies

.NINJAONE ENVIRONMENT VARIABLES (Script Variables — Text Input)
    backupServiceAccount         : Local service account name (e.g., svc_acronis).
                                   Optional — defaults to "svc_acronis" if not set.
    backupServiceAccountPassword : Required only if the account does not exist and must be created.
                                   Configure as Secure/Password type in NinjaOne.

.NOTES
    Author  : Edson Pintado
    Version : 1.0
    Run As  : Administrator / SYSTEM
    Part of : Acronis Backup Security Framework (Script 2 of 4)
#>

# ============================================================
# INITIALIZATION
# ============================================================

$ServiceAccount  = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) {
    "svc_acronis"
} else {
    $env:backupServiceAccount.Trim()
}
$AccountPassword = $env:backupServiceAccountPassword

$LogFile = "C:\Logs\ACB-FixAccount-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework — Script 2 of 4"
Write-Log " Remediation: Backup Service Account"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Service Account : .\$ServiceAccount"
Write-Log " Scope           : Account only (drive not touched)"
Write-Log "======================================================"


# ============================================================
# STEP 1 — VALIDATE OR CREATE SERVICE ACCOUNT
# ============================================================

Write-Log "STEP 1: Checking for service account '.\$ServiceAccount'..."

$account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue

if ($null -eq $account) {
    Write-Log "Account '$ServiceAccount' not found. Attempting to create it..." "WARN"

    if ([string]::IsNullOrWhiteSpace($AccountPassword)) {
        Write-Log "ERROR: Account does not exist and 'backupServiceAccountPassword' is not set." "ERROR"
        Write-Log "       Set the password variable in NinjaOne Script Variables (Secure/Password type) and re-run." "ERROR"
        Exit 1
    }

    try {
        $securePassword = ConvertTo-SecureString -String $AccountPassword -AsPlainText -Force

        New-LocalUser `
            -Name                 $ServiceAccount `
            -Password             $securePassword `
            -FullName             "Acronis Backup Service Account" `
            -Description          "Managed by NinjaOne hardening script. Least-privilege backup account." `
            -PasswordNeverExpires `
            -UserMayNotChangePassword `
            -ErrorAction          Stop

        Write-Log "Account '$ServiceAccount' created successfully."
        Write-Log "  Password : Set from NinjaOne secure variable (not logged)."
        Write-Log "  Flags    : PasswordNeverExpires, UserMayNotChangePassword."

        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop

    } catch {
        Write-Log "ERROR: Failed to create account '$ServiceAccount'. Details: $_" "ERROR"
        Write-Log "       Ensure the password meets the local password complexity policy." "ERROR"
        Exit 1
    }

} else {
    Write-Log "Account '$ServiceAccount' already exists. OK."
}

# Ensure account is enabled
if (-not $account.Enabled) {
    Write-Log "Account '$ServiceAccount' is disabled. Enabling..." "WARN"
    Enable-LocalUser -Name $ServiceAccount
    Write-Log "Account '$ServiceAccount' enabled."
} else {
    Write-Log "Account '$ServiceAccount' is enabled. OK."
}

# Ensure password never expires
if ($account.PasswordNeverExpires -eq $false) {
    Write-Log "Password expiration is enabled. Setting to Never Expire..." "WARN"
    Set-LocalUser -Name $ServiceAccount -PasswordNeverExpires $true
    Write-Log "Password expiration disabled for '$ServiceAccount'."
} else {
    Write-Log "Password expiration is already disabled. OK."
}

Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — REMOVE FROM PRIVILEGED GROUPS
# ============================================================

Write-Log "STEP 2: Removing '$ServiceAccount' from all privileged groups..."

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

$removed     = @()
$notMember   = @()
$notPresent  = @()

foreach ($group in $privilegedGroups) {
    $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
    if ($null -eq $groupExists) {
        $notPresent += $group
        Write-Log "  [SKIP]  '$group' does not exist on this machine."
        continue
    }
    try {
        $members  = Get-LocalGroupMember -Group $group -ErrorAction Stop
        $isMember = $members | Where-Object { $_.Name -like "*\$ServiceAccount" -or $_.Name -eq $ServiceAccount }
        if ($isMember) {
            Remove-LocalGroupMember -Group $group -Member $ServiceAccount -ErrorAction Stop
            $removed += $group
            Write-Log "  [FIXED] Removed '$ServiceAccount' from '$group'."
        } else {
            $notMember += $group
            Write-Log "  [OK]    '$ServiceAccount' is not in '$group'."
        }
    } catch {
        Write-Log "  [WARN]  Could not process group '$group'. Details: $_" "WARN"
    }
}

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEP 3 — VERIFY FINAL STATE
# ============================================================

Write-Log "STEP 3: Verifying final account state..."

$accountFinal = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
if ($accountFinal) {
    Write-Log "  Enabled              : $($accountFinal.Enabled)"
    Write-Log "  Password Never Exp   : $($accountFinal.PasswordNeverExpires)"
    Write-Log "  Last Logon           : $($accountFinal.LastLogon)"
}

# Confirm no remaining privileged memberships
$remainingFindings = @()
foreach ($group in $privilegedGroups) {
    $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
    if ($null -eq $groupExists) { continue }
    try {
        $members  = Get-LocalGroupMember -Group $group -ErrorAction Stop
        $isMember = $members | Where-Object { $_.Name -like "*\$ServiceAccount" -or $_.Name -eq $ServiceAccount }
        if ($isMember) { $remainingFindings += $group }
    } catch {}
}

if ($remainingFindings.Count -eq 0) {
    Write-Log "  Verification: No privileged group memberships remain. OK."
} else {
    Write-Log "  WARNING: The following groups still contain '$ServiceAccount':" "WARN"
    foreach ($r in $remainingFindings) { Write-Log "    [!] $r" "WARN" }
}

Write-Log "STEP 3 COMPLETE."


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " REMEDIATION COMPLETE — FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Service Account : .\$ServiceAccount"
Write-Log " Groups Removed  : $($removed.Count)"
foreach ($r in $removed) { Write-Log "   - $r" }
Write-Log " Remaining Issues: $($remainingFindings.Count)"
Write-Log " Log File        : $LogFile"
Write-Log "======================================================"

if ($remainingFindings.Count -eq 0) {
    Write-Output "`nSUCCESS: Account remediation complete on $env:COMPUTERNAME. Log: $LogFile"
    Exit 0
} else {
    Write-Output "`nWARNING: Remediation completed with $($remainingFindings.Count) unresolved issue(s) on $env:COMPUTERNAME. Log: $LogFile"
    Exit 2
}
