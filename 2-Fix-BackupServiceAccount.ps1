#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remediates the Acronis backup service account group memberships and account configuration.

.DESCRIPTION
    Targeted account-only remediation script. Makes no changes to drives, folders,
    NTFS ACLs, AutoRun settings, or audit policies.

    Handles two distinct machine classes:

    STANDARD MACHINES (servers, workstanders, VM guests):
        - Removes svc_acronis from ALL privileged groups
        - Enables account if disabled
        - Sets PasswordNeverExpires = true
        - Creates account if it does not exist

    DOMAIN CONTROLLERS with Agent for Active Directory:
        - ADDS svc_acronis to Domain Admins, Administrators, Backup Operators
          (required by Acronis per KB 56202 — these are NOT security violations on DCs)
        - Removes svc_acronis from any OTHER privileged groups not required by Acronis
        - Enables account if disabled
        - Sets PasswordNeverExpires = true
        - Creates domain account if it does not exist

    Does NOT touch:
        - Backup drive or ACB folder
        - NTFS ACL permissions
        - AutoRun/AutoPlay settings
        - Audit logging policies

.NINJAONE CUSTOM FIELDS (read via Ninja-Property-Get)
    isActiveDirectoryAgent : Boolean (true/false).
                             Set automatically by Script 5 (Detect-DomainController.ps1).

.NINJAONE SCRIPT VARIABLES (Text Input / Secure)
    backupServiceAccount         : Account name. Optional — defaults to "svc_acronis".
    backupServiceAccountPassword : Required only if account must be created.
                                   Configure as Secure/Password type in NinjaOne.

.NOTES
    Author  : Edson Pintado
    Version : 1.1
    Run As  : Administrator / SYSTEM
    Part of : Acronis Backup Security Framework (Script 2 of 5)
#>

# ============================================================
# INITIALIZATION
# ============================================================

# NinjaOne Custom Field
$isADAgentRaw = Ninja-Property-Get isActiveDirectoryAgent 2>$null
$isADAgent    = ($isADAgentRaw -eq "true")

# NinjaOne Script Variables
$ServiceAccount  = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) {
    "svc_acronis"
} else {
    $env:backupServiceAccount.Trim()
}
$AccountPassword = $env:backupServiceAccountPassword

$MachineClass = if ($isADAgent) {
    "Domain Controller — Agent for Active Directory"
} else {
    "Standard Server / Workstation / VM Guest"
}

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
Write-Log " Acronis Backup Security Framework — Script 2 of 5"
Write-Log " Remediation: Backup Service Account"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
Write-Log " Scope           : Account only (drive not touched)"
Write-Log "======================================================"


# ============================================================
# STEP 1 — VALIDATE OR CREATE SERVICE ACCOUNT
# ============================================================

Write-Log "STEP 1: Checking for service account '$ServiceAccount'..."

if ($isADAgent) {
    # ---- DOMAIN CONTROLLER PATH — use AD module ----
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $account = Get-ADUser -Filter { SamAccountName -eq $ServiceAccount } `
                              -Properties Enabled, PasswordNeverExpires -ErrorAction Stop
    } catch {
        $account = $null
        Write-Log "  AD module unavailable or query failed. Falling back to local user check." "WARN"
        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
    }

    if ($null -eq $account) {
        Write-Log "Domain account '$ServiceAccount' not found. Attempting to create it..." "WARN"

        if ([string]::IsNullOrWhiteSpace($AccountPassword)) {
            Write-Log "ERROR: Account does not exist and 'backupServiceAccountPassword' is not set." "ERROR"
            Write-Log "       Set the password variable in NinjaOne Script Variables (Secure/Password type) and re-run." "ERROR"
            Exit 1
        }

        try {
            $securePassword = ConvertTo-SecureString -String $AccountPassword -AsPlainText -Force
            New-ADUser `
                -SamAccountName       $ServiceAccount `
                -Name                 $ServiceAccount `
                -DisplayName          "Acronis Backup Service Account" `
                -Description          "Managed by NinjaOne hardening script. Required Domain Admins for Agent for AD." `
                -AccountPassword      $securePassword `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true `
                -Enabled              $true `
                -ErrorAction          Stop

            Write-Log "Domain account '$ServiceAccount' created successfully."
            Write-Log "  Password : Set from NinjaOne secure variable (not logged)."
            $account = Get-ADUser -Filter { SamAccountName -eq $ServiceAccount } `
                                  -Properties Enabled, PasswordNeverExpires -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to create domain account '$ServiceAccount'. Details: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "Account '$ServiceAccount' found. OK."
    }

    # Ensure enabled and password never expires (AD path)
    if ($account.PSObject.TypeNames -contains "Microsoft.ActiveDirectory.Management.ADUser") {
        if (-not $account.Enabled) {
            Write-Log "Account is disabled. Enabling..." "WARN"
            Enable-ADAccount -Identity $ServiceAccount
            Write-Log "Account enabled."
        } else {
            Write-Log "Account is enabled. OK."
        }
        if (-not $account.PasswordNeverExpires) {
            Write-Log "Password expiration is enabled. Setting to Never Expire..." "WARN"
            Set-ADUser -Identity $ServiceAccount -PasswordNeverExpires $true
            Write-Log "Password expiration disabled."
        } else {
            Write-Log "Password expiration is already disabled. OK."
        }
    }

} else {
    # ---- STANDARD MACHINE PATH — use local user ----
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
            $account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to create account '$ServiceAccount'. Details: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "Account '$ServiceAccount' found. OK."
    }

    if (-not $account.Enabled) {
        Write-Log "Account is disabled. Enabling..." "WARN"
        Enable-LocalUser -Name $ServiceAccount
        Write-Log "Account enabled."
    } else {
        Write-Log "Account is enabled. OK."
    }

    if ($account.PasswordNeverExpires -eq $false) {
        Write-Log "Password expiration is enabled. Setting to Never Expire..." "WARN"
        Set-LocalUser -Name $ServiceAccount -PasswordNeverExpires $true
        Write-Log "Password expiration disabled."
    } else {
        Write-Log "Password expiration is already disabled. OK."
    }
}

Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — MANAGE GROUP MEMBERSHIPS
# ============================================================

Write-Log "STEP 2: Managing group memberships for '$ServiceAccount'..."

$added   = @()
$removed = @()

if ($isADAgent) {
    # ---- DOMAIN CONTROLLER PATH ----
    # Required groups per Acronis KB 56202 — MUST be present
    $requiredGroups = @("Domain Admins", "Administrators", "Backup Operators")

    # Forbidden groups — must NOT be present even on a DC
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

    Write-Log "  DC Mode: Ensuring REQUIRED group memberships are present (Acronis KB 56202)..."
    foreach ($group in $requiredGroups) {
        try {
            $members  = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                        Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if (-not $members) {
                Add-ADGroupMember -Identity $group -Members $ServiceAccount -ErrorAction Stop
                $added += $group
                Write-Log "  [ADDED] '$ServiceAccount' added to '$group' — required by Acronis for Agent for AD."
            } else {
                Write-Log "  [OK]    '$ServiceAccount' is already in '$group'."
            }
        } catch {
            Write-Log "  [WARN]  Could not process required group '$group'. Details: $_" "WARN"
        }
    }

    Write-Log "  DC Mode: Removing FORBIDDEN group memberships..."
    foreach ($group in $forbiddenGroups) {
        try {
            $members  = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                        Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if ($members) {
                Remove-ADGroupMember -Identity $group -Members $ServiceAccount -Confirm:$false -ErrorAction Stop
                $removed += $group
                Write-Log "  [FIXED] Removed '$ServiceAccount' from '$group' — not required for Acronis."
            } else {
                Write-Log "  [OK]    '$ServiceAccount' is not in '$group'."
            }
        } catch {
            Write-Log "  [SKIP]  Could not check/remove '$group' (may not exist). Details: $_"
        }
    }

} else {
    # ---- STANDARD MACHINE PATH ----
    # Remove from ALL privileged groups — none are required
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
                Remove-LocalGroupMember -Group $group -Member $ServiceAccount -ErrorAction Stop
                $removed += $group
                Write-Log "  [FIXED] Removed '$ServiceAccount' from '$group'."
            } else {
                Write-Log "  [OK]    '$ServiceAccount' is not in '$group'."
            }
        } catch {
            Write-Log "  [WARN]  Could not process group '$group'. Details: $_" "WARN"
        }
    }
}

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEP 3 — VERIFY FINAL STATE
# ============================================================

Write-Log "STEP 3: Verifying final account state..."

$remainingIssues = @()

if ($isADAgent) {
    $requiredGroups = @("Domain Admins", "Administrators", "Backup Operators")
    foreach ($group in $requiredGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction Stop |
                       Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if (-not $members) { $remainingIssues += "STILL MISSING: $group" }
        } catch {}
    }
} else {
    $privilegedGroups = @("Administrators","Backup Operators","Power Users","Remote Desktop Users",
                          "Remote Management Users","Network Configuration Operators",
                          "Event Log Readers","Cryptographic Operators","Hyper-V Administrators")
    foreach ($group in $privilegedGroups) {
        $groupExists = Get-LocalGroup -Name $group -ErrorAction SilentlyContinue
        if ($null -eq $groupExists) { continue }
        try {
            $members  = Get-LocalGroupMember -Group $group -ErrorAction Stop
            $isMember = $members | Where-Object { $_.Name -like "*\$ServiceAccount" -or $_.Name -eq $ServiceAccount }
            if ($isMember) { $remainingIssues += $group }
        } catch {}
    }
}

if ($remainingIssues.Count -eq 0) {
    Write-Log "  Verification: Account state is correct for machine class. OK."
} else {
    Write-Log "  WARNING: Remaining issues detected:" "WARN"
    foreach ($r in $remainingIssues) { Write-Log "    [!] $r" "WARN" }
}

Write-Log "STEP 3 COMPLETE."


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " REMEDIATION COMPLETE — FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
if ($added.Count -gt 0) {
    Write-Log " Groups Added    : $($added.Count)"
    foreach ($a in $added) { Write-Log "   + $a" }
}
if ($removed.Count -gt 0) {
    Write-Log " Groups Removed  : $($removed.Count)"
    foreach ($r in $removed) { Write-Log "   - $r" }
}
Write-Log " Remaining Issues: $($remainingIssues.Count)"
Write-Log " Log File        : $LogFile"
Write-Log "======================================================"

if ($remainingIssues.Count -eq 0) {
    Write-Output "`nSUCCESS: Account remediation complete on $env:COMPUTERNAME ($MachineClass). Log: $LogFile"
    Exit 0
} else {
    Write-Output "`nWARNING: Remediation completed with $($remainingIssues.Count) unresolved issue(s) on $env:COMPUTERNAME. Log: $LogFile"
    Exit 2
}
