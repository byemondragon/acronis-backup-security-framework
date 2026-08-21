#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Full initial Acronis backup security setup for new machines.

.DESCRIPTION
    Onboarding script for new machines receiving Acronis Cyber Protect Cloud for the first time.
    Combines account setup and drive hardening into a single idempotent run.

    Reads the NinjaOne Custom Field "isHyperVHost" and the "backupDriveLetter" variable
    to determine which steps apply to this machine:

    ALL MACHINES (Hyper-V hosts, VM guests, workstanders, standalone servers):
        - Create svc_acronis account if it does not exist
        - Ensure account is enabled and password never expires
        - Remove account from all privileged groups

    MACHINES WITH A LOCALLY ATTACHED BACKUP DRIVE (backupDriveLetter is set):
        - Validate drive exists
        - Create ACB folder
        - Apply least privilege NTFS ACL
        - Disable AutoRun/AutoPlay
        - Enable NTFS audit logging
        - Verify final ACL state

    VM GUESTS WITH NO LOCAL BACKUP DRIVE (backupDriveLetter is empty):
        - Drive steps are skipped — backup destination is on the Hyper-V host
        - Account steps still run

    This script is idempotent — safe to re-run if interrupted or if configuration
    needs to be reapplied.

.NINJAONE CUSTOM FIELD
    isHyperVHost : Boolean (true/false). Used for logging context only.

.NINJAONE ENVIRONMENT VARIABLES (Script Variables — Text Input)
    backupDriveLetter          : Single drive letter without colon (e.g., E).
                                 Required for machines with a locally attached backup drive.
                                 Leave empty for VM guests whose backup drive is on the host.
    backupServiceAccount       : Local service account name (e.g., svc_acronis).
                                 Optional — defaults to "svc_acronis" if not set.
    backupServiceAccountPassword: Strong password for the service account.
                                 Required if the account does not exist yet.
                                 Configure as Secure/Password type in NinjaOne.

.NOTES
    Author  : Edson Pintado
    Version : 1.0
    Run As  : Administrator / SYSTEM
    Part of : Acronis Backup Security Framework (Script 4 of 4)
#>

# ============================================================
# INITIALIZATION
# ============================================================

# NinjaOne Custom Field
$isHyperVHostRaw = Ninja-Property-Get isHyperVHost 2>$null
$isHyperVHost    = ($isHyperVHostRaw -eq "true")

# NinjaOne Script Variables
$DriveLetter     = $env:backupDriveLetter
$ServiceAccount  = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) {
    "svc_acronis"
} else {
    $env:backupServiceAccount.Trim()
}
$AccountPassword = $env:backupServiceAccountPassword

# Sanitize drive letter if provided
$hasDrive = -not [string]::IsNullOrWhiteSpace($DriveLetter)
if ($hasDrive) {
    $DriveLetter = $DriveLetter.Trim().TrimEnd(':').TrimEnd('\').ToUpper()
    $BackupPath  = "$($DriveLetter):\ACB"
}

# Determine machine role for logging
$machineRole = if ($isHyperVHost) {
    "Hyper-V Host"
} elseif ($hasDrive) {
    "Standalone Server / Workstation"
} else {
    "VM Guest (backup drive on Hyper-V host)"
}

$LogFile = "C:\Logs\ACB-Initialize-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework — Script 4 of 4"
Write-Log " Initialize: Full Acronis Backup Protection Setup"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Role    : $machineRole"
Write-Log " Service Account : .\$ServiceAccount"
if ($hasDrive) {
    Write-Log " Drive Letter    : $DriveLetter"
    Write-Log " Backup Path     : $BackupPath"
} else {
    Write-Log " Drive Letter    : Not set — drive steps will be skipped"
}
Write-Log "======================================================"


# ============================================================
# STEP 1 — VALIDATE OR CREATE SERVICE ACCOUNT (All machines)
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
    Write-Log "Account is disabled. Enabling..." "WARN"
    Enable-LocalUser -Name $ServiceAccount
    Write-Log "Account '$ServiceAccount' enabled."
} else {
    Write-Log "Account is enabled. OK."
}

# Ensure password never expires
if ($account.PasswordNeverExpires -eq $false) {
    Write-Log "Password expiration is enabled. Setting to Never Expire..." "WARN"
    Set-LocalUser -Name $ServiceAccount -PasswordNeverExpires $true
    Write-Log "Password expiration disabled."
} else {
    Write-Log "Password expiration is already disabled. OK."
}

Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — REMOVE FROM PRIVILEGED GROUPS (All machines)
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

$removed = @()

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

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEP 3 — VALIDATE DRIVE EXISTS (Local drive machines only)
# ============================================================

if ($hasDrive) {

    Write-Log "STEP 3: Validating drive '$($DriveLetter):' exists..."

    if (-not (Test-Path "$($DriveLetter):")) {
        Write-Log "ERROR: Drive '$($DriveLetter):' does not exist or is not accessible." "ERROR"
        Write-Log "       Verify the drive is connected and the drive letter is correct." "ERROR"
        Exit 1
    }

    Write-Log "Drive '$($DriveLetter):' found. OK."
    Write-Log "STEP 3 COMPLETE."

} else {
    Write-Log "STEP 3: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# STEP 4 — CREATE ACB FOLDER (Local drive machines only)
# ============================================================

if ($hasDrive) {

    Write-Log "STEP 4: Checking for backup folder '$BackupPath'..."

    if (-not (Test-Path $BackupPath)) {
        Write-Log "Folder '$BackupPath' does not exist. Creating..."
        try {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
            Write-Log "Folder '$BackupPath' created successfully."
        } catch {
            Write-Log "ERROR: Failed to create folder '$BackupPath'. Details: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "Folder '$BackupPath' already exists. OK."
    }

    Write-Log "STEP 4 COMPLETE."

} else {
    Write-Log "STEP 4: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# STEP 5 — APPLY LEAST PRIVILEGE NTFS ACL (Local drive machines only)
# ============================================================

function Resolve-IdentityToSID {
    param([string]$IdentityName)
    try {
        $ntAccount = New-Object System.Security.Principal.NTAccount($IdentityName)
        return $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
    } catch {
        Write-Log "ERROR: Could not resolve identity '$IdentityName' to a SID. Details: $_" "ERROR"
        throw
    }
}

if ($hasDrive) {

    Write-Log "STEP 5: Applying least privilege NTFS permissions to '$BackupPath'..."

    try {
        $acl = Get-Acl -Path $BackupPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $computerName = $env:COMPUTERNAME
        $sidService   = Resolve-IdentityToSID "$computerName\$ServiceAccount"
        $sidAdmins    = Resolve-IdentityToSID "BUILTIN\Administrators"
        $sidSystem    = Resolve-IdentityToSID "NT AUTHORITY\SYSTEM"

        Write-Log "Identity resolution: $ServiceAccount -> SID $($sidService.Value)"
        Write-Log "Identity resolution: Administrators  -> SID $($sidAdmins.Value)"
        Write-Log "Identity resolution: SYSTEM          -> SID $($sidSystem.Value)"

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sidService, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Write-Log "ACL rule added: $ServiceAccount -> Full Control"

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sidAdmins, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Write-Log "ACL rule added: Administrators -> Read & Execute only"

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $sidSystem, "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Write-Log "ACL rule added: SYSTEM -> Read & Execute only"

        Set-Acl -Path $BackupPath -AclObject $acl
        Write-Log "NTFS ACL applied. All other identities have no access to '$BackupPath'."

    } catch {
        Write-Log "ERROR: Failed to apply NTFS ACL. Details: $_" "ERROR"
        Exit 1
    }

    Write-Log "STEP 5 COMPLETE."

} else {
    Write-Log "STEP 5: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# STEP 6 — DISABLE AUTORUN/AUTOPLAY (Local drive machines only)
# ============================================================

if ($hasDrive) {

    Write-Log "STEP 6: Disabling AutoRun/AutoPlay on drive '$($DriveLetter):'..."

    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
        Write-Log "AutoRun disabled for all drive types."

        $autoPlayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\$($DriveLetter):"
        if (-not (Test-Path $autoPlayPath)) { New-Item -Path $autoPlayPath -Force | Out-Null }
        Set-ItemProperty -Path $autoPlayPath -Name "(Default)" -Value "MSTakeNoAction" -Force
        Write-Log "AutoPlay set to 'Take no action' for drive '$($DriveLetter):'."

    } catch {
        Write-Log "WARNING: Could not fully configure AutoRun/AutoPlay. Details: $_" "WARN"
    }

    Write-Log "STEP 6 COMPLETE."

} else {
    Write-Log "STEP 6: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# STEP 7 — ENABLE NTFS AUDIT LOGGING (Local drive machines only)
# ============================================================

if ($hasDrive) {

    Write-Log "STEP 7: Enabling audit logging on '$BackupPath'..."

    try {
        $auditResult = auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1
        Write-Log "Audit policy configured: $auditResult"

        $acl = Get-Acl -Path $BackupPath
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Write,Delete,DeleteSubdirectoriesAndFiles",
            "ContainerInherit,ObjectInherit", "None", "Failure"
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $BackupPath -AclObject $acl
        Write-Log "Audit ACE applied: Failed Write/Delete attempts logged in Security Event Log."

    } catch {
        Write-Log "WARNING: Could not apply audit ACE. Details: $_" "WARN"
    }

    Write-Log "STEP 7 COMPLETE."

} else {
    Write-Log "STEP 7: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# STEP 8 — VERIFY FINAL ACL STATE (Local drive machines only)
# ============================================================

if ($hasDrive) {

    Write-Log "STEP 8: Verifying final ACL state on '$BackupPath'..."

    $finalAcl = Get-Acl -Path $BackupPath
    $finalAcl.Access | ForEach-Object {
        Write-Log "  PERMISSION: $($_.IdentityReference) | $($_.FileSystemRights) | $($_.AccessControlType)"
    }

    Write-Log "STEP 8 COMPLETE."

} else {
    Write-Log "STEP 8: SKIPPED — No local backup drive configured for this machine."
}


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " INITIALIZATION COMPLETE — FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Role    : $machineRole"
Write-Log " Service Account : .\$ServiceAccount -> Configured"
Write-Log " Groups Removed  : $($removed.Count)"
foreach ($r in $removed) { Write-Log "   - Removed from: $r" }
if ($hasDrive) {
    Write-Log " Backup Path     : $BackupPath"
    Write-Log " ACL Applied     : $ServiceAccount Full Control | Admins/SYSTEM Read only | All others No Access"
    Write-Log " AutoRun         : Disabled"
    Write-Log " Audit Logging   : Enabled"
} else {
    Write-Log " Drive Steps     : SKIPPED (VM guest — backup drive is on the Hyper-V host)"
}
Write-Log " Log File        : $LogFile"
Write-Log "======================================================"

Write-Output "`nSUCCESS: Acronis backup protection initialized on $env:COMPUTERNAME ($machineRole). Log: $LogFile"
Exit 0
