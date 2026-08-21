#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Applies least privilege NTFS hardening to the Acronis backup drive destination.

.DESCRIPTION
    Targeted drive-only remediation script. Makes no changes to the service account,
    group memberships, or account configuration.

    Run this script when the backup drive ACL permissions need to be corrected on an
    existing machine — for example, after the drive was replaced, re-lettered, or
    the ACB folder permissions were inadvertently changed.

    IMPORTANT — Domain Controller behavior:
        On a DC running Agent for Active Directory, svc_acronis is a member of
        Domain Admins (required by Acronis KB 56202). The NTFS ACL on D:\ACB still
        restricts access to svc_acronis (Full Control) and Administrators/SYSTEM
        (Read only). The Domain Admins membership does NOT grant additional access
        to D:\ACB beyond what the ACL explicitly allows — NTFS permissions take
        precedence over group membership for file system access.

    Actions performed:
        - Validates the backup drive exists
        - Creates the ACB folder if it does not exist
        - Breaks NTFS inheritance and applies clean least-privilege ACL
        - Grants Full Control to the backup service account only
        - Grants Read & Execute to Administrators and SYSTEM
        - Removes all other access
        - Disables AutoRun/AutoPlay on the backup drive
        - Enables NTFS audit logging for failed Write/Delete attempts
        - Verifies and logs the final ACL state

    Note: backupDriveLetter is the execution trigger.
          If not set, the script exits cleanly — this machine has no locally
          attached backup drive to harden (e.g., VM guest).

.NINJAONE CUSTOM FIELDS (read via Ninja-Property-Get)
    isActiveDirectoryAgent : Boolean. Used for logging context only in this script.

.NINJAONE SCRIPT VARIABLES (Text Input)
    backupDriveLetter    : Single drive letter without colon (e.g., E). Required.
    backupServiceAccount : Account name. Optional — defaults to "svc_acronis".

.NOTES
    Author  : Edson Pintado
    Version : 1.1
    Run As  : Administrator / SYSTEM
    Part of : Acronis Backup Security Framework (Script 3 of 5)
#>

# ============================================================
# INITIALIZATION
# ============================================================

# NinjaOne Custom Field
$isADAgentRaw = Ninja-Property-Get isActiveDirectoryAgent 2>$null
$isADAgent    = ($isADAgentRaw -eq "true")

# NinjaOne Script Variables
$DriveLetter    = $env:backupDriveLetter
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

# Validate drive letter was provided
if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
    Write-Output "INFO: NinjaOne variable 'backupDriveLetter' is not set."
    Write-Output "      This machine has no locally attached backup drive to harden."
    Write-Output "      If this is a VM guest, the backup drive resides on the Hyper-V host."
    Write-Output "      No action taken. Exiting cleanly."
    Exit 0
}

# Sanitize drive letter
$DriveLetter = $DriveLetter.Trim().TrimEnd(':').TrimEnd('\').ToUpper()
$BackupPath  = "$($DriveLetter):\ACB"
$LogFile     = "C:\Logs\ACB-FixDrive-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework — Script 3 of 5"
Write-Log " Remediation: Backup Drive Least Privilege"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Drive Letter    : $DriveLetter"
Write-Log " Backup Path     : $BackupPath"
Write-Log " Service Account : $ServiceAccount"
Write-Log " Scope           : Drive only (account not touched)"
if ($isADAgent) {
    Write-Log " DC Note         : svc_acronis is Domain Admins member (Acronis requirement)."
    Write-Log "                   NTFS ACL still restricts D:\ACB access — file system"
    Write-Log "                   permissions take precedence over group membership."
}
Write-Log "======================================================"


# ============================================================
# STEP 1 — VALIDATE DRIVE EXISTS
# ============================================================

Write-Log "STEP 1: Validating drive '$($DriveLetter):' exists..."

if (-not (Test-Path "$($DriveLetter):")) {
    Write-Log "ERROR: Drive '$($DriveLetter):' does not exist or is not accessible." "ERROR"
    Write-Log "       Verify the drive is connected and the drive letter is correct." "ERROR"
    Exit 1
}

Write-Log "Drive '$($DriveLetter):' found. OK."
Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 — CREATE ACB FOLDER IF IT DOES NOT EXIST
# ============================================================

Write-Log "STEP 2: Checking for backup folder '$BackupPath'..."

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

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEP 3 — APPLY LEAST PRIVILEGE NTFS ACL
# ============================================================

Write-Log "STEP 3: Applying least privilege NTFS permissions to '$BackupPath'..."

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

try {
    $acl = Get-Acl -Path $BackupPath
    $acl.SetAccessRuleProtection($true, $false)
    $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

    # Resolve service account identity
    # On a DC, svc_acronis is a domain account — resolve via domain\account
    if ($isADAgent) {
        $domainName  = (Get-WmiObject Win32_ComputerSystem).Domain
        $accountFQN  = "$domainName\$ServiceAccount"
    } else {
        $accountFQN  = "$env:COMPUTERNAME\$ServiceAccount"
    }

    $sidService = Resolve-IdentityToSID $accountFQN
    $sidAdmins  = Resolve-IdentityToSID "BUILTIN\Administrators"
    $sidSystem  = Resolve-IdentityToSID "NT AUTHORITY\SYSTEM"

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

Write-Log "STEP 3 COMPLETE."


# ============================================================
# STEP 4 — DISABLE AUTORUN/AUTOPLAY
# ============================================================

Write-Log "STEP 4: Disabling AutoRun/AutoPlay on drive '$($DriveLetter):'..."

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

Write-Log "STEP 4 COMPLETE."


# ============================================================
# STEP 5 — ENABLE NTFS AUDIT LOGGING
# ============================================================

Write-Log "STEP 5: Enabling audit logging on '$BackupPath'..."

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

Write-Log "STEP 5 COMPLETE."


# ============================================================
# STEP 6 — VERIFY FINAL ACL STATE
# ============================================================

Write-Log "STEP 6: Verifying final ACL state on '$BackupPath'..."

$finalAcl = Get-Acl -Path $BackupPath
$finalAcl.Access | ForEach-Object {
    Write-Log "  PERMISSION: $($_.IdentityReference) | $($_.FileSystemRights) | $($_.AccessControlType)"
}

Write-Log "STEP 6 COMPLETE."


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " REMEDIATION COMPLETE — FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Backup Path     : $BackupPath"
Write-Log " ACL Applied     : $ServiceAccount Full Control | Admins/SYSTEM Read only | All others No Access"
Write-Log " AutoRun         : Disabled"
Write-Log " Audit Logging   : Enabled"
Write-Log " Log File        : $LogFile"
Write-Log "======================================================"

Write-Output "`nSUCCESS: Drive hardening complete on $env:COMPUTERNAME ($MachineClass). Log: $LogFile"
Exit 0
