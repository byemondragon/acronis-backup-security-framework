#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Full initial setup of Acronis backup protection on a new machine.

.DESCRIPTION
    Onboarding script for new machines receiving Acronis Cyber Protect Cloud.
    Handles all machine classes in a single deployment:

    STANDARD MACHINES (servers, workstations):
        - Creates svc_acronis local account if not present
        - Removes account from all privileged groups
        - Creates D:\ACB folder (or specified drive letter)
        - Applies least-privilege NTFS ACL
        - Disables AutoRun/AutoPlay on backup drive
        - Enables NTFS audit logging

    DOMAIN CONTROLLERS with Agent for Active Directory:
        - Creates svc_acronis domain account if not present
        - Ensures membership in Domain Admins, Administrators, Backup Operators
          (required by Acronis KB 56202 for Agent for Active Directory)
        - Removes account from any OTHER privileged groups not required by Acronis
        - Creates D:\ACB folder (or specified drive letter)
        - Applies least-privilege NTFS ACL (NTFS restricts file access regardless
          of Domain Admins membership)
        - Disables AutoRun/AutoPlay on backup drive
        - Enables NTFS audit logging

    VM GUESTS (backup drive resides on Hyper-V host):
        - backupDriveLetter is empty -> drive steps are skipped
        - Account is still validated and configured
        - Logs that drive hardening was performed on the Hyper-V host

    Decision logic:
        backupDriveLetter is set   -> Run full hardening (account + drive)
        backupDriveLetter is empty -> Run account-only hardening (VM guest)
        isActiveDirectoryAgent = true  -> DC mode (domain account + required groups)
        isActiveDirectoryAgent = false -> Standard mode (local account + no groups)

.NINJAONE CUSTOM FIELDS (read via Ninja-Property-Get)
    isActiveDirectoryAgent : Boolean (true/false).
                             Set automatically by Script 5 (Detect-DomainController.ps1).
    isHyperVHost           : Boolean (true/false). Used for logging context.

.NINJAONE SCRIPT VARIABLES (Text Input / Secure)
    backupDriveLetter            : Single drive letter without colon (e.g., E).
                                   Leave empty for VM guests.
    backupServiceAccount         : Account name. Optional -- defaults to "svc_acronis".
    backupServiceAccountPassword : Required only if account must be created.
                                   Configure as Secure/Password type in NinjaOne.

.NOTES
    Author  : Edson Pintado
    Version : 1.2
    Run As  : Administrator / SYSTEM
    Part of : Acronis Backup Security Framework (Script 4 of 5)
#>

# ============================================================
# INITIALIZATION
# ============================================================

$isADAgentRaw  = Ninja-Property-Get isActiveDirectoryAgent 2>$null
$isADAgent     = ($isADAgentRaw -eq "true")
$isHVHostRaw   = Ninja-Property-Get isHyperVHost 2>$null
$isHVHost      = ($isHVHostRaw -eq "true")

$DriveLetter     = $env:backupDriveLetter
$ServiceAccount  = if ([string]::IsNullOrWhiteSpace($env:backupServiceAccount)) { "svc_acronis" } else { $env:backupServiceAccount.Trim() }
$AccountPassword = $env:backupServiceAccountPassword

$hasDrive = -not [string]::IsNullOrWhiteSpace($DriveLetter)
if ($hasDrive) {
    $DriveLetter = $DriveLetter.Trim().TrimEnd(':').TrimEnd('\').ToUpper()
    $BackupPath  = "$($DriveLetter):\ACB"
}

$MachineClass = if ($isADAgent) {
    "Domain Controller -- Agent for Active Directory"
} elseif ($isHVHost) {
    "Hyper-V Host"
} elseif (-not $hasDrive) {
    "VM Guest (backup drive on Hyper-V host)"
} else {
    "Standard Server / Workstation"
}

$LogFile = "C:\Logs\ACB-Initialize-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    Write-Output $entry
    Add-Content -Path $LogFile -Value $entry
}

if (-not (Test-Path "C:\Logs")) { New-Item -ItemType Directory -Path "C:\Logs" -Force | Out-Null }

Write-Log "======================================================"
Write-Log " Acronis Backup Security Framework -- Script 4 of 5"
Write-Log " Initialize: Full Acronis Backup Protection"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
if ($hasDrive) {
    Write-Log " Drive Letter    : $DriveLetter"
    Write-Log " Backup Path     : $BackupPath"
} else {
    Write-Log " Drive Letter    : NOT SET -- drive steps will be skipped"
}
if ($isADAgent) {
    Write-Log " DC Note         : Agent for Active Directory detected."
    Write-Log "                   svc_acronis MUST be in Domain Admins (Acronis KB 56202)."
    Write-Log "                   NTFS ACL on ACB folder still restricts file access."
}
Write-Log "======================================================"


# ============================================================
# STEP 1 -- VALIDATE OR CREATE SERVICE ACCOUNT
# ============================================================

Write-Log "STEP 1: Validating or creating service account '$ServiceAccount'..."

if ($isADAgent) {
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $account = Get-ADUser -Filter { SamAccountName -eq $ServiceAccount } -Properties Enabled, PasswordNeverExpires -ErrorAction Stop
    } catch {
        $account = $null
        Write-Log "  AD module unavailable. Falling back to local check." "WARN"
        $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue
    }

    if ($null -eq $account) {
        Write-Log "  Domain account '$ServiceAccount' not found. Creating..." "WARN"
        if ([string]::IsNullOrWhiteSpace($AccountPassword)) {
            Write-Log "ERROR: Account does not exist and 'backupServiceAccountPassword' is not set." "ERROR"
            Exit 1
        }
        try {
            $sp = ConvertTo-SecureString -String $AccountPassword -AsPlainText -Force
            New-ADUser -SamAccountName $ServiceAccount -Name $ServiceAccount `
                -DisplayName "Acronis Backup Service Account" `
                -Description "Managed by NinjaOne. Domain Admins required for Agent for AD (Acronis KB 56202)." `
                -AccountPassword $sp -PasswordNeverExpires $true -CannotChangePassword $true `
                -Enabled $true -ErrorAction Stop
            Write-Log "  Domain account '$ServiceAccount' created. Password: not logged."
            $account = Get-ADUser -Filter { SamAccountName -eq $ServiceAccount } -Properties Enabled, PasswordNeverExpires -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to create domain account. Details: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "  Account '$ServiceAccount' found. OK."
    }

    if ($account.PSObject.TypeNames -contains "Microsoft.ActiveDirectory.Management.ADUser") {
        if (-not $account.Enabled) { Enable-ADAccount -Identity $ServiceAccount; Write-Log "  Account enabled." }
        else { Write-Log "  Account is enabled. OK." }
        if (-not $account.PasswordNeverExpires) { Set-ADUser -Identity $ServiceAccount -PasswordNeverExpires $true; Write-Log "  Password expiration disabled." }
        else { Write-Log "  Password expiration already disabled. OK." }
    }

} else {
    $account = Get-LocalUser -Name $ServiceAccount -ErrorAction SilentlyContinue

    if ($null -eq $account) {
        Write-Log "  Account '$ServiceAccount' not found. Creating..." "WARN"
        if ([string]::IsNullOrWhiteSpace($AccountPassword)) {
            Write-Log "ERROR: Account does not exist and 'backupServiceAccountPassword' is not set." "ERROR"
            Exit 1
        }
        try {
            $sp = ConvertTo-SecureString -String $AccountPassword -AsPlainText -Force
            New-LocalUser -Name $ServiceAccount -Password $sp -FullName "Acronis Backup Service Account" `
                -Description "Managed by NinjaOne. Least-privilege backup account." `
                -PasswordNeverExpires -UserMayNotChangePassword -ErrorAction Stop
            Write-Log "  Account '$ServiceAccount' created. Password: not logged."
            $account = Get-LocalUser -Name $ServiceAccount -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to create account. Details: $_" "ERROR"
            Exit 1
        }
    } else {
        Write-Log "  Account '$ServiceAccount' found. OK."
    }

    if (-not $account.Enabled) { Enable-LocalUser -Name $ServiceAccount; Write-Log "  Account enabled." }
    else { Write-Log "  Account is enabled. OK." }
    if ($account.PasswordNeverExpires -eq $false) { Set-LocalUser -Name $ServiceAccount -PasswordNeverExpires $true; Write-Log "  Password expiration disabled." }
    else { Write-Log "  Password expiration already disabled. OK." }
}

Write-Log "STEP 1 COMPLETE."


# ============================================================
# STEP 2 -- MANAGE GROUP MEMBERSHIPS
# ============================================================

Write-Log "STEP 2: Configuring group memberships for '$ServiceAccount'..."

if ($isADAgent) {
    $requiredGroups  = @("Domain Admins", "Administrators", "Backup Operators")
    $forbiddenGroups = @("Power Users","Remote Desktop Users","Remote Management Users",
                         "Network Configuration Operators","Event Log Readers",
                         "Cryptographic Operators","Hyper-V Administrators",
                         "Schema Admins","Enterprise Admins","Group Policy Creator Owners")

    Write-Log "  DC Mode: Ensuring REQUIRED memberships (Acronis KB 56202)..."
    foreach ($g in $requiredGroups) {
        try {
            $m = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if (-not $m) { Add-ADGroupMember -Identity $g -Members $ServiceAccount -ErrorAction Stop; Write-Log "  [ADDED] '$ServiceAccount' added to '$g'." }
            else { Write-Log "  [OK]    '$ServiceAccount' already in '$g'." }
        } catch { Write-Log "  [WARN]  Could not process '$g'. Details: $_" "WARN" }
    }

    Write-Log "  DC Mode: Removing FORBIDDEN memberships..."
    foreach ($g in $forbiddenGroups) {
        try {
            $m = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.SamAccountName -eq $ServiceAccount }
            if ($m) { Remove-ADGroupMember -Identity $g -Members $ServiceAccount -Confirm:$false -ErrorAction Stop; Write-Log "  [FIXED] Removed '$ServiceAccount' from '$g'." }
            else { Write-Log "  [OK]    '$ServiceAccount' not in '$g'." }
        } catch { Write-Log "  [SKIP]  Could not check '$g'. Details: $_" }
    }

} else {
    $privilegedGroups = @("Administrators","Backup Operators","Power Users",
                          "Remote Desktop Users","Remote Management Users",
                          "Network Configuration Operators","Event Log Readers",
                          "Cryptographic Operators","Hyper-V Administrators")

    foreach ($g in $privilegedGroups) {
        if (-not (Get-LocalGroup -Name $g -ErrorAction SilentlyContinue)) { Write-Log "  [SKIP]  '$g' does not exist."; continue }
        try {
            $m = Get-LocalGroupMember -Group $g -ErrorAction Stop | Where-Object { $_.Name -like "*\$ServiceAccount" -or $_.Name -eq $ServiceAccount }
            if ($m) { Remove-LocalGroupMember -Group $g -Member $ServiceAccount -ErrorAction Stop; Write-Log "  [FIXED] Removed '$ServiceAccount' from '$g'." }
            else { Write-Log "  [OK]    '$ServiceAccount' not in '$g'." }
        } catch { Write-Log "  [WARN]  Could not process '$g'. Details: $_" "WARN" }
    }
}

Write-Log "STEP 2 COMPLETE."


# ============================================================
# STEPS 3-8 -- DRIVE HARDENING (SKIPPED FOR VM GUESTS)
# ============================================================

if (-not $hasDrive) {
    Write-Log "STEPS 3-8: SKIPPED -- No backup drive letter provided."
    Write-Log "           This machine is a VM guest. Backup drive resides on the Hyper-V host."
    Write-Log "           Drive hardening was performed on the host via Script 3 or Script 4."
} else {

    # STEP 3 -- VALIDATE DRIVE
    Write-Log "STEP 3: Validating drive '$($DriveLetter):'..."
    if (-not (Test-Path "$($DriveLetter):")) {
        Write-Log "ERROR: Drive '$($DriveLetter):' does not exist or is not accessible." "ERROR"
        Exit 1
    }
    Write-Log "Drive '$($DriveLetter):' found. OK."
    Write-Log "STEP 3 COMPLETE."

    # STEP 4 -- CREATE ACB FOLDER
    Write-Log "STEP 4: Checking for backup folder '$BackupPath'..."
    if (-not (Test-Path $BackupPath)) {
        try { New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null; Write-Log "Folder '$BackupPath' created." }
        catch { Write-Log "ERROR: Failed to create '$BackupPath'. Details: $_" "ERROR"; Exit 1 }
    } else { Write-Log "Folder '$BackupPath' already exists. OK." }
    Write-Log "STEP 4 COMPLETE."

    # STEP 5 -- APPLY NTFS ACL
    Write-Log "STEP 5: Applying least privilege NTFS permissions to '$BackupPath'..."

    function Resolve-IdentityToSID {
        param([string]$IdentityName)
        try {
            $nt = New-Object System.Security.Principal.NTAccount($IdentityName)
            return $nt.Translate([System.Security.Principal.SecurityIdentifier])
        } catch {
            Write-Log "ERROR: Could not resolve identity '$IdentityName'. Details: $_" "ERROR"
            throw
        }
    }

    try {
        $acl = Get-Acl -Path $BackupPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }

        $accountFQN = if ($isADAgent) { "$(( Get-WmiObject Win32_ComputerSystem).Domain)\$ServiceAccount" } else { "$env:COMPUTERNAME\$ServiceAccount" }
        $sidSvc    = Resolve-IdentityToSID $accountFQN
        $sidAdm    = Resolve-IdentityToSID "BUILTIN\Administrators"
        $sidSys    = Resolve-IdentityToSID "NT AUTHORITY\SYSTEM"

        Write-Log "  Identity: $ServiceAccount -> SID $($sidSvc.Value)"
        Write-Log "  Identity: Administrators  -> SID $($sidAdm.Value)"
        Write-Log "  Identity: SYSTEM          -> SID $($sidSys.Value)"

        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSvc, "FullControl",      "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidAdm, "ReadAndExecute",   "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($sidSys, "ReadAndExecute",   "ContainerInherit,ObjectInherit", "None", "Allow")))

        Set-Acl -Path $BackupPath -AclObject $acl
        Write-Log "  NTFS ACL applied: $ServiceAccount Full Control | Admins/SYSTEM Read only | All others No Access."
        if ($isADAgent) {
            Write-Log "  DC Note: Domain Admins membership does NOT grant additional file access."
            Write-Log "           NTFS ACL takes precedence -- only $ServiceAccount can write to $BackupPath."
        }
    } catch {
        Write-Log "ERROR: Failed to apply NTFS ACL. Details: $_" "ERROR"
        Exit 1
    }
    Write-Log "STEP 5 COMPLETE."

    # STEP 6 -- DISABLE AUTORUN
    Write-Log "STEP 6: Disabling AutoRun/AutoPlay on drive '$($DriveLetter):'..."
    try {
        $rp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $rp)) { New-Item -Path $rp -Force | Out-Null }
        Set-ItemProperty -Path $rp -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
        Write-Log "  AutoRun disabled for all drive types."
        $ap = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\$($DriveLetter):"
        if (-not (Test-Path $ap)) { New-Item -Path $ap -Force | Out-Null }
        Set-ItemProperty -Path $ap -Name "(Default)" -Value "MSTakeNoAction" -Force
        Write-Log "  AutoPlay set to 'Take no action' for drive '$($DriveLetter):'."
    } catch { Write-Log "WARNING: Could not fully configure AutoRun/AutoPlay. Details: $_" "WARN" }
    Write-Log "STEP 6 COMPLETE."

    # STEP 7 -- ENABLE AUDIT LOGGING
    Write-Log "STEP 7: Enabling NTFS audit logging on '$BackupPath'..."
    try {
        $ar = auditpol /set /subcategory:"File System" /success:enable /failure:enable 2>&1
        Write-Log "  Audit policy: $ar"
        $acl = Get-Acl -Path $BackupPath
        $rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            "Everyone", "Write,Delete,DeleteSubdirectoriesAndFiles",
            "ContainerInherit,ObjectInherit", "None", "Failure")
        $acl.AddAuditRule($rule)
        Set-Acl -Path $BackupPath -AclObject $acl
        Write-Log "  Audit ACE applied: Failed Write/Delete attempts logged in Security Event Log."
    } catch { Write-Log "WARNING: Could not apply audit ACE. Details: $_" "WARN" }
    Write-Log "STEP 7 COMPLETE."

    # STEP 8 -- VERIFY FINAL ACL STATE
    Write-Log "STEP 8: Verifying final ACL state on '$BackupPath'..."
    (Get-Acl -Path $BackupPath).Access | ForEach-Object {
        Write-Log "  PERMISSION: $($_.IdentityReference) | $($_.FileSystemRights) | $($_.AccessControlType)"
    }
    Write-Log "STEP 8 COMPLETE."
}


# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Log "======================================================"
Write-Log " INITIALIZATION COMPLETE -- FINAL SUMMARY"
Write-Log " Machine         : $env:COMPUTERNAME"
Write-Log " Machine Class   : $MachineClass"
Write-Log " Service Account : $ServiceAccount"
Write-Log " Account Steps   : COMPLETED (Steps 1-2)"
if ($hasDrive) {
    Write-Log " Drive Steps     : COMPLETED (Steps 3-8)"
    Write-Log " Backup Path     : $BackupPath"
    Write-Log " ACL             : $ServiceAccount Full Control | Admins/SYSTEM Read only"
    Write-Log " AutoRun         : Disabled"
    Write-Log " Audit Logging   : Enabled"
} else {
    Write-Log " Drive Steps     : SKIPPED (VM guest -- backup drive is on Hyper-V host)"
}
Write-Log " Log File        : $LogFile"
Write-Log "======================================================"

Write-Output "`nSUCCESS: Acronis backup protection initialized on $env:COMPUTERNAME ($MachineClass). Log: $LogFile"
Exit 0
