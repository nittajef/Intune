##
# Microsoft Windows 10 Security Technical Implementation Guide
# Version: 2, Release: 7 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
##


#
# Gather data used across multiple rule checks
#

$AuditPolicy = @{}
auditpol /get /category:* /r | ConvertFrom-Csv | % { $AuditPolicy[$_.Subcategory] = $_.'Inclusion Setting' }

$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

# Determine the "Domain SID" that the machine is a member of
$id = new-object System.Security.Principal.NTAccount($env:COMPUTERNAME + "$")
$id.Translate([System.Security.Principal.SecurityIdentifier]).toString() -match "(^S-1-5-\d+-\d+-\d+-\d+-)\d+$" | Out-Null
$DomainSID = $Matches[1]

$LocalUsers = Get-LocalUser

$v1507 = "10240"
$v1607 = "14393"
$v1809 = "17763"
$v21H2 = "19044"
$LTSB = @($v1507, $v1607, $v1809, $v21H2)

# Create hash of local security policies (exported in .ini format)
# Ref: Ingest .ini file: https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
$SPFile = [System.Environment]::GetEnvironmentVariable('TEMP','Machine') + "\secpol.cfg"
secedit /export /cfg $SPFile | Out-Null

$SecurityPolicy = @{}  
switch -regex -file $SPFile
{
    "^\[(.+)\]$" # Section
    {
        $section = $matches[1]
        $SecurityPolicy[$section] = @{}
    }
    "(.+?)\s*=\s*(.*)" # Key
    {
        if (!($section))
        {
            $section = "No-Section"
            $SecurityPolicy[$section] = @{}
        }
        $name,$value = $matches[1..2]
        $SecurityPolicy[$section][$name] = $value
    }
}
Remove-Item -Force $SPFile -Confirm:$false



##
# V-220697
# Domain-joined systems must use Windows 10 Enterprise Edition 64-bit version.
#
##
# DISCUSSION: 
# Features such as Credential Guard use virtualization-based security to protect information that could be used
# in credential theft attacks if compromised. A number of system requirements must be met for Credential Guard
# to be configured and enabled properly. Virtualization-based security and Credential Guard are only available
# with Windows 10 Enterprise 64-bit version.
#
##
# CHECK: 
# Verify domain-joined systems are using Windows 10 Enterprise Edition 64-bit version.
#
# For standalone or nondomain-joined systems, this is NA.
#
# Open "Settings".
#
# Select "System", then "About".
#
# If "Edition" is not "Windows 10 Enterprise", this is a finding.
#
# If "System type" is not "64-bit operating system...", this is a finding.
#
##
# FIX: 
# Use Windows 10 Enterprise 64-bit version for domain-joined systems.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220697r857178_rule
# STIG ID: WN10-00-000005
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsArchitecture -eq "64-bit") {
        if ($ComputerInfo.WindowsProductName -eq "Windows 10 Enterprise") {
            $V220697 = $true
        }
    }
} catch {
    $V220697 = $false
}

##
# V-220698
# Windows 10 domain-joined systems must have a Trusted Platform Module (TPM) enabled and ready for use.
#
##
# DISCUSSION: 
# Credential Guard uses virtualization-based security to protect information that could be used in credential
# theft attacks if compromised. A number of system requirements must be met for Credential Guard to be
# configured and enabled properly. Without a TPM enabled and ready for use, Credential Guard keys are stored in
# a less secure method using software.
#
##
# CHECK: 
# Verify domain-joined systems have a TPM enabled and ready for use.
#
# For standalone or nondomain-joined systems, this is NA.
#
# Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Verify the system has a TPM and is ready for use.
# Run "tpm.msc".
# Review the sections in the center pane.
# "Status" must indicate it has been configured with a message such as "The TPM is ready for use" or "The TPM is
# on and ownership has been taken".
# TPM Manufacturer Information - Specific Version = 2.0 or 1.2
#
# If a TPM is not found or is not ready for use, this is a finding.
#
##
# FIX: 
# For standalone or nondomain-joined systems, this is NA.
#
# Virtualization-based security, including Credential Guard, currently cannot be implemented in VDI due to
# specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V
# feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Ensure domain-joined systems have a Trusted Platform Module (TPM) that is configured for use. (Versions 2.0 or
# 1.2 support Credential Guard.)
#
# The TPM must be enabled in the firmware.
#
# Run "tpm.msc" for configuration options in Windows.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220698r857181_rule
# STIG ID: WN10-00-000010
# REFERENCE: 
##
try {
    $tpm = Get-Tpm
    if ($tpm.TpmPresent -and $tpm.TpmReady -and $tpm.TpmEnabled) {
        $V220698 = $true
    } else {
        $V220698 = $false
    }
} catch {
    $V220698 = $false
}

##
# V-220699
# Windows 10 systems must have Unified Extensible Firmware Interface (UEFI) firmware and be configured to run in
# UEFI mode, not Legacy BIOS.
#
##
# DISCUSSION: 
# UEFI provides additional security features in comparison to legacy BIOS firmware, including Secure Boot. UEFI
# is required to support additional security features in Windows 10, including Virtualization Based Security and
# Credential Guard. Systems with UEFI that are operating in Legacy BIOS mode will not support these security
# features.
#
##
# CHECK: 
# For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon
# logoff, this is NA.
#
# Verify the system firmware is configured to run in UEFI mode, not Legacy BIOS.
#
# Run "System Information".
#
# Under "System Summary", if "BIOS Mode" does not display "UEFI", this is a finding.
#
##
# FIX: 
# Configure UEFI firmware to run in UEFI mode, not Legacy BIOS mode.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220699r569187_rule
# STIG ID: WN10-00-000015
# REFERENCE: 
##
try {
    if (bcdedit | Select-String ".*bootmgfw.efi") {
        $V220699 = $true
    } else {
        $V220699 = $false
    }
} catch {
    $V220699 = $false
}

##
# V-220701-NoChk
# Windows 10 must employ automated mechanisms to determine the state of system components with regard to flaw
# remediation using the following frequency: continuously, where ESS is used; 30 days, for any additional
# internal network scans not covered by ESS; and annually, for external scans by Computer Network Defense
# Service Provider (CNDSP).
#
##
# DISCUSSION: 
# An approved tool for continuous network scanning must be installed and configured to run.
#
# Without the use of automated mechanisms to scan for security flaws on a continuous and/or periodic basis, the
# operating system or other system components may remain vulnerable to the exploits presented by undetected
# software flaws.
#
# To support this requirement, the operating system may have an integrated solution incorporating continuous
# scanning using ESS and periodic scanning using other tools, as specified in the requirement.
#
##
# CHECK: 
# Verify DoD-approved ESS software is installed and properly operating. Ask the site ISSM for documentation of
# the ESS software installation and configuration.
#
# If the ISSM is not able to provide a documented configuration for an installed ESS or if the ESS software is
# not properly maintained or used, this is a finding.
#
# Note: Example of documentation can be a copy of the site's CCB approved Software Baseline with version of
# software noted or a memo from the ISSM stating current ESS software and version.
#
##
# FIX: 
# Install DoD-approved ESS software and ensure it is operating continuously.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220701r793197_rule
# STIG ID: WN10-00-000025
# REFERENCE: 
##
$V220701 = $true

##
# V-220702
# Windows 10 information systems must use BitLocker to encrypt all disks to protect the confidentiality and
# integrity of all information at rest.
#
##
# DISCUSSION: 
# If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces
# permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby
# circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even
# when the operating system is not running.
#
##
# CHECK: 
# Verify all Windows 10 information systems (including SIPRNet) employ BitLocker for full disk encryption.
#
# For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon
# logoff, this is NA.
#
# For Azure Virtual Desktop (AVD) implementations with no data at rest, this is NA.
#
# If full disk encryption using BitLocker is not implemented, this is a finding.
#
# Verify BitLocker is turned on for the operating system drive and any fixed data drives.
#
# Open "BitLocker Drive Encryption" from the Control Panel.
#
# If the operating system drive or any fixed data drives have "Turn on BitLocker", this is a finding.
#
# NOTE: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full
# disk encryption and satisfies the pre-boot authentication requirements (WN10-00-000031 and WN10-00-000032).
#
##
# FIX: 
# Enable full disk encryption on all information systems (including SIPRNet) using BitLocker.
#
# BitLocker, included in Windows, can be enabled in the Control Panel under "BitLocker Drive Encryption" as well
# as other management tools.
#
# NOTE: An alternate encryption application may be used in lieu of BitLocker providing it is configured for full
# disk encryption and satisfies the pre-boot authentication requirements (WN10-00-000031 and WN10-00-000032).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220702r859296_rule
# STIG ID: WN10-00-000030
# REFERENCE: 
##
try {
    if (Get-BitLockerVolume | Where-Object { $_.ProtectionStatus -eq "Off" }) {
        $V220702 = $false
    } else {
        $V220702 = $true
    }
} catch {
    $V220702 = $false
}

##
# V-220703
# Windows 10 systems must use a BitLocker PIN for pre-boot authentication.
#
##
# DISCUSSION: 
# If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces
# permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby
# circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even
# when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing
# encrypted drives.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon
# logoff, this is NA.
#
# For Azure Virtual Desktop (AVD) implementations with no data at rest, this is NA.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\FVE\
#
# Value Name: UseAdvancedStartup
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
# If one of the following registry values does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\FVE\
#
# Value Name: UseTPMPIN
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
# Value Name: UseTPMKeyPIN
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
# When BitLocker network unlock is used:
#
# Value Name: UseTPMPIN
# Type: REG_DWORD
# Value: 0x00000002 (2)
#
# Value Name: UseTPMKeyPIN
# Type: REG_DWORD
# Value: 0x00000002 (2)
#
# BitLocker network unlock may be used in conjunction with a BitLocker PIN. Refer to the article at the link
# below for information about network unlock.
#
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# BitLocker Drive Encryption >> Operating System Drives "Require additional authentication at startup" to
# "Enabled" with "Configure TPM Startup PIN:" set to "Require startup PIN with TPM" or with "Configure TPM
# startup key and PIN:" set to "Require startup key and PIN with TPM".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220703r859157_rule
# STIG ID: WN10-00-000031
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseAdvancedStartup -ErrorAction Stop) -eq 1 -and
        (((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMPIN -ErrorAction Stop) -in @(1,2)) -or
        ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name UseTPMKeyPIN -ErrorAction Stop) -in @(1,2)))) {
        $V220703 = $true
    } else {
        $V220703 = $false
    }
} catch {
    $V220703 = $false
}

##
# V-220704
# Windows 10 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.
#
##
# DISCUSSION: 
# If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces
# permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby
# circumventing operating system controls. Encrypting the data ensures that confidentiality is protected even
# when the operating system is not running. Pre-boot authentication prevents unauthorized users from accessing
# encrypted drives. Increasing the PIN length requires a greater number of guesses for an attacker.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# For virtual desktop implementations (VDIs) in which the virtual desktop instance is deleted or refreshed upon
# logoff, this is NA.
#
# For Azure Virtual Desktop (AVD) implementations with no data at rest, this is NA.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\FVE\
#
# Value Name: MinimumPIN
# Type: REG_DWORD
# Value: 0x00000006 (6) or greater
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# BitLocker Drive Encryption >> Operating System Drives "Configure minimum PIN length for startup" to "Enabled"
# with "Minimum characters:" set to "6" or greater.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220704r859297_rule
# STIG ID: WN10-00-000032
# REFERENCE: 
##
try {
    if ($MinimumBLPIN) {
        $pin = $MinimumBLPIN
    } else {
        $pin = 6
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE\" -Name MinimumPIN -ErrorAction Stop) -ge $pin) {
        $V220704 = $true
    } else {
        $V220704 = $false
    }
} catch {
    $V220704 = $false
}

##
# V-220705-NoChk
# The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized
# software programs.
#
##
# DISCUSSION: 
# Utilizing an allowlist provides a configuration management method for allowing the execution of only
# authorized software. Using only authorized software decreases risk by limiting the number of potential
# vulnerabilities.
#
# The organization must identify authorized software programs and only permit execution of authorized software.
# The process used to identify software programs that are authorized to execute on organizational information
# systems is commonly referred to as allowlisting.
#
##
# CHECK: 
# This is applicable to unclassified systems; for other systems, this is Not Applicable.
#
# Verify the operating system employs a deny-all, permit-by-exception policy to allow the execution of
# authorized software programs. This must include packaged apps such as the universal apps installed by default
# on systems.
#
# If an application allowlisting program is not in use on the system, this is a finding.
#
# Configuration of allowlisting applications will vary by the program.
#
# AppLocker is an allowlisting application built into Windows 10 Enterprise. A deny-by-default implementation is
# initiated by enabling any AppLocker rules within a category, only allowing what is specified by defined rules.
#
# If AppLocker is used, perform the following to view the configuration of AppLocker:
# Run "PowerShell".
#
# Execute the following command, substituting [c:\temp\file.xml] with a location and file name appropriate for
# the system:
# Get-AppLockerPolicy -Effective -XML > c:\temp\file.xml
#
# This will produce an xml file with the effective settings that can be viewed in a browser or opened in a
# program such as Excel for review.
#
# Implementation guidance for AppLocker is available at the following link:
#
#
##
# FIX: 
# Configure an application allowlisting program to employ a deny-all, permit-by-exception policy to allow the
# execution of authorized software programs.
#
# Configuration of allowlisting applications will vary by the program. AppLocker is an allowlisting application
# built into Windows 10 Enterprise.
#
# If AppLocker is used, it is configured through group policy in Computer Configuration >> Windows Settings >>
# Security Settings >> Application Control Policies >> AppLocker.
#
# Implementation guidance for AppLocker is available at the following link:
#
#
##
# SEVERITY: CAT II
# RULE ID: SV-220705r890420_rule
# STIG ID: WN10-00-000035
# REFERENCE: 
##
$V220705 = $true

##
# V-220709
# Alternate operating systems must not be permitted on the same system.
#
##
# DISCUSSION: 
# Allowing other operating systems to run on a secure system may allow security to be circumvented.
#
##
# CHECK: 
# Verify the system does not include other operating system installations.
#
# Run "Advanced System Settings".
# Select the "Advanced" tab.
# Click the "Settings" button in the "Startup and Recovery" section.
#
# If the drop-down list box "Default operating system:" shows any operating system other than Windows 10, this
# is a finding.
#
##
# FIX: 
# Ensure Windows 10 is the only operating system on a device.  Remove alternate operating systems.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220709r569187_rule
# STIG ID: WN10-00-000055
# REFERENCE: 
##
try {
    
    #$V220709 = $true
} catch {
    $V220709 = $false
}



##
# V-220710-NoChk
# Non system-created file shares on a system must limit access to groups that require it.
#
##
# DISCUSSION: 
# Shares which provide network access, should not typically exist on a workstation except for system-created
# administrative shares, and could potentially expose sensitive information.  If a share is necessary, share
# permissions, as well as NTFS permissions, must be reconfigured to give the minimum access to those accounts
# that require it.
#
##
# CHECK: 
# Non system-created shares should not typically exist on workstations.
#
# If only system-created shares exist on the system this is NA.
#
# Run "Computer Management".
# Navigate to System Tools >> Shared Folders >> Shares.
#
# If the only shares listed are "ADMIN$", "C$" and "IPC$", this is NA.
# (Selecting Properties for system-created shares will display a message that it has been shared for
# administrative purposes.)
#
# Right click any non-system-created shares.
# Select "Properties".
# Select the "Share Permissions" tab.
#
# Verify the necessity of any shares found.
# If the file shares have not been reconfigured to restrict permissions to the specific groups or accounts that
# require access, this is a finding.
#
# Select the "Security" tab.
#
# If the NTFS permissions have not been reconfigured to restrict permissions to the specific groups or accounts
# that require access, this is a finding.
#
##
# FIX: 
# If a non system-created share is required on a system, configure the share and NTFS permissions to limit
# access to the specific groups or accounts that require it.
#
# Remove any unnecessary non-system created shares.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220710r569187_rule
# STIG ID: WN10-00-000060
# REFERENCE: 
##
$V220710 = $true

##
# V-220713
# Only accounts responsible for the backup operations must be members of the Backup Operators group.
#
##
# DISCUSSION: 
# Backup Operators are able to read and write to any file in the system, regardless of the rights assigned to
# it.  Backup and restore rights permit users to circumvent the file access restrictions present on NTFS disk
# drives for backup and restore purposes.  Members of the Backup Operators group must have separate logon
# accounts for performing backup duties.
#
##
# CHECK: 
# Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Groups.
# Review the members of the Backup Operators group.
#
# If the group contains no accounts, this is not a finding.
#
# If the group contains any accounts, the accounts must be specifically for backup functions.
#
# If the group contains any standard user accounts used for performing normal user tasks, this is a finding.
#
##
# FIX: 
# Create separate accounts for backup operations for users with this privilege.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220713r569187_rule
# STIG ID: WN10-00-000075
# REFERENCE: 
##
try {
    $members = Get-LocalGroupMember -Group "Backup Operators"
    $V220713 = $true
    foreach ($member in $members) {
        if ($member.Name -notin $BackupOperators) {
            $V220713 = $false
        }
    }
} catch {
    $V220713 = $false
}

##
# V-220714
# Only authorized user accounts must be allowed to create or run virtual machines on Windows 10 systems.
#
##
# DISCUSSION: 
# Allowing other operating systems to run on a secure system may allow users to circumvent security. For
# Hyper-V, preventing unauthorized users from being assigned to the Hyper-V Administrators group will prevent
# them from accessing or creating virtual machines on the system. The Hyper-V Hypervisor is used by
# Virtualization Based Security features such as Credential Guard on Windows 10; however, it is not the full
# Hyper-V installation.
#
##
# CHECK: 
# If a hosted hypervisor (Hyper-V, VMware Workstation, etc.) is installed on the system, verify only authorized
# user accounts are allowed to run virtual machines.
#
# For Hyper-V, Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Groups.
# Double click on "Hyper-V Administrators".
#
# If any unauthorized groups or user accounts are listed in "Members:", this is a finding.
#
# For hosted hypervisors other than Hyper-V, verify only authorized user accounts have access to run the virtual
# machines. Restrictions may be enforced by access to the physical system, software restriction policies, or
# access restrictions built in to the application.
#
# If any unauthorized groups or user accounts have access to create or run virtual machines, this is a finding.
#
# All users authorized to create or run virtual machines must be documented with the ISSM/ISSO. Accounts nested
# within group accounts must be documented as individual accounts and not the group accounts.
#
##
# FIX: 
# For Hyper-V, remove any unauthorized groups or user accounts from the "Hyper-V Administrators" group.
#
# For hosted hypervisors other than Hyper-V, restrict access to create or run virtual machines to authorized
# user accounts only.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220714r569187_rule
# STIG ID: WN10-00-000080
# REFERENCE: 
##
try {
    $members = Get-LocalGroupMember -Group "Hyper-V Administrators"
    $V220714 = $true
    foreach ($member in $members) {
        if ($member.Name -notin $HyperVAdministrators) {
            $V220714 = $false
        }
    }
} catch {
    $V220714 = $false
}

##
# V-220716
# Accounts must be configured to require password expiration.
#
##
# DISCUSSION: 
# Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.
#
##
# CHECK: 
# Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Users.
# Double click each active account.
#
# If "Password never expires" is selected for any account, this is a finding.
#
##
# FIX: 
# Configure all passwords to expire.
# Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Users.
# Double click each active account.
# Ensure "Password never expires" is not checked on all active accounts.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220716r569187_rule
# STIG ID: WN10-00-000090
# REFERENCE: 
##
try {
    $V220716 = $true
    foreach ($user in $LocalUsers) {
        if ($user.Enabled -eq $true -and $user.PasswordExpires -eq '') {
             $V220716 = $false
        }
    }
} catch {
    $V220716 = $false
}

##
# V-220717
# Permissions for system files and directories must conform to minimum requirements.
#
##
# DISCUSSION: 
# Changing the system's file and directory permissions allows the possibility of unauthorized and anonymous
# modification to the operating system and installed applications.
#
##
# CHECK: 
# The default file system permissions are adequate when the Security Option "Network access: Let Everyone
# permissions apply to anonymous users" is set to "Disabled" (WN10-SO-000160).
#
# If the default file system permissions are maintained and the referenced option is set to "Disabled", this is
# not a finding.
#
# Verify the default permissions for the sample directories below. Non-privileged groups such as Users or
# Authenticated Users must not have greater than Read & execute permissions except where noted as defaults.
# (Individual accounts must not be used to assign permissions.)
#
# Viewing in File Explorer:
# Select the "Security" tab, and the "Advanced" button.
#
# C:\
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# Administrators - Full control - This folder, subfolders and files
# SYSTEM - Full control - This folder, subfolders and files
# Users - Read & execute - This folder, subfolders and files
# Authenticated Users - Modify - Subfolders and files only
# Authenticated Users - Create folders / append data - This folder only
#
# \Program Files
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# TrustedInstaller - Full control - This folder and subfolders
# SYSTEM - Modify - This folder only
# SYSTEM - Full control - Subfolders and files only
# Administrators - Modify - This folder only
# Administrators - Full control - Subfolders and files only
# Users - Read & execute - This folder, subfolders and files
# CREATOR OWNER - Full control - Subfolders and files only
# ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
# ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
#
# \Windows
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# TrustedInstaller - Full control - This folder and subfolders
# SYSTEM - Modify - This folder only
# SYSTEM - Full control - Subfolders and files only
# Administrators - Modify - This folder only
# Administrators - Full control - Subfolders and files only
# Users - Read & execute - This folder, subfolders and files
# CREATOR OWNER - Full control - Subfolders and files only
# ALL APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
# ALL RESTRICTED APPLICATION PACKAGES - Read & execute - This folder, subfolders and files
#
# Alternately use icacls.
#
# Run "CMD" as administrator.
# Enter "icacls" followed by the directory.
#
# icacls c:\
# icacls "c:\program files"
# icacls c:\windows
#
# The following results will be displayed as each is entered:
#
# c:\
# BUILTIN\Administrators:(OI)(CI)(F)
# NT AUTHORITY\SYSTEM:(OI)(CI)(F)
# BUILTIN\Users:(OI)(CI)(RX)
# NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
# NT AUTHORITY\Authenticated Users:(AD)
# Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
# Successfully processed 1 files; Failed processing 0 files
#
# c:\program files 
# NT SERVICE\TrustedInstaller:(F)
# NT SERVICE\TrustedInstaller:(CI)(IO)(F)
# NT AUTHORITY\SYSTEM:(M)
# NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
# BUILTIN\Administrators:(M)
# BUILTIN\Administrators:(OI)(CI)(IO)(F)
# BUILTIN\Users:(RX)
# BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
# CREATOR OWNER:(OI)(CI)(IO)(F)
# APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
# APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
# APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
# APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
# Successfully processed 1 files; Failed processing 0 files
#
# c:\windows
# NT SERVICE\TrustedInstaller:(F)
# NT SERVICE\TrustedInstaller:(CI)(IO)(F)
# NT AUTHORITY\SYSTEM:(M)
# NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
# BUILTIN\Administrators:(M)
# BUILTIN\Administrators:(OI)(CI)(IO)(F)
# BUILTIN\Users:(RX)
# BUILTIN\Users:(OI)(CI)(IO)(GR,GE)
# CREATOR OWNER:(OI)(CI)(IO)(F)
# APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(RX)
# APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
# APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(RX)
# APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(OI)(CI)(IO)(GR,GE)
# Successfully processed 1 files; Failed processing 0 files
#
##
# FIX: 
# Maintain the default file system permissions and configure the Security Option: "Network access: Let everyone
# permissions apply to anonymous users" to "Disabled" (WN10-SO-000160).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220717r851965_rule
# STIG ID: WN10-00-000095
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name EveryoneIncludesAnonymous -ErrorAction Stop) -eq 0) {
        $V220717 = $true

        $acl = Get-Acl -Path "C:\"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "None") {
                # Okay as default permissions
            } elseif ($entry.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-536805376" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                # Okay as default permissions
            } elseif ($entry.IdentityReference.Value -eq "NT AUTHORITY\Authenticated Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "AppendData" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                # Okay as default permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }

        $acl = Get-Acl -Path "\Program Files"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "None" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions  
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "Modify, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "CREATOR OWNER") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }
    
        $acl = Get-Acl -Path "\Windows"
        foreach ($entry in $acl.Access) {
            if ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                $entry.IsInherited -eq "False" -and
                $entry.AccessControlType -eq "Allow" -and
                $entry.FileSystemRights -eq "FullControl" -and
                $entry.InheritanceFlags -eq "None" -and
                $entry.PropagationFlags -eq "None") {
                # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "NT SERVICE\TrustedInstaller" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions  
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "Modify, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -in @("NT AUTHORITY\SYSTEM", "BUILTIN\Administrators", "CREATOR OWNER") -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "268435456" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default permissions        
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Users" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "-1610612736" -and
                      $entry.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
                      $entry.PropagationFlags -eq "InheritOnly") {
                      # Okay as default special permissions
            } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES" -and
                      $entry.IsInherited -eq "False" -and
                      $entry.AccessControlType -eq "Allow" -and
                      $entry.FileSystemRights -eq "ReadAndExecute, Synchronize" -and
                      $entry.InheritanceFlags -eq "None" -and
                      $entry.PropagationFlags -eq "None") {
                      # Okay as default special permissions
            } elseif ($AllowAppCapabilitySIDs -eq $true -and
                      $entry.IdentityReference.Value -like "S-1-15-3-*") {
                # Allow as an app capability SID
            } else {
                $V220717 = $false
            }
        }
    } else {
        $V220717 = $false
    }
} catch {
    $V220717 = $false
}

##
# V-220719
# Simple Network Management Protocol (SNMP) must not be installed on the system.
#
##
# DISCUSSION: 
# Some protocols and services do not support required security features, such as encrypting passwords or
# traffic.
#
##
# CHECK: 
# "SNMP" is not installed by default.  Verify it has not been installed.
#
# Navigate to the Windows\System32 directory.
#
# If the "SNMP" application exists, this is a finding.
#
##
# FIX: 
# Uninstall "Simple Network Management Protocol (SNMP)" from the system.
#
# Run "Programs and Features".
# Select "Turn Windows Features on or off".
# De-select "Simple Network Management Protocol (SNMP)".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220719r569187_rule
# STIG ID: WN10-00-000105
# REFERENCE: 
##
try {
    if (Get-Service -Name snmp -or Test-Path -Path "C:\Windows\System32\snmp.exe") {
        $V220719 = $false
    } else {
        $V220719 = $true
    }
} catch {
    $V220719 = $false
}

##
# V-220720
# Simple TCP/IP Services must not be installed on the system.
#
##
# DISCUSSION: 
# Some protocols and services do not support required security features, such as encrypting passwords or
# traffic.
#
##
# CHECK: 
# "Simple TCP/IP Services" is not installed by default.  Verify it has not been installed.
#
# Run "Services.msc".
#
# If "Simple TCP/IP Services" is listed, this is a finding.
#
##
# FIX: 
# Uninstall "Simple TCPIP Services (i.e. echo, daytime etc)" from the system.
#
# Run "Programs and Features".
# Select "Turn Windows Features on or off".
# De-select "Simple TCPIP Services (i.e. echo, daytime etc)".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220720r569187_rule
# STIG ID: WN10-00-000110
# REFERENCE: 
##
try {
    if (Get-Service -Name simptcp) {
        $V220720 = $false
    } else {
        $V220720 = $true
    }
} catch {
    $V220720 = $false
}

##
# V-220721
# The Telnet Client must not be installed on the system.
#
##
# DISCUSSION: 
# Some protocols and services do not support required security features, such as encrypting passwords or
# traffic.
#
##
# CHECK: 
# The "Telnet Client" is not installed by default.  Verify it has not been installed.
#
# Navigate to the Windows\System32 directory.
#
# If the "telnet" application exists, this is a finding.
#
##
# FIX: 
# Uninstall "Telnet Client" from the system.
#
# Run "Programs and Features".
# Select "Turn Windows Features on or off".
#
# De-select "Telnet Client".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220721r569187_rule
# STIG ID: WN10-00-000115
# REFERENCE: 
##
try {
    if (Test-Path -Path "C:\Windows\System32\telnet.exe") {
        $V220721 = $false
    } else {
        $V220721 = $true
    }
} catch {
    $V220721 = $false
}

##
# V-220722
# The TFTP Client must not be installed on the system.
#
##
# DISCUSSION: 
# Some protocols and services do not support required security features, such as encrypting passwords or
# traffic.
#
##
# CHECK: 
# The "TFTP Client" is not installed by default.  Verify it has not been installed.
#
# Navigate to the Windows\System32 directory.
#
# If the "TFTP" application exists, this is a finding.
#
##
# FIX: 
# Uninstall "TFTP Client" from the system.
#
# Run "Programs and Features".
# Select "Turn Windows Features on or off".
#
# De-select "TFTP Client".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220722r569187_rule
# STIG ID: WN10-00-000120
# REFERENCE: 
##
try {
    if (Test-Path -Path "C:\Windows\System32\tftp.exe") {
        $V220722 = $false
    } else {
        $V220722 = $true
    }
} catch {
    $V220722 = $false
}

##
# V-220723
# Software certificate installation files must be removed from Windows 10.
#
##
# DISCUSSION: 
# Use of software certificates and their accompanying installation files for end users to access resources is
# less secure than the use of hardware-based certificates.
#
##
# CHECK: 
# Search all drives for *.p12 and *.pfx files.
#
# If any files with these extensions exist, this is a finding.
#
# This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g.,
# Oracle Wallet Manager) or Adobe PreFlight certificate files. Some applications create files with extensions of
# .p12 that are not certificate installation files. Removal of non-certificate installation files from systems
# is not required. These must be documented with the ISSO.
#
##
# FIX: 
# Remove any certificate installation files (*.p12 and *.pfx) found on a system.
#
# Note: This does not apply to server-based applications that have a requirement for .p12 certificate files
# (e.g., Oracle Wallet Manager) or Adobe PreFlight certificate files.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220723r569187_rule
# STIG ID: WN10-00-000130
# REFERENCE: 
##
try {
    $drives = Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' -and $_.DriveLetter } | Select-Object -Expand DriveLetter
    $V220723 = $true
    foreach ($drive in $drives) {
        $drive = $drive + ":\"
        if (Get-Childitem -Path $drive -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '.+\.(pfx|p12)$' } | Select-Object -First 1) {
            $V220723 = $false
        }
    }
} catch {
    $V220723 = $false
}

##
# V-220724
# A host-based firewall must be installed and enabled on the system.
#
##
# DISCUSSION: 
# A firewall provides a line of defense against attack, allowing or blocking inbound and outbound connections
# based on a set of rules.
#
##
# CHECK: 
# Determine if a host-based firewall is installed and enabled on the system.  If a host-based firewall is not
# installed and enabled on the system, this is a finding.
#
# The configuration requirements will be determined by the applicable firewall STIG.
#
##
# FIX: 
# Install and enable a host-based firewall on the system.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220724r569187_rule
# STIG ID: WN10-00-000135
# REFERENCE: 
##
try {
    
    #$V220724 = $true
} catch {
    $V220724 = $false
}



##
# V-220725-NoChk
# Inbound exceptions to the firewall on Windows 10 domain workstations must only allow authorized remote
# management hosts.
#
##
# DISCUSSION: 
# Allowing inbound access to domain workstations from other systems may allow lateral movement across systems if
# credentials are compromised.  Limiting inbound connections only from authorized remote management systems will
# help limit this exposure.
#
##
# CHECK: 
# Verify firewall exceptions to inbound connections on domain workstations include only authorized remote
# management hosts.
#
# If allowed inbound exceptions are not limited to authorized remote management hosts, this is a finding.
#
# Review inbound firewall exceptions.
# Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced
# Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right
# pane)
#
# For any inbound rules that allow connections view the Scope for Remote IP address. This may be defined as an
# IP address, subnet, or range. The rule must apply to all firewall profiles.
#
# If a third-party firewall is used, ensure comparable settings are in place.
#
##
# FIX: 
# Configure firewall exceptions to inbound connections on domain workstations to include only authorized remote
# management hosts.
#
# Configure only inbound connection exceptions for authorized remote management hosts.
# Computer Configuration >> Windows Settings >> Security Settings >> Windows Defender Firewall with Advanced
# Security >> Windows Defender Firewall with Advanced Security >> Inbound Rules (this link will be in the right
# pane)
#
# For any inbound rules that allow connections, configure the Scope for Remote IP address to those of authorized
# remote management hosts. This may be defined as an IP address, subnet or range. Apply the rule to all firewall
# profiles.
#
# If a third-party firewall is used, configure inbound exceptions to only include authorized remote management
# hosts.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220725r569187_rule
# STIG ID: WN10-00-000140
# REFERENCE: 
##
$V220725 = $true

##
# V-220728
# The Windows PowerShell 2.0 feature must be disabled on the system.
#
##
# DISCUSSION: 
# Windows PowerShell 5.0 added advanced logging features which can provide additional detail when malware has
# been run on a system.  Disabling the Windows PowerShell 2.0 mitigates against a downgrade attack that evades
# the Windows PowerShell 5.0 script block logging feature.
#
##
# CHECK: 
# Run "Windows PowerShell" with elevated privileges (run as administrator).
#
# Enter the following:
# Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2*
#
# If either of the following have a "State" of "Enabled", this is a finding.
#
# FeatureName : MicrosoftWindowsPowerShellV2
# State : Enabled
# FeatureName : MicrosoftWindowsPowerShellV2Root
# State : Enabled
#
# Alternately:
# Search for "Features".
#
# Select "Turn Windows features on or off".
#
# If "Windows PowerShell 2.0" (whether the subcategory of "Windows PowerShell 2.0 Engine" is selected or not) is
# selected, this is a finding.
#
##
# FIX: 
# Disable "Windows PowerShell 2.0" on the system.
#
# Run "Windows PowerShell" with elevated privileges (run as administrator).
# Enter the following:
# Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
#
# This command should disable both "MicrosoftWindowsPowerShellV2Root" and "MicrosoftWindowsPowerShellV2" which
# correspond to "Windows PowerShell 2.0" and "Windows PowerShell 2.0 Engine" respectively in "Turn Windows
# features on or off".
#
# Alternately:
# Search for "Features".
# Select "Turn Windows features on or off".
# De-select "Windows PowerShell 2.0".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220728r569187_rule
# STIG ID: WN10-00-000155
# REFERENCE: 
##
try {
    $V220728 = $true
    if ((Get-WindowsOptionalFeature -Online | Where FeatureName -like *PowerShellv2* | Select-Object -ExpandProperty State) -contains "Enabled") {
        $V220728 = $false
    }
} catch {
    $V220728 = $false
}

##
# V-220729
# The Server Message Block (SMB) v1 protocol must be disabled on the system.
#
##
# DISCUSSION: 
# SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a
# number of attacks such as collision and preimage attacks as well as not being FIPS compliant.
#
# Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that
# only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however
# Windows Server 2003 is no longer a supported operating system. Some older Network Attached Storage (NAS)
# devices may only support SMBv1.
#
##
# CHECK: 
# Different methods are available to disable SMBv1 on Windows 10.  This is the preferred method, however if
# V-220730 and V-220731 are configured, this is NA.
#
# Run "Windows PowerShell" with elevated privileges (run as administrator).
#
# Enter the following:
# Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol
#
# If "State : Enabled" is returned, this is a finding.
#
# Alternately:
# Search for "Features".
#
# Select "Turn Windows features on or off".
#
# If "SMB 1.0/CIFS File Sharing Support" is selected, this is a finding.
#
##
# FIX: 
# Disable the SMBv1 protocol.
#
# Run "Windows PowerShell" with elevated privileges (run as administrator).
#
# Enter the following:
# Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
#
# Alternately:
# Search for "Features".
#
# Select "Turn Windows features on or off".
#
# De-select "SMB 1.0/CIFS File Sharing Support".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220729r793187_rule
# STIG ID: WN10-00-000160
# REFERENCE: 
##
try {
    $V220729 = $true
    if ((Get-WindowsOptionalFeature -Online | Where FeatureName -eq SMB1Protocol | Select-Object -ExpandProperty State) -contains "Enabled") {
        $V220729 = $false
    }
} catch {
    $V220729 = $false
}

##
# V-220730
# The Server Message Block (SMB) v1 protocol must be disabled on the SMB server.
#
##
# DISCUSSION: 
# SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a
# number of attacks such as collision and preimage attacks as well as not being FIPS compliant.
#
# Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that
# only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however
# Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only
# support SMBv1.
#
##
# CHECK: 
# Different methods are available to disable SMBv1 on Windows 10, if V-220729 is configured, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\
#
# Value Name: SMB1
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Configure SMBv1 Server" to "Disabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
# "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.   
#
# The system must be restarted for the change to take effect.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220730r793189_rule
# STIG ID: WN10-00-000165
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\" -Name SMB1 -ErrorAction Stop) -eq 0) {
        $V220730 = $true
    } else {
        $V220730 = $false
    }
} catch {
    $V220730 = $false
}


##
# V-220731
# The Server Message Block (SMB) v1 protocol must be disabled on the SMB client.
#
##
# DISCUSSION: 
# SMBv1 is a legacy protocol that uses the MD5 algorithm as part of SMB. MD5 is known to be vulnerable to a
# number of attacks such as collision and preimage attacks as well as not being FIPS compliant.
#
# Disabling SMBv1 support may prevent access to file or print sharing resources with systems or devices that
# only support SMBv1. File shares and print services hosted on Windows Server 2003 are an example, however
# Windows Server 2003 is no longer a supported operating system. Some older network attached devices may only
# support SMBv1.
#
##
# CHECK: 
# Different methods are available to disable SMBv1 on Windows 10, if V-220729 is configured, this is NA.
#
# If the following registry value is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\mrxsmb10\
#
# Value Name: Start
#
# Type: REG_DWORD
# Value: 0x00000004 (4)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Configure SMBv1 client driver" to "Enabled" with "Disable driver (recommended)" selected for "Configure
# MrxSmb10 driver".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
# "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.   
#
# The system must be restarted for the changes to take effect. 
#
##
# SEVERITY: CAT II
# RULE ID: SV-220731r793191_rule
# STIG ID: WN10-00-000170
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10\" -Name Start -ErrorAction Stop) -eq 4) {
        $V220731 = $true
    } else {
        $V220731 = $false
    }
} catch {
    $V220731 = $false
}


##
# V-220732
# The Secondary Logon service must be disabled on Windows 10.
#
##
# DISCUSSION: 
# The Secondary Logon service provides a means for entering alternate credentials, typically used to run
# commands with elevated privileges.  Using privileged credentials in a standard user session can expose those
# credentials to theft.
#
##
# CHECK: 
# Run "Services.msc".
#
# Locate the "Secondary Logon" service.
#
# If the "Startup Type" is not "Disabled" or the "Status" is "Running", this is a finding.
#
##
# FIX: 
# Configure the "Secondary Logon" service "Startup Type" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220732r569187_rule
# STIG ID: WN10-00-000175
# REFERENCE: 
##
try {
    $V220732
    $svc = Get-Service -Name "seclogon" | Select-Object Status,StartType
    if ($svc.StartType -ne "Disabled" -or $svc.Status -eq "Running") {
        $V220732 = $false
    }
} catch {
    $V220732 = $false
}

##
# V-220733-NoChk
# Orphaned security identifiers (SIDs) must be removed from user rights on Windows 10.
#
##
# DISCUSSION: 
# Accounts or groups given rights on a system may show up as unresolved SIDs for various reasons including
# deletion of the accounts or groups.  If the account or group objects are reanimated, there is a potential they
# may still have rights no longer intended.  Valid domain accounts or groups may also show up as unresolved SIDs
# if a connection to the domain cannot be established for some reason.
#
##
# CHECK: 
# Review the effective User Rights setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# Review each User Right listed for any unresolved SIDs to determine whether they are valid, such as due to
# being temporarily disconnected from the domain. (Unresolved SIDs have the format of "*S-1-...".)
#
# If any unresolved SIDs exist and are not for currently valid accounts or groups, this is a finding.
#
##
# FIX: 
# Remove any unresolved SIDs found in User Rights assignments and determined to not be for currently valid
# accounts or groups by removing the accounts or groups from the appropriate group policy.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220733r569187_rule
# STIG ID: WN10-00-000190
# REFERENCE: 
##
$V220733 = $true

##
# V-220734-NoChk
# Bluetooth must be turned off unless approved by the organization.
#
##
# DISCUSSION: 
# If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device
# is paired with a system, there is potential for sensitive information to be compromised.
#
##
# CHECK: 
# This is NA if the system does not have Bluetooth.
#
# Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.
#
# Approval must be documented with the ISSO.
#
##
# FIX: 
# Turn off Bluetooth radios not organizationally approved. Establish an organizational policy for the use of
# Bluetooth.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220734r569187_rule
# STIG ID: WN10-00-000210
# REFERENCE: 
##
$V220734 = $true

##
# V-220735-NoChk
# Bluetooth must be turned off when not in use.
#
##
# DISCUSSION: 
# If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device
# is paired with a system, there is potential for sensitive information to be compromised.
#
##
# CHECK: 
# This is NA if the system does not have Bluetooth.
#
# Verify the organization has a policy to turn off Bluetooth when not in use and personnel are trained. If it
# does not, this is a finding.
#
##
# FIX: 
# Turn off Bluetooth radios when not in use. Establish an organizational policy for the use of Bluetooth to
# include training of personnel.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220735r569187_rule
# STIG ID: WN10-00-000220
# REFERENCE: 
##
$V220735 = $true

##
# V-220736-NoChk
# The system must notify the user when a Bluetooth device attempts to connect.
#
##
# DISCUSSION: 
# If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device
# is paired with a system, there is potential for sensitive information to be compromised
#
##
# CHECK: 
# This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.
#
# Search for "Bluetooth".
# View Bluetooth Settings.
# Select "More Bluetooth Options"
# If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.
#
##
# FIX: 
# Configure Bluetooth to notify users if devices attempt to connect.
# View Bluetooth Settings.
# Ensure "Alert me when a new Bluetooth device wants to connect" is checked.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220736r569187_rule
# STIG ID: WN10-00-000230
# REFERENCE: 
##
$V220736 = $true

##
# V-220738-NoChk
# Windows 10 nonpersistent VM sessions must not exceed 24 hours. 
#
##
# DISCUSSION: 
# For virtual desktop implementations (VDIs) where the virtual desktop instance is deleted or refreshed upon
# logoff, the organization should enforce that sessions be terminated within 24 hours. This would ensure any
# data stored on the VM that is not encrypted or covered by Credential Guard is deleted.
#
##
# CHECK: 
# Ensure there is a documented policy or procedure in place that nonpersistent VM sessions do not exceed 24
# hours. If the system is NOT a nonpersistent VM, this is Not Applicable.
#
# If no such documented policy or procedure is in place, this is a finding.
#
##
# FIX: 
# Set nonpersistent VM sessions to not exceed 24 hours.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220738r890426_rule
# STIG ID: WN10-00-000250
# REFERENCE: 
##
$V220738 = $true

##
# V-220739
# Windows 10 account lockout duration must be configured to 15 minutes or greater.
#
##
# DISCUSSION: 
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.   This
# parameter specifies the amount of time that an account will remain locked after the specified number of failed
# logon attempts.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Account Lockout Policy.
#
# If the "Account lockout duration" is less than "15" minutes (excluding "0"), this is a finding.
#
# Configuring this to "0", requiring an administrator to unlock the account, is more restrictive and is not a
# finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Account Lockout Policy >> "Account lockout duration" to "15" minutes or greater.
#
# A value of "0" is also acceptable, requiring an administrator to unlock the account.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220739r851968_rule
# STIG ID: WN10-AC-000005
# REFERENCE: 
##
try {
    if ($LockoutDuration) {
        $lock = $LockoutDuration
    } else {
        $lock = 14
    }
    if ($lock -eq 0) {
        if ($SecurityPolicy.'System Access'.LockoutDuration -eq 0) {
            $V220739 = $true
        }
    } elseif ($SecurityPolicy.'System Access'.LockoutDuration -ne 1..$lock) {
            $V220739 = $true
    } else {
        $V220739 = $false
    }
} catch {
    $V220739 = $false
}

##
# V-220740
# The number of allowed bad logon attempts must be configured to 3 or less.
#
##
# DISCUSSION: 
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.  The higher
# this value is, the less effective the account lockout feature will be in protecting the local system.  The
# number of bad logon attempts must be reasonably small to minimize the possibility of a successful password
# attack, while allowing for honest errors made during a normal user logon.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Account Lockout Policy.
#
# If the "Account lockout threshold" is "0" or more than "3" attempts, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Account Lockout Policy >> "Account lockout threshold" to "3" or less invalid logon attempts
# (excluding "0" which is unacceptable).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220740r569187_rule
# STIG ID: WN10-AC-000010
# REFERENCE: 
##
try {
    if ($LockoutThreshold) {
        $thresh = $LockoutThreshold
    } else {
        $thresh = 3
    }
    if ($SecurityPolicy.'System Access'.LockoutBadCount -eq 1..$thresh) {
        $V220740 = $true
    } else {
        $V220740 = $false
    }
} catch {
    $V220740 = $false
}

##
# V-220741
# The period of time before the bad logon counter is reset must be configured to 15 minutes.
#
##
# DISCUSSION: 
# The account lockout feature, when enabled, prevents brute-force password attacks on the system.  This
# parameter specifies the period of time that must pass after failed logon attempts before the counter is reset
# to 0.  The smaller this value is, the less effective the account lockout feature will be in protecting the
# local system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Account Lockout Policy.
#
# If the "Reset account lockout counter after" value is less than "15" minutes, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Account Lockout Policy >> "Reset account lockout counter after" to "15" minutes.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220741r851969_rule
# STIG ID: WN10-AC-000015
# REFERENCE: 
##
try {
    if ($ResetCounter) {
        $reset = $ResetCounter
    } else {
        $reset = 15
    }
    if ($SecurityPolicy.'System Access'.ResetLockoutCount -ge $reset) {
        $V220741 = $true
    } else {
        $V220741 = $false
    }
} catch {
    $V220741 = $false
}

##
# V-220742
# The password history must be configured to 24 passwords remembered.
#
##
# DISCUSSION: 
# A system is more vulnerable to unauthorized access when system users recycle the same password several times
# without being required to change a password to a unique password on a regularly scheduled basis.  This enables
# users to effectively negate the purpose of mandating periodic password changes.  The default value is 24 for
# Windows domain systems.  DoD has decided this is the appropriate value for all Windows systems.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for "Enforce password history" is less than "24" passwords remembered, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Enforce password history" to "24" passwords remembered.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220742r569187_rule
# STIG ID: WN10-AC-000020
# REFERENCE: 
##
try {
    if ($PWHistory) {
        $hist = $PWHistory
    } else {
        $hist = 24
    }
    if ($SecurityPolicy.'System Access'.PasswordHistorySize -ge $hist) {
        $V220742 = $true
    } else {
        $V220742 = $false
    }
} catch {
    $V220742 = $false
}

##
# V-220743
# The maximum password age must be configured to 60 days or less.
#
##
# DISCUSSION: 
# The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the
# passwords.   Scheduled changing of passwords hinders the ability of unauthorized system users to crack
# passwords and gain access to a system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for the "Maximum password age" is greater than "60" days, this is a finding.  If the value is set
# to "0" (never expires), this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Maximum Password Age" to "60" days or less (excluding "0" which is
# unacceptable).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220743r569187_rule
# STIG ID: WN10-AC-000025
# REFERENCE: 
##
try {
    if ($MaxPwAge) {
        $age = $MaxPwAge
    } else {
        $age = 60
    }
    if ($SecurityPolicy.'System Access'.MaximumPasswordAge -eq 1..$age) {
        $V220743 = $true
    } else {
        $V220743 = $false
    }
} catch {
    $V220743 = $false
}

##
# V-220744
# The minimum password age must be configured to at least 1 day.
#
##
# DISCUSSION: 
# Permitting passwords to be changed in immediate succession within the same day allows users to cycle passwords
# through their history database.  This enables users to effectively negate the purpose of mandating periodic
# password changes.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for the "Minimum password age" is less than "1" day, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Minimum Password Age" to at least "1" day.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220744r569187_rule
# STIG ID: WN10-AC-000030
# REFERENCE: 
##
try {
    if ($MinPwAge) {
        $age = $MinPwAge
    } else {
        $age = 1
    }
    if ($SecurityPolicy.'System Access'.MinimumPasswordAge -le $age) {
        $V220744 = $true
    } else {
        $V220744 = $false
    }
} catch {
    $V220744 = $false
}

##
# V-220745
# Passwords must, at a minimum, be 14 characters.
#
##
# DISCUSSION: 
# Information systems not protected with strong password schemes (including passwords of minimum length) provide
# the opportunity for anyone to crack the password, thus gaining access to the system and compromising the
# device, information, or the local network.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for the "Minimum password length," is less than "14" characters, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Minimum password length" to "14" characters.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220745r569187_rule
# STIG ID: WN10-AC-000035
# REFERENCE: 
##
try {
    if ($MinPwLength) {
        $length = $MinPwLength
    } else {
        $length = 14
    }
    if ($SecurityPolicy.'System Access'.MinimumPasswordLength -ge $length) {
        $V220745 = $true
    } else {
        $V220745 = $false
    }
} catch {
    $V220745 = $false
}

##
# V-220746
# The built-in Microsoft password complexity filter must be enabled.
#
##
# DISCUSSION: 
# The use of complex passwords increases their strength against guessing and brute-force attacks.  This setting
# configures the system to verify that newly created passwords conform to the Windows password complexity
# policy.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for "Password must meet complexity requirements" is not set to "Enabled", this is a finding.
#
# If the site is using a password filter that requires this setting be set to "Disabled" for the filter to be
# used, this would not be considered a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Password must meet complexity requirements" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220746r569187_rule
# STIG ID: WN10-AC-000040
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'System Access'.PasswordComplexity -eq 1) {
        $V220746 = $true
    } else {
        $V220746 = $false
    }
} catch {
    $V220746 = $false
}

##
# V-220748
# The system must be configured to audit Account Logon - Credential Validation failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Credential validation records events related to validation tests on credentials for a user account logon.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Account Logon >> Credential Validation - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Account Logon >> "Audit Credential Validation" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220748r569187_rule
# STIG ID: WN10-AU-000005
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Credential Validation' -match "Failure") {
        $V220748 = $true
    } else {
        $V220748 = $false
    }
} catch {
    $V220748 = $false
}

##
# V-220749
# The system must be configured to audit Account Logon - Credential Validation successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Credential validation records events related to validation tests on credentials for a user account logon.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Account Logon >> Credential Validation - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Account Logon >> "Audit Credential Validation" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220749r569187_rule
# STIG ID: WN10-AU-000010
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Credential Validation' -match "Success") {
        $V220749 = $true
    } else {
        $V220749 = $false
    }
} catch {
    $V220748 = $false
}

##
# V-220750
# The system must be configured to audit Account Management - Security Group Management successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Security Group Management records events such as creating, deleting or changing of security groups, including
# changes in group members.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Account Management >> Security Group Management - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit Security Group Management"
# with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220750r851970_rule
# STIG ID: WN10-AU-000030
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security Group Management' -match "Success") {
        $V220750 = $true
    } else {
        $V220750 = $false
    }
} catch {
    $V220750 = $false
}

##
# V-220751
# The system must be configured to audit Account Management - User Account Management failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling
# user accounts.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Account Management >> User Account Management - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit User Account Management"
# with "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220751r851971_rule
# STIG ID: WN10-AU-000035
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'User Account Management' -match "Failure") {
        $V220751 = $true
    } else {
        $V220751 = $false
    }
} catch {
    $V220751 = $false
}

##
# V-220752
# The system must be configured to audit Account Management - User Account Management successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# User Account Management records events such as creating, changing, deleting, renaming, disabling, or enabling
# user accounts.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Account Management >> User Account Management - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Account Management >> "Audit User Account Management"
# with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220752r851972_rule
# STIG ID: WN10-AU-000040
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'User Account Management' -match "Success") {
        $V220752 = $true
    } else {
        $V220752 = $false
    }
} catch {
    $V220752 = $false
}

##
# V-220753
# The system must be configured to audit Detailed Tracking - PNP Activity successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Plug and Play activity records events related to the successful connection of external devices.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective. 
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Detailed Tracking >> Plug and Play Events - Success
#
##
# FIX: 
# Computer Configuration >> Windows Settings >> Advanced Audit Policy Configuration >> System Audit Policies >>
# Detailed Tracking >> "Audit PNP Activity" with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220753r851973_rule
# STIG ID: WN10-AU-000045
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Plug and Play Events' -match "Success") {
        $V220753 = $true
    } else {
        $V220753 = $false
    }
} catch {
    $V220753 = $false
}

##
# V-220754
# The system must be configured to audit Detailed Tracking - Process Creation successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Process creation records events related to the creation of a process and the source.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Detailed Tracking >> Process Creation - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Detailed Tracking >> "Audit Process Creation" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220754r851974_rule
# STIG ID: WN10-AU-000050
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Process Creation' -match "Success") {
        $V220754 = $true
    } else {
        $V220754 = $false
    }
} catch {
    $V220754 = $false
}

##
# V-220755
# The system must be configured to audit Logon/Logoff - Account Lockout failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Account Lockout events can be used to identify potentially malicious logon attempts.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
#
# Open a Command Prompt with elevated privileges ("Run as Administrator").
#
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Account Lockout - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Account Lockout" with "Failure"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220755r569187_rule
# STIG ID: WN10-AU-000054
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Account Lockout' -match "Failure") {
        $V220755 = $true
    } else {
        $V220755 = $false
    }
} catch {
    $V220755 = $false
}

##
# V-220756
# The system must be configured to audit Logon/Logoff - Group Membership successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Group Membership records information related to the group membership of a user's logon token.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective. 
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Group Membership - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Advanced Audit Policy
# Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Group Membership" with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220756r569187_rule
# STIG ID: WN10-AU-000060
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Group Membership' -match "Success") {
        $V220756 = $true
    } else {
        $V220756 = $false
    }
} catch {
    $V220756 = $false
}

##
# V-220757
# The system must be configured to audit Logon/Logoff - Logoff successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Logoff records user logoffs. If this is an interactive logoff, it is recorded on the local system. If it is to
# a network share, it is recorded on the system accessed.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Logoff - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Logoff" with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220757r569187_rule
# STIG ID: WN10-AU-000065
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logoff -match "Success") {
        $V220757 = $true
    } else {
        $V220757 = $false
    }
} catch {
    $V220757 = $false
}

##
# V-220758
# The system must be configured to audit Logon/Logoff - Logon failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a
# network share, it is recorded on the system accessed.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Logon - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Logon" with "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220758r569187_rule
# STIG ID: WN10-AU-000070
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logon -match "Failure") {
        $V220758 = $true
    } else {
        $V220758 = $false
    }
} catch {
    $V220758 = $false
}

##
# V-220759
# The system must be configured to audit Logon/Logoff - Logon successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Logon records user logons. If this is an interactive logon, it is recorded on the local system. If it is to a
# network share, it is recorded on the system accessed.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Logon - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Logon" with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220759r569187_rule
# STIG ID: WN10-AU-000075
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.Logon -match "Success") {
        $V220759 = $true
    } else {
        $V220759 = $false
    }
} catch {
    $V220759 = $false
}

##
# V-220760
# The system must be configured to audit Logon/Logoff - Special Logon successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Special Logon records special logons which have administrative privileges and can be used to elevate
# processes.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff >> Special Logon - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Special Logon" with "Success"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220760r569187_rule
# STIG ID: WN10-AU-000080
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Special Logon' -match "Success") {
        $V220760 = $true
    } else {
        $V220760 = $false
    }
} catch {
    $V220760 = $false
}

##
# V-220761
# Windows 10 must be configured to audit Object Access - File Share failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing file shares records events related to connection to shares on a system including system shares such
# as C$.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
#
# Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
#
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following:
#
# Object Access >> File Share - Failure
#
# If the system does not audit the above, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit File Share" with "Failure"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220761r569187_rule
# STIG ID: WN10-AU-000081
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'File Share' -match "Failure") {
        $V220761 = $true
    } else {
        $V220761 = $false
    }
} catch {
    $V220761 = $false
}

##
# V-220762
# Windows 10 must be configured to audit Object Access - File Share successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing file shares records events related to connection to shares on a system including system shares such
# as C$.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
#
# Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following:
#
# Object Access >> File Share - Success
#
# If the system does not audit the above, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit File Share" with "Success"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220762r569187_rule
# STIG ID: WN10-AU-000082
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'File Share' -match "Success") {
        $V220762 = $true
    } else {
        $V220762 = $false
    }
} catch {
    $V220762 = $false
}

##
# V-220763
# Windows 10 must be configured to audit Object Access - Other Object Access Events successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing for other object access records events related to the management of task scheduler jobs and COM+
# objects.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
#
# Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
#
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following:
#
# Object Access >> Other Object Access Events - Success
#
# If the system does not audit the above, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Other Object Access Events"
# with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220763r569187_rule
# STIG ID: WN10-AU-000083
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Object Access Events' -match "Success") {
        $V220763 = $true
    } else {
        $V220763 = $false
    }
} catch {
    $V220763 = $false
}

##
# V-220764
# Windows 10 must be configured to audit Object Access - Other Object Access Events failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing for other object access records events related to the management of task scheduler jobs and COM+
# objects.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
#
# Open PowerShell or a Command Prompt with elevated privileges ("Run as Administrator").
#
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following:
#
# Object Access >> Other Object Access Events - Failure
#
# If the system does not audit the above, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Other Object Access Events"
# with "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220764r569187_rule
# STIG ID: WN10-AU-000084
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Object Access Events' -match "Failure") {
        $V220764 = $true
    } else {
        $V220764 = $false
    }
} catch {
    $V220764 = $false
}

##
# V-220765
# The system must be configured to audit Object Access - Removable Storage failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing object access for removable media records events related to access attempts on file system objects on
# removable storage devices.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Object Access >> Removable Storage - Failure
#
# Some virtual machines may generate excessive audit events for access to the virtual hard disk itself when this
# setting is enabled. This may be set to Not Configured in such cases and would not be a finding.  This must be
# documented with the ISSO to include mitigations such as monitoring or restricting any actual removable storage
# connected to the VM.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Removable Storage" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220765r569187_rule
# STIG ID: WN10-AU-000085
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Removable Storage' -match "Failure") {
        $V220765 = $true
    } else {
        $V220765 = $false
    }
} catch {
    $V220765 = $false
}

##
# V-220766
# The system must be configured to audit Object Access - Removable Storage successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Auditing object access for removable media records events related to access attempts on file system objects on
# removable storage devices.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Object Access >> Removable Storage - Success
#
# Some virtual machines may generate excessive audit events for access to the virtual hard disk itself when this
# setting is enabled. This may be set to Not Configured in such cases and would not be a finding.  This must be
# documented with the ISSO to include mitigations such as monitoring or restricting any actual removable storage
# connected to the VM.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Removable Storage" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220766r569187_rule
# STIG ID: WN10-AU-000090
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Removable Storage' -match "Success") {
        $V220766 = $true
    } else {
        $V220766 = $false
    }
} catch {
    $V220766 = $false
}

##
# V-220767
# The system must be configured to audit Policy Change - Audit Policy Change successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Policy Change records events related to changes in audit policy.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Policy Change >> Audit Policy Change - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Audit Policy Change" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220767r569187_rule
# STIG ID: WN10-AU-000100
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Audit Policy Change' -match "Success") {
        $V220767 = $true
    } else {
        $V220767 = $false
    }
} catch {
    $V220767 = $false
}

##
# V-220768
# The system must be configured to audit Policy Change - Authentication Policy Change successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Authentication Policy Change records events related to changes in authentication policy including Kerberos
# policy and Trust changes.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Policy Change >> Authentication Policy Change - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Authentication Policy Change"
# with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220768r851975_rule
# STIG ID: WN10-AU-000105
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Authentication Policy Change' -match "Success") {
        $V220768 = $true
    } else {
        $V220768 = $false
    }
} catch {
    $V220768 = $false
}

##
# V-220769
# The system must be configured to audit Policy Change - Authorization Policy Change successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Authorization Policy Change records events related to changes in user rights, such as Create a token object.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective. 
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# -Open a Command Prompt with elevated privileges ("Run as Administrator").
# -Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding.
#
# Policy Change >> Authorization Policy Change - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit Authorization Policy Change"
# with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220769r569187_rule
# STIG ID: WN10-AU-000107
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Authorization Policy Change' -match "Success") {
        $V220769 = $true
    } else {
        $V220769 = $false
    }
} catch {
    $V220769 = $false
}

##
# V-220770
# The system must be configured to audit Privilege Use - Sensitive Privilege Use failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the
# operating system" or "Debug programs".
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Privilege Use >> Sensitive Privilege Use - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Privilege Use >> "Audit Sensitive Privilege Use" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220770r851976_rule
# STIG ID: WN10-AU-000110
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Sensitive Privilege Use' -match "Failure") {
        $V220770 = $true
    } else {
        $V220770 = $false
    }
} catch {
    $V220770 = $false
}

##
# V-220771
# The system must be configured to audit Privilege Use - Sensitive Privilege Use successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Sensitive Privilege Use records events related to use of sensitive privileges, such as "Act as part of the
# operating system" or "Debug programs".
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# Privilege Use >> Sensitive Privilege Use - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Privilege Use >> "Audit Sensitive Privilege Use" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220771r851977_rule
# STIG ID: WN10-AU-000115
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Sensitive Privilege Use' -match "Failure") {
        $V220771 = $true
    } else {
        $V220771 = $false
    }
} catch {
    $V220771 = $false
}

##
# V-220772
# The system must be configured to audit System - IPSec Driver failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# IPSec Driver records events related to the IPSec Driver such as dropped packets.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> IPSec Driver - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit IPSec Driver" with "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220772r569187_rule
# STIG ID: WN10-AU-000120
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'IPsec Driver' -match "Failure") {
        $V220772 = $true
    } else {
        $V220772 = $false
    }
} catch {
    $V220772 = $false
}

##
# V-220773
# The system must be configured to audit System - Other System Events successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Other System Events records information related to cryptographic key operations and the Windows Firewall
# service.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective. 
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> Other System Events - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit Other System Events" with "Success"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220773r569187_rule
# STIG ID: WN10-AU-000130
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other System Events' -match "Success") {
        $V220773 = $true
    } else {
        $V220773 = $false
    }
} catch {
    $V220773 = $false
}

$hash = [ordered]@{
    'V-220697' = $V220697
    'V-220698' = $V220698
    'V-220699' = $V220699
    'V-220701-NoChk' = $V220701
    'V-220702' = $V220702
    'V-220703' = $V220703
    'V-220704' = $V220704
    'V-220705-NoChk' = $V220705
    'V-220709' = $V220709
    'V-220710-NoChk' = $V220710
    'V-220713' = $V220713
    'V-220714' = $V220714
    'V-220716' = $V220716
    'V-220717' = $V220717
    'V-220719' = $V220719
    'V-220720' = $V220720
    'V-220721' = $V220721
    'V-220722' = $V220722
    'V-220723' = $V220723
    'V-220724' = $V220724
    'V-220725-NoChk' = $V220725
    'V-220728' = $V220728
    'V-220729' = $V220729
    'V-220730' = $V220730
    'V-220731' = $V220731
    'V-220732' = $V220732
    'V-220733-NoChk' = $V220733
    'V-220734-NoChk' = $V220734
    'V-220735-NoChk' = $V220735
    'V-220736-NoChk' = $V220736
    'V-220738-NoChk' = $V220738
    'V-220739' = $V220739
    'V-220740' = $V220740
    'V-220741' = $V220741
    'V-220742' = $V220742
    'V-220743' = $V220743
    'V-220744' = $V220744
    'V-220745' = $V220745
    'V-220746' = $V220746
    'V-220748' = $V220748
    'V-220749' = $V220749
    'V-220750' = $V220750
    'V-220751' = $V220751
    'V-220752' = $V220752
    'V-220753' = $V220753
    'V-220754' = $V220754
    'V-220755' = $V220755
    'V-220756' = $V220756
    'V-220757' = $V220757
    'V-220758' = $V220758
    'V-220759' = $V220759
    'V-220760' = $V220760
    'V-220761' = $V220761
    'V-220762' = $V220762
    'V-220763' = $V220763
    'V-220764' = $V220764
    'V-220765' = $V220765
    'V-220766' = $V220766
    'V-220767' = $V220767
    'V-220768' = $V220768
    'V-220769' = $V220769
    'V-220770' = $V220770
    'V-220771' = $V220771
    'V-220772' = $V220772
    'V-220773' = $V220773
}

return $hash | ConvertTo-Json -Compress
