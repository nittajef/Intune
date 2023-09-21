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

$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

$DeviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard

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



#
# List of accounts used across multiple rule checks
#
$Administrators = @("\Administrator")



##
# V-220706
# Windows 10 systems must be maintained at a supported servicing level.
#
##
# DISCUSSION: 
# Windows 10 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a
# Service. Systems at unsupported servicing levels or releases will not receive security updates for new
# vulnerabilities, which leaves them subject to exploitation.
#
# New versions with feature updates are planned to be released on a semiannual basis with an estimated support
# timeframe of 18 to 30 months depending on the release. Support for previously released versions has been
# extended for Enterprise editions.
#
# A separate servicing branch intended for special-purpose systems is the Long-Term Servicing Channel (LTSC,
# formerly Branch - LTSB), which will receive security updates for 10 years but excludes feature updates.
#
##
# CHECK: 
# Run "winver.exe".
#
# If the "About Windows" dialog box does not display the following or greater, this is a finding:
#
# "Microsoft Windows Version 20H2 (OS Build 190xx.x)"
#
# Note: Microsoft has extended support for previous versions, providing critical and important updates for
# Windows 10 Enterprise.
#
# Microsoft scheduled end-of-support dates for current Semi-Annual Channel versions:
#
# v20H2 - 9 May 2023
# v21H1 - 13 Dec 2022
# v21H2 - 11 June 2024                                               
#
# No preview versions will be used in a production environment.
#
# Special-purpose systems using the Long-Term Servicing Branch\Channel (LTSC\B) may be at the following
# versions, which is not a finding:
#
# v1507 (Build 10240)
# v1607 (Build 14393)
# v1809 (Build 17763)
# v21H2 (Build 19044)
#
##
# FIX: 
# Update systems on the Semi-Annual Channel to "Microsoft Windows Version 20H2 (OS Build 190xx.x)" or greater.
#
# It is recommended systems be upgraded to the most recently released version.
#
# Special-purpose systems using the LTSC\B may be at the following versions:
#
# v1507 (Build 10240)
# v1607 (Build 14393)
# v1809 (Build 17763)
# v21H2 (Build 19044)
#
##
# SEVERITY: CAT I
# RULE ID: SV-220706r857183_rule
# STIG ID: WN10-00-000040
# REFERENCE: 
##
try {
    if ($SupportedBuilds) {
        $builds = $SupportedBuilds
    } else {
        $builds = @("19044", "19045", "22000", "22621")
    }
    if ($builds -contains $ComputerInfo.OsBuildNumber) {
        $V220706 = $true
    } else {
        $V220706 = $false
    }
} catch {
    $V220706 = $false
}

##
# V-220707
# The Windows 10 system must use an anti-virus program.
#
##
# DISCUSSION: 
# Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism
# to detect this type of software will aid in elimination of the software from the operating system.
#
##
# CHECK: 
# Verify an anti-virus solution is installed on the system and in use. The anti-virus solution may be bundled
# with an approved Endpoint Security Solution.
#
# Verify if Windows Defender is in use or enabled:
#
# Open "PowerShell".
#
# Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName"
#
# Verify third-party antivirus is in use or enabled:
#
# Open "PowerShell".
#
# Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName"
#
# Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName"
#
# If there is no anti-virus solution installed on the system, this is a finding.
#
##
# FIX: 
# If no anti-virus software is on the system and in use, install Windows Defender or a third-party anti-virus
# solution.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220707r793194_rule
# STIG ID: WN10-00-000045
# REFERENCE: 
##
try {
    $V220707 = $false
    $apps = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
    foreach ($app in $apps) {
        if ($app.productState.ToString('X').Substring(1,2) -eq '10') {
            $V220707 = $true
        }
    }
} catch {
    $V220707 = $false
}

##
# V-220708
# Local volumes must be formatted using NTFS.
#
##
# DISCUSSION: 
# The ability to set access permissions and auditing is critical to maintaining the security and proper access
# controls of a system.  To support this, volumes must be formatted using the NTFS file system.
#
##
# CHECK: 
# Run "Computer Management".
# Navigate to Storage >> Disk Management.
#
# If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a
# finding.
#
# This does not apply to system partitions such the Recovery and EFI System Partition.
#
##
# FIX: 
# Format all local volumes to use NTFS.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220708r569187_rule
# STIG ID: WN10-00-000050
# REFERENCE: 
##
try {
    $volumes = Get-Volume
    # Get UniqueId for the EFI partition which is FAT32
    $efi_id = "\\?\Volume$(((Get-Partition).Where{$_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'}.Guid))\"
    $V220708 = $true
    foreach ($volume in $volumes) {
        if ($volume.UniqueId -ne $efi_id -and $volume.DriveType -eq "Fixed" -and $volume.FileSystemType -ne "NTFS") {
            $V220708 = $false
        }
    }
} catch {
    $V220708 = $false
}

##
# V-220712
# Only accounts responsible for the administration of a system must have Administrator rights on the system.
#
##
# DISCUSSION: 
# An account that does not have Administrator duties must not have Administrator rights.  Such rights would
# allow the account to bypass or modify required security restrictions on that machine and make it vulnerable to
# attack.
#
# System administrators must log on to systems only using accounts with the minimum level of authority
# necessary.
#
# For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator
# group (see V-36434 in the Active Directory Domain STIG).  Restricting highly privileged accounts from the
# local Administrators group helps mitigate the risk of privilege escalation resulting from credential theft
# attacks.
#
# Standard user accounts must not be members of the local administrators group.
#
##
# CHECK: 
# Run "Computer Management".
# Navigate to System Tools >> Local Users and Groups >> Groups.
# Review the members of the Administrators group.
# Only the appropriate administrator groups or accounts responsible for administration of the system may be
# members of the group.
#
# For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator
# group.
#
# Standard user accounts must not be members of the local administrator group.
#
# If prohibited accounts are members of the local administrators group, this is a finding.
#
# The built-in Administrator account or other required administrative accounts would not be a finding.
#
##
# FIX: 
# Configure the system to include only administrator groups or accounts that are responsible for the system in
# the local Administrators group.
#
# For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator
# group.
#
# Remove any standard user accounts.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220712r877392_rule
# STIG ID: WN10-00-000070
# REFERENCE: 
##
try {
    $members = Get-LocalGroupMember -Group "Administrators"
    $V220712 = $true
    foreach ($member in $members) {
        if ($member.Name -match "\Domain Admins") {
            $V220712 = $false
        }
        if ($member.Name -notin $Administrators) {
            $V220712 = $false
        }
    }
} catch {
    $V220712 = $false
}

##
# V-220718
# Internet Information System (IIS) or its subcomponents must not be installed on a workstation.
#
##
# DISCUSSION: 
# Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted. 
#  Websites must only be hosted on servers that have been designed for that purpose and can be adequately
# secured.
#
##
# CHECK: 
# IIS is not installed by default.  Verify it has not been installed on the system.
#
# Run "Programs and Features".
# Select "Turn Windows features on or off".
#
# If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are
# selected, this is a finding.
#
# If an application requires IIS or a subset to be installed to function, this needs be documented with the
# ISSO.  In addition, any applicable requirements from the IIS STIG must be addressed.
#
##
# FIX: 
# Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" from the
# system.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220718r569187_rule
# STIG ID: WN10-00-000100
# REFERENCE: 
##
try {
    if (((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole").State) -eq "Disabled") {
        $V220718 = $true
    }
} catch {
    $V220718 = $false
}

##
# V-220726
# Data Execution Prevention (DEP) must be configured to at least OptOut.
#
##
# DISCUSSION: 
# Attackers are constantly looking for vulnerabilities in systems and applications. Data Execution Prevention
# (DEP) prevents harmful code from running in protected memory locations reserved for Windows and other
# programs.
#
##
# CHECK: 
# Verify the DEP configuration.
# Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
# Enter "BCDEdit /enum {current}". (If using PowerShell "{current}" must be enclosed in quotes.)
# If the value for "nx" is not "OptOut", this is a finding.
# (The more restrictive configuration of "AlwaysOn" would not be a finding.)
#
##
# FIX: 
# Configure DEP to at least OptOut.
#
# Note: Suspend BitLocker before making changes to the DEP configuration.
#
# Open a command prompt (cmd.exe) or PowerShell with elevated privileges (Run as administrator).
# Enter "BCDEDIT /set {current} nx OptOut".  (If using PowerShell "{current}" must be enclosed in quotes.)
# "AlwaysOn", a more restrictive selection, is also valid but does not allow applications that do not function
# properly to be opted out of DEP.
#
# Opted out exceptions can be configured in the "System Properties".
#
# Open "System" in Control Panel.
# Select "Advanced system settings".
# Click "Settings" in the "Performance" section.
# Select the "Data Execution Prevention" tab.
# Applications that are opted out are configured in the window below the selection "Turn on DEP for all programs
# and services except those I select:".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220726r851966_rule
# STIG ID: WN10-00-000145
# REFERENCE: 
##
try {
    $DEP = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property DataExecutionPrevention_SupportPolicy
    if ($DEP.DataExecutionPrevention_SupportPolicy -eq 1 -or $DEP.DataExecutionPrevention_SupportPolicy -eq 3) {
        $V220726 = $true
    } else {
        $V220726 = $false
    }
} catch {
    $V220726 = $false
}

##
# V-220727
# Structured Exception Handling Overwrite Protection (SEHOP) must be enabled.
#
##
# DISCUSSION: 
# Attackers are constantly looking for vulnerabilities in systems and applications. Structured Exception
# Handling Overwrite Protection (SEHOP) blocks exploits that use the Structured Exception Handling overwrite
# technique, a common buffer overflow attack.
#
##
# CHECK: 
# This is applicable to Windows 10 prior to v1709.
#
# Verify SEHOP is turned on.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Session Manager\kernel\
#
# Value Name: DisableExceptionChainValidation
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Enable Structured Exception Handling Overwrite Protection (SEHOP)" to "Enabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
# "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220727r851967_rule
# STIG ID: WN10-00-000150
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -Name DisableExceptionChainValidation -ErrorAction Stop) -eq 0) {
        $V220727 = $true
    } else {
        $V220727 = $false
    }
} catch {
    $V220727 = $false
}


##
# V-220737-NoChk
# Administrative accounts must not be used with applications that access the Internet, such as web browsers, or
# with potential Internet sources, such as email.
#
##
# DISCUSSION: 
# Using applications that access the Internet or have potential Internet sources using administrative privileges
# exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user,
# the entire system could be compromised. Web browsers and email are common attack vectors for introducing
# malicious code and must not be run with an administrative account.
#
# Since administrative accounts may generally change or work around technical restrictions for running a web
# browser or other applications, it is essential that policy requires administrative accounts to not access the
# Internet or use applications, such as email.
#
# The policy should define specific exceptions for local service administration. These exceptions may include
# HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.
#
# Technical means such as application whitelisting can be used to enforce the policy to ensure compliance.
#
##
# CHECK: 
# Determine whether administrative accounts are prevented from using applications that access the Internet, such
# as web browsers, or with potential Internet sources, such as email, except as necessary for local service
# administration.
#
# The organization must have a policy that prohibits administrative accounts from using applications that access
# the Internet, such as web browsers, or with potential Internet sources, such as email, except as necessary for
# local service administration. The policy should define specific exceptions for local service administration.
# These exceptions may include HTTP(S)-based tools that are used for the administration of the local system,
# services, or attached devices.
#
# Technical measures such as the removal of applications or application whitelisting must be used where feasible
# to prevent the use of applications that access the Internet. 
#
# If accounts with administrative privileges are not prevented from using applications that access the Internet
# or with potential Internet sources, this is a finding.
#
##
# FIX: 
# Establish and enforce a policy that prohibits administrative accounts from using applications that access the
# Internet, such as web browsers, or with potential Internet sources, such as email. Define specific exceptions
# for local service administration. These exceptions may include HTTP(S)-based tools that are used for the
# administration of the local system, services, or attached devices.
#
# Implement technical measures where feasible such as removal of applications or use of application whitelisting
# to restrict the use of applications that can access the Internet.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220737r569187_rule
# STIG ID: WN10-00-000240
# REFERENCE: 
##
$V220737 = $true

##
# V-220747
# Reversible password encryption must be disabled.
#
##
# DISCUSSION: 
# Storing passwords using reversible encryption is essentially the same as storing clear-text versions of the
# passwords. For this reason, this policy must never be enabled.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >>
# Account Policies >> Password Policy.
#
# If the value for "Store password using reversible encryption" is not set to "Disabled", this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Account
# Policies >> Password Policy >> "Store passwords using reversible encryption" to "Disabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220747r877397_rule
# STIG ID: WN10-AC-000045
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnablePlainTextPassword -ErrorAction Stop) -eq 0) {
        $V220747 = $true
    } else {
        $V220747 = $false
    }
} catch {
    $V220747 = $false
}

##
# V-220812
# Credential Guard must be running on Windows 10 domain-joined systems.
#
##
# DISCUSSION: 
# Credential Guard uses virtualization based security to protect information that could be used in credential
# theft attacks if compromised. This authentication information, which was stored in the Local Security
# Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be
# accessed by privileged system software.
#
##
# CHECK: 
# Confirm Credential Guard is running on domain-joined systems.
#
# For devices that support Credential Guard, this feature must be enabled. Organizations must take the
# appropriate action to acquire and implement compatible hardware with Credential Guard enabled.
#
# Virtualization based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDIs) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is Not Applicable.
#
# Run "PowerShell" with elevated privileges (run as administrator). 
#
# Enter the following:
# "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
#
# If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.
#
# Alternately:
#
# Run "System Information".
#
# Under "System Summary", verify the following:
#
# If "Virtualization-based Security Services Running" does not list "Credential Guard", this is finding.
#
# The policy settings referenced in the Fix section will configure the following registry value. However, due to
# hardware requirements, the registry value alone does not ensure proper function.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\
#
# Value Name: LsaCfgFlags
# Value Type: REG_DWORD
# Value: 0x00000001 (1) (Enabled with UEFI lock)
#
##
# FIX: 
# Virtualization based security, including Credential Guard, currently cannot be implemented in VDIs due to
# specific supporting requirements including a TPM, UEFI with Secure Boot, and the capability to run the Hyper-V
# feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is Not Applicable.
#
# For VDIs with persistent desktops, this may be downgraded to a CAT II only where administrators have specific
# tokens for the VDI. Administrator accounts on virtual desktops must only be used on systems in the VDI; they
# may not have administrative privileges on any other systems such as servers and physical workstations.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >>
# "Turn On Virtualization Based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential
# Guard Configuration:".
#
# v1507 LTSB does not include selection options; select "Enable Credential Guard".
#
# A Microsoft TechNet article on Credential Guard, including system requirement details, can be found at the
# following link:
#
# https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard
#
##
# SEVERITY: CAT I
# RULE ID: SV-220812r890430_rule
# STIG ID: WN10-CC-000075
# REFERENCE: 
##
if ($DeviceGuard.SecurityServicesRunning -contains 1) {
    $V220812 = $true
} else {
    $V220812 = $false
}

##
# V-220823
# Solicited Remote Assistance must not be allowed.
#
##
# DISCUSSION: 
# Remote assistance allows another user to view or take control of the local session of a user.  Solicited
# assistance is help that is specifically requested by the local user.  This may allow unauthorized parties
# access to the resources on the computer.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fAllowToGetHelp
#  
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote
# Assistance >> "Configure Solicited Remote Assistance" to "Disabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220823r569187_rule
# STIG ID: WN10-CC-000155
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -ErrorAction Stop) -eq 0) {
        $V220823 = $true
    } else {
        $V220823 = $false
    }
} catch {
    $V220823 = $false
}


##
# V-220827
# Autoplay must be turned off for non-volume devices.
#
##
# DISCUSSION: 
# Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive
# as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may
# start.  This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP)
# devices).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
#
# Value Name: NoAutoplayfornonVolume
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# AutoPlay Policies >> "Disallow Autoplay for non-volume devices" to "Enabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220827r851989_rule
# STIG ID: WN10-CC-000180
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoAutoplayfornonVolume -ErrorAction Stop) -eq 1) {
        $V220827 = $true
    } else {
        $V220827 = $false
    }
} catch {
    $V220827 = $false
}


##
# V-220828
# The default autorun behavior must be configured to prevent autorun commands.
#
##
# DISCUSSION: 
# Allowing autorun commands to execute may introduce malicious code to a system.  Configuring this setting
# prevents autorun commands from executing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
#
# Value Name: NoAutorun
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# AutoPlay Policies >> "Set the default behavior for AutoRun" to "Enabled:Do not execute any autorun commands".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220828r851990_rule
# STIG ID: WN10-CC-000185
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoAutorun -ErrorAction Stop) -eq 1) {
        $V220828 = $true
    } else {
        $V220828 = $false
    }
} catch {
    $V220828 = $false
}


##
# V-220829
# Autoplay must be disabled for all drives.
#
##
# DISCUSSION: 
# Allowing autoplay to execute may introduce malicious code to a system.  Autoplay begins reading from a drive
# as soon as you insert media in the drive.  As a result, the setup file of programs or music on audio media may
# start.  By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the
# CD-ROM drive) and on network drives.  If you enable this policy, you can also disable autoplay on all drives.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\
#
# Value Name: NoDriveTypeAutoRun
#
# Value Type: REG_DWORD
# Value: 0x000000ff (255)
#
# Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is
# selected, or "255" with Decimal selected.  Using the policy value specified in the Fix section will enter it
# correctly.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220829r851991_rule
# STIG ID: WN10-CC-000190
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" -Name NoDriveTypeAutoRun -ErrorAction Stop) -eq 255) {
        $V220829 = $true
    } else {
        $V220829 = $false
    }
} catch {
    $V220829 = $false
}


##
# V-220857
# The Windows Installer Always install with elevated privileges must be disabled.
#
##
# DISCUSSION: 
# Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate
# privileges when installing applications can allow malicious persons and applications to gain full control of a
# system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
#
# Value Name: AlwaysInstallElevated
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Installer >> "Always install with elevated privileges" to "Disabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220857r851998_rule
# STIG ID: WN10-CC-000315
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -ErrorAction Stop) -eq 0) {
        $V220857 = $true
    } else {
        $V220857 = $false
    }
} catch {
    $V220857 = $false
}


##
# V-220862
# The Windows Remote Management (WinRM) client must not use Basic authentication.
#
##
# DISCUSSION: 
# Basic authentication uses plain text passwords that could be used to compromise a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
#
# Value Name: AllowBasic
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220862r877395_rule
# STIG ID: WN10-CC-000330
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -ErrorAction Stop) -eq 0) {
        $V220862 = $true
    } else {
        $V220862 = $false
    }
} catch {
    $V220862 = $false
}


##
# V-220865
# The Windows Remote Management (WinRM) service must not use Basic authentication.
#
##
# DISCUSSION: 
# Basic authentication uses plain text passwords that could be used to compromise a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
#
# Value Name: AllowBasic
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled".
#
# Severity Override Guidance: The AO can allow the severity override if they have reviewed the overall
# protection. This would only be allowed temporarily for implementation as documented and approved. 
# ....
# Allowing Basic authentication to be used for the sole creation of Office 365 DoD tenants.
# ....
# A documented mechanism and or script that can disable Basic authentication once administration completes. 
# ....
# Use of a Privileged Access Workstation (PAW) and adherence to the Clean Source principle for administration.
#
##
# SEVERITY: CAT I
# RULE ID: SV-220865r877395_rule
# STIG ID: WN10-CC-000345
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowBasic -ErrorAction Stop) -eq 0) {
        $V220865 = $true
    } else {
        $V220865 = $false
    }
} catch {
    $V220865 = $false
}


##
# V-220928
# Anonymous SID/Name translation must not be allowed.
#
##
# DISCUSSION: 
# Allowing anonymous SID/Name translation can provide sensitive information for accessing a system.  Only
# authorized users must be able to perform such translations.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options.
#
# If the value for "Network access: Allow anonymous SID/Name translation" is not set to "Disabled", this is a
# finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network access: Allow anonymous SID/Name translation" to "Disabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220928r569187_rule
# STIG ID: WN10-SO-000140
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'System Access'.LSAAnonymousNameLookup -eq 0) {
        $V220928 = $true
    } else {
        $V220928 = $false
    }
} catch {
    $V220928 = $false
}

##
# V-220929
# Anonymous enumeration of SAM accounts must not be allowed.
#
##
# DISCUSSION: 
# Anonymous enumeration of SAM accounts allows anonymous log on users (null session connections) to list all
# accounts names, thus providing a list of potential points to attack the system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: RestrictAnonymousSAM
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts" to
# "Enabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220929r569187_rule
# STIG ID: WN10-SO-000145
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -ErrorAction Stop) -eq 1) {
        $V220929 = $true
    } else {
        $V220929 = $false
    }
} catch {
    $V220929 = $false
}


##
# V-220930
# Anonymous enumeration of shares must be restricted.
#
##
# DISCUSSION: 
# Allowing anonymous logon users (null session connections) to list all account names and enumerate all shared
# resources can provide a map of potential points to attack the system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: RestrictAnonymous
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network access: Do not allow anonymous enumeration of SAM accounts and
# shares" to "Enabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220930r569187_rule
# STIG ID: WN10-SO-000150
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -ErrorAction Stop) -eq 1) {
        $V220930 = $true
    } else {
        $V220930 = $false
    }
} catch {
    $V220930 = $false
}


##
# V-220932
# Anonymous access to Named Pipes and Shares must be restricted.
#
##
# DISCUSSION: 
# Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. 
#  This setting restricts access to those defined in "Network access: Named Pipes that can be accessed
# anonymously" and "Network access: Shares that can be accessed anonymously",  both of which must be blank under
# other requirements.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\
#
# Value Name: RestrictNullSessAccess
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network access: Restrict anonymous access to Named Pipes and Shares" to
# "Enabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220932r569187_rule
# STIG ID: WN10-SO-000165
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RestrictNullSessAccess -ErrorAction Stop) -eq 1) {
        $V220932 = $true
    } else {
        $V220932 = $false
    }
} catch {
    $V220932 = $false
}


##
# V-220937
# The system must be configured to prevent the storage of the LAN Manager hash of passwords.
#
##
# DISCUSSION: 
# The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash
# to retrieve account passwords.  This setting controls whether or not a LAN Manager hash of the password is
# stored in the SAM the next time the password is changed.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: NoLMHash
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Do not store LAN Manager hash value on next password
# change" to "Enabled".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220937r877397_rule
# STIG ID: WN10-SO-000195
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name NoLMHash -ErrorAction Stop) -eq 1) {
        $V220937 = $true
    } else {
        $V220937 = $false
    }
} catch {
    $V220937 = $false
}


##
# V-220938
# The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
#
##
# DISCUSSION: 
# The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to
# domain accounts.  NTLM, which is less secure, is retained in later Windows versions  for compatibility with
# clients and servers that are running earlier versions of Windows or applications that still use it.  It is
# also used to authenticate logons to stand-alone computers that are running later versions.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: LmCompatibilityLevel
#
# Value Type: REG_DWORD
# Value: 5
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: LAN Manager authentication level" to "Send NTLMv2 response
# only. Refuse LM & NTLM".
#
##
# SEVERITY: CAT I
# RULE ID: SV-220938r569187_rule
# STIG ID: WN10-SO-000205
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -ErrorAction Stop) -eq 5) {
        $V220938 = $true
    } else {
        $V220938 = $false
    }
} catch {
    $V220938 = $false
}


##
# V-220958
# The Act as part of the operating system user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Act as part of the operating system" user right can assume the identity of any user and
# gain access to resources that user is authorized to access.  Any accounts with this right can take complete
# control of a system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts (to include administrators), are granted the "Act as part of the operating system"
# user right, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Act as part of the operating system" to be defined but containing no
# entries (blank).
#
##
# SEVERITY: CAT I
# RULE ID: SV-220958r877392_rule
# STIG ID: WN10-UR-000015
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeTcbPrivilege) {
        $V220958 = $false
    } else {
        $V220958 = $true
    }
} catch {
    $V220958 = $false
}

##
# V-220963
# The Create a token object user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Create a token object" user right allows a process to create an access token. This could be used to
# provide elevated rights and compromise a system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts are granted the "Create a token object" user right, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Create a token object" to be defined but containing no entries (blank).
#
##
# SEVERITY: CAT I
# RULE ID: SV-220963r877392_rule
# STIG ID: WN10-UR-000045
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeCreateTokenPrivilege) {
        $V220963 = $false
    } else {
        $V220963 = $true
    }
} catch {
    $V220963 = $false
}

##
# V-220967
# The Debug programs user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing
# complete access to sensitive and critical operating system components.  This right is given to Administrators
# in the default configuration.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Debug Programs" user right, this is a
# finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Debug programs" to only include the following groups or accounts:
#
# Administrators
#
##
# SEVERITY: CAT I
# RULE ID: SV-220967r877392_rule
# STIG ID: WN10-UR-000065
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege -eq '*S-1-5-32-544') {
        $V220967 = $true
    } else {
        $V220967 = $false
    }
} catch {
    $V220967 = $false
}

$hash = [ordered]@{
    'V-220706' = $V220706
    'V-220707' = $V220707
    'V-220708' = $V220708
    'V-220712' = $V220712
    'V-220718' = $V220718
    'V-220726' = $V220726
    'V-220727' = $V220727
    'V-220737-NoChk' = $V220737
    'V-220747' = $V220747
    'V-220812' = $V220812
    'V-220823' = $V220823
    'V-220827' = $V220827
    'V-220828' = $V220828
    'V-220829' = $V220829
    'V-220857' = $V220857
    'V-220862' = $V220862
    'V-220865' = $V220865
    'V-220928' = $V220928
    'V-220929' = $V220929
    'V-220930' = $V220930
    'V-220932' = $V220932
    'V-220937' = $V220937
    'V-220938' = $V220938
    'V-220958' = $V220958
    'V-220963' = $V220963
    'V-220967' = $V220967
}

return $hash | ConvertTo-Json -Compress
