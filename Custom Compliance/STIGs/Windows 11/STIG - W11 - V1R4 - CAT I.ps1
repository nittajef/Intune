##
# Microsoft Windows 11 Security Technical Implementation Guide
# Version: 1, Release: 4 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
# Files created: 10/13/2023 1:54:39 PM
##


#
# Gather/set data used across multiple rule checks
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



##
# V-253263
# Windows 11 systems must be maintained at a supported servicing level.
#
##
# DISCUSSION: 
# Windows 11 is maintained by Microsoft at servicing levels for specific periods of time to support Windows as a
# Service. Systems at unsupported servicing levels or releases will not receive security updates for new
# vulnerabilities which leaves them subject to exploitation.
#
# New versions with feature updates are planned to be released on a semi-annual basis with an estimated support
# timeframe of 18 to 30 months depending on the release. Support for previously released versions has been
# extended for Enterprise editions.
#
# A separate servicing branch intended for special purpose systems is the Long-Term Servicing Channel (LTSC,
# formerly Branch - LTSB) which will receive security updates for 10 years but excludes feature updates.
#
##
# CHECK: 
# Run "winver.exe".
#
# If the "About Windows" dialog box does not display "Microsoft Windows 11 Version 21H2 (OS Build 22000.348)" or
# greater, this is a finding.
#
##
# FIX: 
# Update systems on the Semi-Annual Channel to "Microsoft Windows 11 Version 21H2 (OS Build 22000.348)" or
# greater.
#
##
# SEVERITY: CAT I
# RULE ID: SV-253263r828873_rule
# STIG ID: WN11-00-000040
# W10 ID: V-220706
# REFERENCE: 
##
try {
    if ($SupportedBuilds) {
        $builds = $SupportedBuilds
    } else {
        $builds = @("19044", "19045", "22000", "22621")
        $builds += $LTSB
    }
    if ($builds -contains $ComputerInfo.OsBuildNumber) {
        $V253263 = $true
    } else {
        $V253263 = $false
    }
} catch {
    $V253263 = $false
}

##
# V-253264
# The Windows 11 system must use an antivirus program.
#
##
# DISCUSSION: 
# Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism
# to detect this type of software will aid in elimination of the software from the operating system.
#
##
# CHECK: 
# Verify an antivirus solution is installed on the system and in use. The antivirus solution may be bundled with
# an approved Endpoint Security Solution.
#
# Verify if Microsoft Defender Antivirus is in use or enabled:
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
# If there is no antivirus solution installed on the system, this is a finding.
#
##
# FIX: 
# Install Microsoft Defender Antivirus or a third-party antivirus solution.
#
##
# SEVERITY: CAT I
# RULE ID: SV-253264r828876_rule
# STIG ID: WN11-00-000045
# W10 ID: V-220707
# REFERENCE: 
##
try {
    $V253264 = $false
    $apps = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
    foreach ($app in $apps) {
        if ($app.productState.ToString('X').Substring(1,2) -eq '10') {
            $V253264 = $true
        }
    }
} catch {
    $V253264 = $false
}

##
# V-253265
# Local volumes must be formatted using NTFS.
#
##
# DISCUSSION: 
# The ability to set access permissions and auditing is critical to maintaining the security and proper access
# controls of a system. To support this, volumes must be formatted using the NTFS file system.
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
# RULE ID: SV-253265r828879_rule
# STIG ID: WN11-00-000050
# W10 ID: V-220708
# REFERENCE: 
##
try {
    $volumes = Get-Volume
    # Get UniqueId for the EFI partition which is FAT32
    $efi_id = "\\?\Volume$(((Get-Partition).Where{$_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'}.Guid))\"
    $V253265 = $true
    foreach ($volume in $volumes) {
        if ($volume.UniqueId -ne $efi_id -and $volume.DriveType -eq "Fixed" -and $volume.FileSystemType -ne "NTFS") {
            $V253265 = $false
        }
    }
} catch {
    $V253265 = $false
}

##
# V-253269
# Only accounts responsible for the administration of a system must have Administrator rights on the system.
#
##
# DISCUSSION: 
# An account that does not have Administrator duties must not have Administrator rights. Such rights would allow
# the account to bypass or modify required security restrictions on that machine and make it vulnerable to
# attack.
#
# System administrators must log on to systems only using accounts with the minimum level of authority
# necessary.
#
# For domain-joined workstations, the Domain Admins group must be replaced by a domain workstation administrator
# group (see V-36434 in the Active Directory Domain STIG). Restricting highly privileged accounts from the local
# Administrators group helps mitigate the risk of privilege escalation resulting from credential theft attacks.
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
# RULE ID: SV-253269r828891_rule
# STIG ID: WN11-00-000070
# W10 ID: V-220712
# REFERENCE: 
##
try {
    $members = Get-LocalGroupMember -Group "Administrators"
    $V253269 = $true
    foreach ($member in $members) {
        if ($member.Name -match "\Domain Admins") {
            $V253269 = $false
            break
        } elseif ($member.Name -notin $Administrators) {
            $V253269 = $false
            break
        } elseif ($member.SID -like "*-500") {
            # Default administrator account is okay
        }
    }
} catch {
    $V253269 = $false
}

##
# V-253275
# Internet Information System (IIS) or its subcomponents must not be installed on a workstation.
#
##
# DISCUSSION: 
# IIS is not installed by default. Installation of Internet Information System (IIS) may allow unauthorized
# internet services to be hosted. Websites must only be hosted on servers that have been designed for that
# purpose and can be adequately secured.
#
##
# CHECK: 
# Verify it has not been installed on the system.
#
# Run "Programs and Features".
# Select "Turn Windows features on or off".
#
# If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are
# selected, this is a finding.
#
# If an application requires IIS or a subset to be installed to function, this needs be documented with the
# ISSO. In addition, any applicable requirements from the IIS STIG must be addressed.
#
##
# FIX: 
# Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" from the
# system.
#
##
# SEVERITY: CAT I
# RULE ID: SV-253275r828909_rule
# STIG ID: WN11-00-000100
# W10 ID: V-220718
# REFERENCE: 
##
try {
    if (((Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServerRole").State) -eq "Disabled") {
        $V253275 = $true
    }
} catch {
    $V253275 = $false
}

##
# V-253283
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
# Enter "BCDEDIT /set {current} nx OptOut". (If using PowerShell "{current}" must be enclosed in quotes.)
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
# RULE ID: SV-253283r828933_rule
# STIG ID: WN11-00-000145
# W10 ID: V-220726
# REFERENCE: 
##
try {
    $DEP = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -Property DataExecutionPrevention_SupportPolicy
    if ($DEP.DataExecutionPrevention_SupportPolicy -eq 1 -or $DEP.DataExecutionPrevention_SupportPolicy -eq 3) {
        $V253283 = $true
    } else {
        $V253283 = $false
    }
} catch {
    $V253283 = $false
}

##
# V-253284
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
# Verify SEHOP is turned on.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
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
# RULE ID: SV-253284r828936_rule
# STIG ID: WN11-00-000150
# W10 ID: V-220727
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\" -Name DisableExceptionChainValidation -ErrorAction Stop) -eq 0) {
        $V253284 = $true
    } else {
        $V253284 = $false
    }
} catch {
    $V253284 = $false
}


##
# V-253294
# Administrative accounts must not be used with applications that access the internet, such as web browsers, or
# with potential internet sources, such as email.
#
##
# DISCUSSION: 
# Using applications that access the internet or have potential internet sources using administrative privileges
# exposes a system to compromise. If a flaw in an application is exploited while running as a privileged user,
# the entire system could be compromised. Web browsers and email are common attack vectors for introducing
# malicious code and must not be run with an administrative account.
#
# Since administrative accounts may generally change or work around technical restrictions for running a web
# browser or other applications, it is essential that policy requires administrative accounts to not access the
# internet or use applications, such as email.
#
# The policy must define specific exceptions for local service administration. These exceptions may include
# HTTP(S)-based tools that are used for the administration of the local system, services, or attached devices.
#
# Technical means such as application allowlisting can be used to enforce the policy to ensure compliance.
#
##
# CHECK: 
# Determine whether administrative accounts are prevented from using applications that access the internet, such
# as web browsers, or with potential internet sources, such as email, except as necessary for local service
# administration.
#
# The organization must have a policy that prohibits administrative accounts from using applications that access
# the internet, such as web browsers, or with potential internet sources, such as email, except as necessary for
# local service administration. The policy must define specific exceptions for local service administration.
# These exceptions may include HTTP(S)-based tools that are used for the administration of the local system,
# services, or attached devices.
#
# Technical measures such as the removal of applications or application allowlisting must be used where feasible
# to prevent the use of applications that access the internet. 
#
# If accounts with administrative privileges are not prevented from using applications that access the internet
# or with potential internet sources, this is a finding.
#
##
# FIX: 
# Establish and enforce a policy that prohibits administrative accounts from using applications that access the
# internet, such as web browsers, or with potential internet sources, such as email. Define specific exceptions
# for local service administration. These exceptions may include HTTP(S)-based tools that are used for the
# administration of the local system, services, or attached devices.
#
# Implement technical measures where feasible such as removal of applications or use of application allowlisting
# to restrict the use of applications that can access the internet.
#
##
# SEVERITY: CAT I
# RULE ID: SV-253294r828966_rule
# STIG ID: WN11-00-000240
# W10 ID: V-220737
# REFERENCE: 
##
$V253294 = $true


##
# V-253305
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
# RULE ID: SV-253305r877397_rule
# STIG ID: WN11-AC-000045
# W10 ID: V-220747
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name EnablePlainTextPassword -ErrorAction Stop) -eq 0) {
        $V253305 = $true
    } else {
        $V253305 = $false
    }
} catch {
    $V253305 = $false
}

##
# V-253370
# Credential Guard must be running on Windows 11 domain-joined systems.
#
##
# DISCUSSION: 
# Credential Guard uses virtualization-based security to protect information that could be used in credential
# theft attacks if compromised. This authentication information, which was stored in the Local Security
# Authority (LSA) in previous versions of Windows, is isolated from the rest of operating system and can only be
# accessed by privileged system software.
#
##
# CHECK: 
# Confirm Credential Guard is running on domain-joined systems.
#
# For those devices that support Credential Guard, this feature must be enabled. Organizations need to take the
# appropriate action to acquire and implement compatible hardware with Credential Guard enabled.
#
# Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# Run "PowerShell" with elevated privileges (run as administrator).
# Enter the following:
# "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard"
#
# If "SecurityServicesRunning" does not include a value of "1" (e.g., "{1, 2}"), this is a finding.
#
# Alternately:
#
# Run "System Information".
# Under "System Summary", verify the following:
# If "virtualization-based Services Running" does not list "Credential Guard", this is finding.
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
# Virtualization-based security, including Credential Guard, currently cannot be implemented in virtual desktop
# implementations (VDI) due to specific supporting requirements including a TPM, UEFI with Secure Boot, and the
# capability to run the Hyper-V feature within the virtual desktop.
#
# For VDIs where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# For VDIs with persistent desktops, this may be downgraded to a CAT II only where administrators have specific
# tokens for the VDI. Administrator accounts on virtual desktops must only be used on systems in the VDI; they
# may not have administrative privileges on any other systems such as servers and physical workstations.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Device Guard >>
# "Turn On virtualization-based Security" to "Enabled" with "Enabled with UEFI lock" selected for "Credential
# Guard Configuration:".
#
# A Microsoft TechNet article on Credential Guard, including system requirement details, can be found at the
# following link:
#
# https://docs.microsoft.com/en-us/windows/access-protection/credential-guard/credential-guard
#
##
# SEVERITY: CAT I
# RULE ID: SV-253370r829194_rule
# STIG ID: WN11-CC-000075
# W10 ID: V-220812
# REFERENCE: 
##
if ($DeviceGuard.SecurityServicesRunning -contains 1) {
    $V253370 = $true
} else {
    $V253370 = $false
}

##
# V-253382
# Solicited Remote Assistance must not be allowed.
#
##
# DISCUSSION: 
# Remote assistance allows another user to view or take control of the local session of a user. Solicited
# assistance is help that is specifically requested by the local user. This may allow unauthorized parties
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
# RULE ID: SV-253382r829230_rule
# STIG ID: WN11-CC-000155
# W10 ID: V-220823
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fAllowToGetHelp -ErrorAction Stop) -eq 0) {
        $V253382 = $true
    } else {
        $V253382 = $false
    }
} catch {
    $V253382 = $false
}


##
# V-253386
# Autoplay must be turned off for non-volume devices.
#
##
# DISCUSSION: 
# Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as
# soon as media is inserted in the drive. As a result, the setup file of programs or music on audio media may
# start. This setting will disable autoplay for non-volume devices (such as Media Transfer Protocol (MTP)
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
# RULE ID: SV-253386r829242_rule
# STIG ID: WN11-CC-000180
# W10 ID: V-220827
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoAutoplayfornonVolume -ErrorAction Stop) -eq 1) {
        $V253386 = $true
    } else {
        $V253386 = $false
    }
} catch {
    $V253386 = $false
}


##
# V-253387
# The default autorun behavior must be configured to prevent autorun commands.
#
##
# DISCUSSION: 
# Allowing autorun commands to execute may introduce malicious code to a system. Configuring this setting
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
# RULE ID: SV-253387r829245_rule
# STIG ID: WN11-CC-000185
# W10 ID: V-220828
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoAutorun -ErrorAction Stop) -eq 1) {
        $V253387 = $true
    } else {
        $V253387 = $false
    }
} catch {
    $V253387 = $false
}


##
# V-253388
# Autoplay must be disabled for all drives.
#
##
# DISCUSSION: 
# Allowing autoplay to execute may introduce malicious code to a system. Autoplay begins reading from a drive as
# soon as media is inserted in the drive. As a result, the setup file of programs or music on audio media may
# start. By default, autoplay is disabled on removable drives, such as the floppy disk drive (but not the CD-ROM
# drive) and on network drives. If this policy is enabled, autoplay can be disabled on all drives.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\
#
# Value Name: NoDriveTypeAutoRun
#
# Value Type: REG_DWORD
# Value: 0x000000ff (255)
#
# Note: If the value for NoDriveTypeAutorun is entered manually, it must be entered as "ff" when Hexadecimal is
# selected, or "255" with Decimal selected. Using the policy value specified in the Fix section will enter it
# correctly.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# AutoPlay Policies >> "Turn off AutoPlay" to "Enabled:All Drives".
#
##
# SEVERITY: CAT I
# RULE ID: SV-253388r829248_rule
# STIG ID: WN11-CC-000190
# W10 ID: V-220829
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" -Name NoDriveTypeAutoRun -ErrorAction Stop) -eq 255) {
        $V253388 = $true
    } else {
        $V253388 = $false
    }
} catch {
    $V253388 = $false
}


##
# V-253411
# The Windows Installer feature "Always install with elevated privileges" must be disabled.
#
##
# DISCUSSION: 
# Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate
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
# RULE ID: SV-253411r829317_rule
# STIG ID: WN11-CC-000315
# W10 ID: V-220857
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name AlwaysInstallElevated -ErrorAction Stop) -eq 0) {
        $V253411 = $true
    } else {
        $V253411 = $false
    }
} catch {
    $V253411 = $false
}


##
# V-253416
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
# RULE ID: SV-253416r877395_rule
# STIG ID: WN11-CC-000330
# W10 ID: V-220862
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowBasic -ErrorAction Stop) -eq 0) {
        $V253416 = $true
    } else {
        $V253416 = $false
    }
} catch {
    $V253416 = $false
}


##
# V-253418
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
# RULE ID: SV-253418r877395_rule
# STIG ID: WN11-CC-000345
# W10 ID: V-220865
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowBasic -ErrorAction Stop) -eq 0) {
        $V253418 = $true
    } else {
        $V253418 = $false
    }
} catch {
    $V253418 = $false
}


##
# V-253452
# Anonymous SID/Name translation must not be allowed.
#
##
# DISCUSSION: 
# Allowing anonymous SID/Name translation can provide sensitive information for accessing a system. Only
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
# RULE ID: SV-253452r829440_rule
# STIG ID: WN11-SO-000140
# W10 ID: V-220928
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'System Access'.LSAAnonymousNameLookup -eq 0) {
        $V253452 = $true
    } else {
        $V253452 = $false
    }
} catch {
    $V253452 = $false
}

##
# V-253453
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
# RULE ID: SV-253453r829443_rule
# STIG ID: WN11-SO-000145
# W10 ID: V-220929
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymousSAM -ErrorAction Stop) -eq 1) {
        $V253453 = $true
    } else {
        $V253453 = $false
    }
} catch {
    $V253453 = $false
}


##
# V-253454
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
# RULE ID: SV-253454r829446_rule
# STIG ID: WN11-SO-000150
# W10 ID: V-220930
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictAnonymous -ErrorAction Stop) -eq 1) {
        $V253454 = $true
    } else {
        $V253454 = $false
    }
} catch {
    $V253454 = $false
}


##
# V-253456
# Anonymous access to Named Pipes and Shares must be restricted.
#
##
# DISCUSSION: 
# Allowing anonymous access to named pipes or shares provides the potential for unauthorized system access. This
# setting restricts access to those defined in "Network access: Named Pipes that can be accessed anonymously"
# and "Network access: Shares that can be accessed anonymously", both of which must be blank under other
# requirements.
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
# RULE ID: SV-253456r829452_rule
# STIG ID: WN11-SO-000165
# W10 ID: V-220932
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RestrictNullSessAccess -ErrorAction Stop) -eq 1) {
        $V253456 = $true
    } else {
        $V253456 = $false
    }
} catch {
    $V253456 = $false
}


##
# V-253461
# The system must be configured to prevent the storage of the LAN Manager hash of passwords.
#
##
# DISCUSSION: 
# The LAN Manager hash uses a weak encryption algorithm and there are several tools available that use this hash
# to retrieve account passwords. This setting controls whether or not a LAN Manager hash of the password is
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
# RULE ID: SV-253461r877397_rule
# STIG ID: WN11-SO-000195
# W10 ID: V-220937
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name NoLMHash -ErrorAction Stop) -eq 1) {
        $V253461 = $true
    } else {
        $V253461 = $false
    }
} catch {
    $V253461 = $false
}


##
# V-253462
# The LanMan authentication level must be set to send NTLMv2 response only, and to refuse LM and NTLM.
#
##
# DISCUSSION: 
# The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to
# domain accounts. NTLM, which is less secure, is retained in later Windows versions for compatibility with
# clients and servers that are running earlier versions of Windows or applications that still use it. It is also
# used to authenticate logons to stand-alone computers that are running later versions.
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
# RULE ID: SV-253462r829470_rule
# STIG ID: WN11-SO-000205
# W10 ID: V-220938
# REFERENCE: 
##

try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LmCompatibilityLevel -ErrorAction Stop) -eq 5) {
        $V253462 = $true
    } else {
        $V253462 = $false
    }
} catch {
    $V253462 = $false
}


##
# V-253481
# The "Act as part of the operating system" user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# Accounts with the "Act as part of the operating system" user right can assume the identity of any user and
# gain access to resources that user is authorized to access. Any accounts with this right can take complete
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
# RULE ID: SV-253481r877392_rule
# STIG ID: WN11-UR-000015
# W10 ID: V-220958
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeTcbPrivilege -eq $null) {
        $V253481 = $true
    } else {
        $V253481 = $false
    }
} catch {
    $V253481 = $false
}

##
# V-253486
# The "Create a token object" user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
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
# RULE ID: SV-253486r877392_rule
# STIG ID: WN11-UR-000045
# W10 ID: V-220963
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeCreateTokenPrivilege -eq $null) {
        $V253486 = $true
    } else {
        $V253486 = $false
    }
} catch {
    $V253486 = $false
}

##
# V-253490
# The "Debug programs" user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# Accounts with the "Debug Programs" user right can attach a debugger to any process or to the kernel, providing
# complete access to sensitive and critical operating system components. This right is given to Administrators
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
# RULE ID: SV-253490r877392_rule
# STIG ID: WN11-UR-000065
# W10 ID: V-220967
# REFERENCE: 
##
try {
    $V253490 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V253490 = $false
        }
    }
} catch {
    $V253490 = $false
}

$hash = [ordered]@{
    'V-253263 - OS Supported Servicing Level' = $V253263
    'V-253264 - Use Anti-virus' = $V253264
    'V-253265 - Local Volumes formatted NTFS' = $V253265
    'V-253269 - Limit Administrator Rights' = $V253269
    'V-253275 - No IIS Installed' = $V253275
    'V-253283 - Configure DEP OptOut' = $V253283
    'V-253284 - Enable SEHOP' = $V253284
    'V-253294-NoChk - Limit Administrative Account Internet Access' = $V253294
    'V-253305 - Disable Reversible PW Encryption' = $V253305
    'V-253370 - Enable Credential Guard' = $V253370
    'V-253382 - Disable Solicited Remote Assistance' = $V253382
    'V-253386 - Disable Autoplay for non-Volume Devices' = $V253386
    'V-253387 - Disable Autorun' = $V253387
    'V-253388 - Disable Autoplay for All Drives' = $V253388
    'V-253411 - Disable Windows Installer Always Install Elevated' = $V253411
    'V-253416 - Disable Basic Authentication for WinRM Client' = $V253416
    'V-253418 - Disable Basic Authentication for WinRM Server' = $V253418
    'V-253452 - Disable Anonymous SID/Name Translation' = $V253452
    'V-253453 - Disable Anonymous Enumeration of SAM Accounts' = $V253453
    'V-253454 - Restrict Anonymous Enumeration of Shares' = $V253454
    'V-253456 - Restrict Anonymous Access to Named Pipes and Shares' = $V253456
    'V-253461 - Disable Storage of LM Hash Passwords' = $V253461
    'V-253462 - Configure LM Authentication to NTLMv2 and Refust LM and NTLM' = $V253462
    'V-253481 - Restrict Right - Act as Part of the OS' = $V253481
    'V-253486 - Restrict Right - Create a Token Object' = $V253486
    'V-253490 - Restrict Right - Debug Programs' = $V253490
}

return $hash | ConvertTo-Json -Compress
