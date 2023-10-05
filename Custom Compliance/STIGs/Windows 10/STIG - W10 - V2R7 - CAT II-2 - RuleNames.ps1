##
# Microsoft Windows 10 Security Technical Implementation Guide
# Version: 2, Release: 7 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
# Files created: 10/5/2023 12:32:57 PM
##


#
# Gather/set data used across multiple rule checks
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
# V-220792
# Camera access from the lock screen must be disabled.
#
##
# DISCUSSION: 
# Enabling camera access from the lock screen could allow for unauthorized use.  Requiring logon will ensure the
# device is only used by authorized personnel.
#
##
# CHECK: 
# If the device does not have a camera, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\
#
# Value Name: NoLockScreenCamera
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# If the device does not have a camera, this is NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >>
# Personalization >> "Prevent enabling lock screen camera" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220792r569187_rule
# STIG ID: WN10-CC-000005
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenCamera -ErrorAction Stop) -eq 1) {
        $V220792 = $true
    } else {
        $V220792 = $false
    }
} catch {
    $V220792 = $false
}


##
# V-220793
# Windows 10 must cover or disable the built-in or attached camera when not in use.
#
##
# DISCUSSION: 
# It is detrimental for operating systems to provide, or install by default, functionality exceeding
# requirements or mission objectives. These unnecessary capabilities or services are often overlooked and
# therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
#
# Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent
# compromises of organizational information. Providing easy methods to physically disconnect from such devices
# after a collaborative computing session helps to ensure that participants actually carry out the disconnect
# activity without having to go through complex and tedious procedures.
#
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
#
##
# CHECK: 
# If the device or operating system does not have a camera installed, this requirement is not applicable.
#
# This requirement is not applicable to mobile devices (smartphones and tablets) where the use of the camera is
# a local AO decision.
#
# This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are
# centrally managed.
#
# For an external camera, if there is not a method for the operator to manually disconnect the camera at the end
# of collaborative computing sessions, this is a finding.
#
# For a built-in camera, the camera must be protected by a camera cover (e.g., laptop camera cover slide) when
# not in use. 
#
# If the built-in camera is not protected with a camera cover, or if the built-in camera is not disabled in the
# bios, this is a finding.
#
# If the camera is not disconnected or covered, the following registry entry is required:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# RegistryPath\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
#
# Value Name: Value
# Value Data: Deny
#
# If "Value" is set to a value other than "Deny" and the collaborative computing device has not been authorized
# for use, this is a finding.
#
##
# FIX: 
# If the camera is not disconnected or covered, the following registry entry is required:
#  
# Registry Hive: HKEY_LOCAL_MACHINE
# RegistryPath\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
#
# Value Name: Value
# Value Data: Deny
#
##
# SEVERITY: CAT II
# RULE ID: SV-220793r819667_rule
# STIG ID: WN10-CC-000007
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name Value -ErrorAction Stop) -eq "Deny") {
        $V220793 = $true
    } else {
        $V220793 = $false
    }
} catch {
    $V220793 = $false
}

##
# V-220794
# The display of slide shows on the lock screen must be disabled.
#
##
# DISCUSSION: 
# Slide shows that are displayed on the lock screen could display sensitive information to unauthorized
# personnel.  Turning off this feature will limit access to the information to a logged on user.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\
#
# Value Name: NoLockScreenSlideshow
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >>
# Personalization >> "Prevent enabling lock screen slide show" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220794r569187_rule
# STIG ID: WN10-CC-000010
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenSlideshow -ErrorAction Stop) -eq 1) {
        $V220794 = $true
    } else {
        $V220794 = $false
    }
} catch {
    $V220794 = $false
}


##
# V-220795
# IPv6 source routing must be configured to highest protection.
#
##
# DISCUSSION: 
# Configuring the system to disable IPv6 source routing protects against spoofing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
#
# Value Name: DisableIpSourceRouting
#
# Value Type: REG_DWORD
# Value: 2
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to
# "Highest protection, source routing is completely disabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220795r569187_rule
# STIG ID: WN10-CC-000020
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -ErrorAction Stop) -eq 2) {
        $V220795 = $true
    } else {
        $V220795 = $false
    }
} catch {
    $V220795 = $false
}


##
# V-220796
# The system must be configured to prevent IP source routing.
#
##
# DISCUSSION: 
# Configuring the system to disable IP source routing protects against spoofing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
#
# Value Name: DisableIPSourceRouting
#
# Value Type: REG_DWORD
# Value: 2
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest
# protection, source routing is completely disabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220796r569187_rule
# STIG ID: WN10-CC-000025
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIPSourceRouting -ErrorAction Stop) -eq 2) {
        $V220796 = $true
    } else {
        $V220796 = $false
    }
} catch {
    $V220796 = $false
}


##
# V-220799
# Local administrator accounts must have their privileged token filtered to prevent elevated privileges from
# being used over the network on domain systems.
#
##
# DISCUSSION: 
# A compromised local administrator account can provide means for an attacker to move laterally between domain
# systems.
#
# With User Account Control enabled, filtering the privileged token for built-in administrator accounts will
# prevent the elevated privileges of these accounts from being used over the network.
#
##
# CHECK: 
# If the system is not a member of a domain, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: LocalAccountTokenFilterPolicy
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Apply UAC restrictions to local accounts on network logons" to "Enabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220799r569187_rule
# STIG ID: WN10-CC-000037
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -ErrorAction Stop) -eq 0) {
        $V220799 = $true
    } else {
        $V220799 = $false
    }
} catch {
    $V220799 = $false
}


##
# V-220800
# WDigest Authentication must be disabled.
#
##
# DISCUSSION: 
# When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security
# Authority Subsystem Service (LSASS) exposing them to theft.  WDigest is disabled by default in Windows 10. 
#  This setting ensures this is enforced.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
#
# Value Name: UseLogonCredential
#
# Type: REG_DWORD
# Value:  0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "WDigest Authentication (disabling may require KB2871997)" to "Disabled".
#
# The patch referenced in the policy title is not required for Windows 10.
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220800r569187_rule
# STIG ID: WN10-CC-000038
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -ErrorAction Stop) -eq 0) {
        $V220800 = $true
    } else {
        $V220800 = $false
    }
} catch {
    $V220800 = $false
}


##
# V-220801
# Run as different user must be removed from context menus.
#
##
# DISCUSSION: 
# The "Run as different user" selection from context menus allows the use of credentials other than the
# currently logged on user.  Using privileged credentials in a standard user session can expose those
# credentials to theft.  Removing this option from context menus helps prevent this from occurring.
#
##
# CHECK: 
# If the following registry values do not exist or are not configured as specified, this is a finding.
# The policy configures the same Value Name, Type and Value under four different registry paths.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Paths:  
# \SOFTWARE\Classes\batfile\shell\runasuser\
# \SOFTWARE\Classes\cmdfile\shell\runasuser\
# \SOFTWARE\Classes\exefile\shell\runasuser\
# \SOFTWARE\Classes\mscfile\shell\runasuser\
#
# Value Name:  SuppressionPolicy
#
# Type:  REG_DWORD
# Value:  0x00001000 (4096)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Remove "Run as Different User" from context menus" to "Enabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220801r569187_rule
# STIG ID: WN10-CC-000039
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096) {
        $V220801 = $true
    } else {
        $V220801 = $false
    }
} catch {
    $V220801 = $false
}

##
# V-220802
# Insecure logons to an SMB server must be disabled.
#
##
# DISCUSSION: 
# Insecure guest logons allow unauthenticated access to shared folders.  Shared resources on a system must
# require authentication to establish proper access.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
#
# Value Name: AllowInsecureGuestAuth
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Lanman
# Workstation >> "Enable insecure guest logons" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220802r569187_rule
# STIG ID: WN10-CC-000040
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -ErrorAction Stop) -eq 0) {
        $V220802 = $true
    } else {
        $V220802 = $false
    }
} catch {
    $V220802 = $false
}


##
# V-220803
# Internet connection sharing must be disabled.
#
##
# DISCUSSION: 
# Internet connection sharing makes it possible for an existing internet connection, such as through wireless,
# to be shared and used by other systems essentially creating a mobile hotspot.  This exposes the system sharing
# the connection to others with potentially malicious purpose.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Network Connections\
#
# Value Name: NC_ShowSharedAccessUI
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network
# Connections >> "Prohibit use of Internet Connection Sharing on your DNS domain network" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220803r569187_rule
# STIG ID: WN10-CC-000044
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -ErrorAction Stop) -eq 0) {
        $V220803 = $true
    } else {
        $V220803 = $false
    }
} catch {
    $V220803 = $false
}


##
# V-220805
# Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
#
##
# DISCUSSION: 
# Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.
# By default Windows uses ECC curves with shorter key lengths first.  Requiring ECC curves with longer key
# lengths to be prioritized first helps ensure more secure algorithms are used.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
#
# Value Name: EccCurves
#
# Value Type: REG_MULTI_SZ
# Value: NistP384 NistP256
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> SSL
# Configuration Settings >> "ECC Curve Order" to "Enabled" with "ECC Curve Order:" including the following in
# the order listed:
#
# NistP384
# NistP256
#
##
# SEVERITY: CAT II
# RULE ID: SV-220805r569187_rule
# STIG ID: WN10-CC-000052
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\" -Name EccCurves -ErrorAction Stop) -eq "NistP384 NistP256") {
        $V220805 = $true
    } else {
        $V220805 = $false
    }
} catch {
    $V220805 = $false
}

##
# V-220806
# Simultaneous connections to the internet or a Windows domain must be limited.
#
##
# DISCUSSION: 
# Multiple network connections can provide additional attack vectors to a system and must be limited. The
# "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems
# from automatically establishing multiple connections. When both wired and wireless connections are available,
# for example, the less-preferred connection (typically wireless) will be disconnected.
#
##
# CHECK: 
# The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
# is "Enabled".
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "3", this is not a finding.
#
# If it exists and is configured with a value of "0", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
#
# Value Name: fMinimizeConnections
#
# Value Type: REG_DWORD
# Value: 3 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
# is "Enabled".
#
# If this must be corrected, configure the policy value for Computer Configuration >> Administrative Templates
# >> Network >> Windows Connection Manager >> "Minimize the number of simultaneous connections to the Internet
# or a Windows Domain" to "Enabled". 
#
# Under "Options", set "Minimize Policy Options" to "3 = Prevent Wi-Fi When on Ethernet".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220806r890427_rule
# STIG ID: WN10-CC-000055
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 3) {
        $V220806 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 0) {
        $V220806 = $false
    } else {
        $V220806 = $false
    }
} catch {
    $V220806 = $true
}

##
# V-220807
# Connections to non-domain networks when connected to a domain authenticated network must be blocked.
#
##
# DISCUSSION: 
# Multiple network connections can provide additional attack vectors to a system and should be limited.  When
# connected to a domain, communication must go through the domain connection.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
#
# Value Name: fBlockNonDomain
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows
# Connection Manager >> "Prohibit connection to non-domain networks when connected to domain authenticated
# network" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220807r569187_rule
# STIG ID: WN10-CC-000060
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fBlockNonDomain -ErrorAction Stop) -eq 1) {
        $V220807 = $true
    } else {
        $V220807 = $false
    }
} catch {
    $V220807 = $false
}


##
# V-220808
# Wi-Fi Sense must be disabled.
#
##
# DISCUSSION: 
# Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared.  It
# also allows the sharing of the system's known networks to contacts.  Automatically connecting to hotspots and
# shared networks can expose a system to unsecured or potentially malicious systems.
#
##
# CHECK: 
# This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\
#
# Value Name: AutoConnectAllowedOEM
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> WLAN Service
# >> WLAN Settings>> "Allow Windows to automatically connect to suggested open hotspots, to networks shared by
# contacts, and to hotspots offering paid services" to "Disabled".   
#
# v1507 LTSB does not include this group policy setting.  It may be configured through other means such as using
# group policy from a later version of Windows 10 or a registry update.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220808r569187_rule
# STIG ID: WN10-CC-000065
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\" -Name AutoConnectAllowedOEM -ErrorAction Stop) -eq 0) {
        $V220808 = $true
    } else {
        $V220808 = $false
    }
} catch {
    $V220808 = $false
}


##
# V-220809
# Command line data must be included in process creation events.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Enabling "Include command line data for process creation events" will record the command line information with
# the process creation events in the log.  This can provide additional detail when malware has run on a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE 
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
#
# Value Name: ProcessCreationIncludeCmdLine_Enabled
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Audit Process
# Creation >> "Include command line in process creation events" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220809r569187_rule
# STIG ID: WN10-CC-000066
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction Stop) -eq 1) {
        $V220809 = $true
    } else {
        $V220809 = $false
    }
} catch {
    $V220809 = $false
}


##
# V-220810
# Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials.
#
##
# DISCUSSION: 
# An exportable version of credentials is provided to remote hosts when using credential delegation which
# exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation
# of non-exportable credentials providing additional protection of the credentials.  Enabling this configures
# the host to support Restricted Admin mode or Remote Credential Guard.
#
##
# CHECK: 
# This is NA for Windows 10 LTSC\B versions 1507 and 1607.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
#
# Value Name: AllowProtectedCreds
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials
# Delegation >> "Remote host allows delegation of non-exportable credentials" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220810r569187_rule
# STIG ID: WN10-CC-000068
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -ErrorAction Stop) -eq 1) {
        $V220810 = $true
    } else {
        $V220810 = $false
    }
} catch {
    $V220810 = $false
}


##
# V-220813
# Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.
#
##
# DISCUSSION: 
# By being launched first by the kernel, ELAM ( Early Launch Antimalware) is ensured to be launched before any
# third-party software, and is therefore able to detect malware in the boot process and prevent it from
# initializing.
#
##
# CHECK: 
# The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce
# "Good, unknown and bad but critical" (preventing "bad").
#
# If the registry value name below does not exist, this a finding.
#
# If it exists and is configured with a value of "7", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
#
# Value Name: DriverLoadPolicy
#
# Value Type: REG_DWORD
# Value: 1, 3, or 8 
#
# Possible values for this setting are:
# 8 - Good only
# 1 - Good and unknown
# 3 - Good, unknown and bad but critical
# 7 - All (which includes "Bad" and would be a finding)
#
##
# FIX: 
# Ensure that Early Launch Antimalware - Boot-Start Driver Initialization policy is set to enforce "Good,
# unknown and bad but critical" (preventing "bad").
#
# If this needs to be corrected configure the policy value for Computer Configuration >> Administrative
# Templates >> System >> Early Launch Antimalware >> "Boot-Start Driver Initialization Policy" to "Enabled" with
# "Good, unknown and bad but critical" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220813r569187_rule
# STIG ID: WN10-CC-000085
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -in @(1,3,8)) {
        $V220813 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -eq 7) {
        $V220813 = $false
    } else {
        $V220813 = $false
    }
} catch {
    $V220813 = $false
}

##
# V-220814
# Group Policy objects must be reprocessed even if they have not changed.
#
##
# DISCUSSION: 
# Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed"
# option ensures that the policies will be reprocessed even if none have been changed. This way, any
# unauthorized changes are forced to match the domain-based group policy settings again.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
#
# Value Name: NoGPOListChanges
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >>
# "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy
# objects have not changed".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220814r569187_rule
# STIG ID: WN10-CC-000090
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges -ErrorAction Stop) -eq 0) {
        $V220814 = $true
    } else {
        $V220814 = $false
    }
} catch {
    $V220814 = $false
}


##
# V-220815
# Downloading print driver packages over HTTP must be prevented.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents the computer from
# downloading print driver packages over HTTP.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\
#
# Value Name: DisableWebPnPDownload
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off downloading of print drivers over
# HTTP" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220815r569187_rule
# STIG ID: WN10-CC-000100
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -ErrorAction Stop) -eq 1) {
        $V220815 = $true
    } else {
        $V220815 = $false
    }
} catch {
    $V220815 = $false
}


##
# V-220816
# Web publishing and online ordering wizards must be prevented from downloading a list of providers.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents Windows from downloading
# a list of providers for the Web publishing and online ordering wizards.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
#
# Value Name: NoWebServices
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off Internet download for Web publishing
# and online ordering wizards" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220816r569187_rule
# STIG ID: WN10-CC-000105
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -ErrorAction Stop) -eq 1) {
        $V220816 = $true
    } else {
        $V220816 = $false
    }
} catch {
    $V220816 = $false
}


##
# V-220817
# Printing over HTTP must be prevented.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents the client computer from
# printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\
#
# Value Name: DisableHTTPPrinting
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off printing over HTTP" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220817r569187_rule
# STIG ID: WN10-CC-000110
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableHTTPPrinting -ErrorAction Stop) -eq 1) {
        $V220817 = $true
    } else {
        $V220817 = $false
    }
} catch {
    $V220817 = $false
}


##
# V-220818
# Systems must at least attempt device authentication using certificates.
#
##
# DISCUSSION: 
# Using certificates to authenticate devices to the domain provides increased security over passwords.  By
# default systems will attempt to authenticate using certificates and fall back to passwords if the domain
# controller does not support certificates for devices.  This may also be configured to always use certificates
# for device authentication.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# The default behavior for "Support device authentication using certificate" is "Automatic".
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "1", this is not a finding.
#
# If it exists and is configured with a value of "0", this is a finding.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
#
# Value Name:  DevicePKInitEnabled
# Value Type:  REG_DWORD
# Value:  1 (or if the Value Name does not exist)
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# The default behavior for "Support device authentication using certificate" is "Automatic".
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> System >> Kerberos >> "Support device authentication using certificate" to "Not Configured or
# "Enabled" with either option selected in "Device authentication behavior using certificate:".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220818r857191_rule
# STIG ID: WN10-CC-000115
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -ErrorAction Stop) -eq 1) {
        $V220818 = $true
    } else {
        $V220818 = $false
    }
} catch {
    $V220818 = $false
}


##
# V-220819
# The network selection user interface (UI) must not be displayed on the logon screen.
#
##
# DISCUSSION: 
# Enabling interaction with the network selection UI allows users to change connections to available networks
# without signing into Windows.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: DontDisplayNetworkSelectionUI
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Do
# not display network selection UI" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220819r569187_rule
# STIG ID: WN10-CC-000120
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name DontDisplayNetworkSelectionUI -ErrorAction Stop) -eq 1) {
        $V220819 = $true
    } else {
        $V220819 = $false
    }
} catch {
    $V220819 = $false
}


##
# V-220820
# Local users on domain-joined computers must not be enumerated.
#
##
# DISCUSSION: 
# The username is one part of logon credentials that could be used to gain access to a system. Preventing the
# enumeration of users limits this information to authorized personnel.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnumerateLocalUsers
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >>
# "Enumerate local users on domain-joined computers" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220820r857194_rule
# STIG ID: WN10-CC-000130
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnumerateLocalUsers -ErrorAction Stop) -eq 0) {
        $V220820 = $true
    } else {
        $V220820 = $false
    }
} catch {
    $V220820 = $false
}


##
# V-220821
# Users must be prompted for a password on resume from sleep (on battery).
#
##
# DISCUSSION: 
# Authentication must always be required when accessing a system.  This setting ensures the user is prompted for
# a password on resume from sleep (on battery).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#
# Value Name: DCSettingIndex
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power
# Management >> Sleep Settings >> "Require a password when a computer wakes (on battery)" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220821r851986_rule
# STIG ID: WN10-CC-000145
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name DCSettingIndex -ErrorAction Stop) -eq 1) {
        $V220821 = $true
    } else {
        $V220821 = $false
    }
} catch {
    $V220821 = $false
}


##
# V-220822
# The user must be prompted for a password on resume from sleep (plugged in).
#
##
# DISCUSSION: 
# Authentication must always be required when accessing a system.  This setting ensures the user is prompted for
# a password on resume from sleep (plugged in).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#
# Value Name: ACSettingIndex
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power
# Management >> Sleep Settings >> "Require a password when a computer wakes (plugged in)" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220822r851987_rule
# STIG ID: WN10-CC-000150
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -ErrorAction Stop) -eq 1) {
        $V220822 = $true
    } else {
        $V220822 = $false
    }
} catch {
    $V220822 = $false
}


##
# V-220824
# Unauthenticated RPC clients must be restricted from connecting to the RPC server.
#
##
# DISCUSSION: 
# Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent
# anonymous connections.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\
#
# Value Name: RestrictRemoteClients
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote
# Procedure Call >> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220824r877039_rule
# STIG ID: WN10-CC-000165
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -ErrorAction Stop) -eq 1) {
        $V220824 = $true
    } else {
        $V220824 = $false
    }
} catch {
    $V220824 = $false
}


##
# V-220830
# Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
#
##
# DISCUSSION: 
# Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support
# it.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\
#
# Value Name: EnhancedAntiSpoofing
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled". 
#
# v1607:
# The policy name is "Use enhanced anti-spoofing when available".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220830r569187_rule
# STIG ID: WN10-CC-000195
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Name EnhancedAntiSpoofing -ErrorAction Stop) -eq 1) {
        $V220830 = $true
    } else {
        $V220830 = $false
    }
} catch {
    $V220830 = $false
}


##
# V-220832
# Administrator accounts must not be enumerated during elevation.
#
##
# DISCUSSION: 
# Enumeration of administrator accounts when elevating can provide part of the logon information to an
# unauthorized user.  This setting configures the system to always require users to type in a username and
# password to elevate a running application.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
#
# Value Name: EnumerateAdministrators
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220832r569187_rule
# STIG ID: WN10-CC-000200
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -ErrorAction Stop) -eq 0) {
        $V220832 = $true
    } else {
        $V220832 = $false
    }
} catch {
    $V220832 = $false
}


##
# V-220833
# If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows
# Analytics.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature. Limiting this capability will prevent potentially sensitive information from being sent
# outside the enterprise. The "Enhanced" level for telemetry includes additional information beyond "Security"
# and "Basic" on how Windows and apps are used and advanced reliability data. Windows Analytics can use a
# "limited enhanced" level to provide information such as health data for devices.
#
##
# CHECK: 
# This setting requires v1709 or later of Windows 10; it is NA for prior versions.
#
# If "Enhanced" level is enabled for telemetry, this must be configured. If "Security" or "Basic" are
# configured, this is NA. (See V-220834).
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\
#
# Value Name: LimitEnhancedDiagnosticDataWindowsAnalytics
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Data Collection and Preview Builds >> "Limit Enhanced diagnostic data to the minimum required by Windows
# Analytics" to "Enabled" with "Enable Windows Analytics collection" selected in "Options:".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220833r793250_rule
# STIG ID: WN10-CC-000204
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2) {
        if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name LimitEnhancedDiagnosticDataWindowsAnalytics -ErrorAction Stop) -eq 1) {
            $V220833 = $true
        } else {
            $V220833 = $false
        }
    } else {
        $V220833 = $true
    }
} catch {
    $V220833 = $false
}

##
# V-220834
# Windows Telemetry must not be configured to Full.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature. Limiting this capability will prevent potentially sensitive information from being sent
# outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively
# none outside of the Malicious Software Removal Tool (MSRT), Defender and telemetry client settings. "Basic"
# sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced"
# includes additional information on how Windows and apps are used and advanced reliability data. Windows
# Analytics can use a "limited enhanced" level to provide information such as health data for devices.  This
# requires the configuration of an additional setting available with v1709 and later of Windows 10. 
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\
#
# Value Name: AllowTelemetry
#
# Type: REG_DWORD
# Value: 0x00000000 (0) (Security)
# 0x00000001 (1) (Basic)
#
# If an organization is using v1709 or later of Windows 10 this may be configured to "Enhanced" to support
# Windows Analytics. V-82145 must also be configured to limit the Enhanced diagnostic data to the minimum
# required by Windows Analytics. This registry value will then be 0x00000002 (2).
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Data Collection and Preview Builds >> "Allow Telemetry" to "Enabled" with "0 - Security [Enterprise Only]" or
# "1 - Basic" selected in "Options:".   
#
# If an organization is using v1709 or later of Windows 10 this may be configured to "2 - Enhanced" to support
# Windows Analytics. V-82145 must also be configured to limit the Enhanced diagnostic data to the minimum
# required by Windows Analytics.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220834r569187_rule
# STIG ID: WN10-CC-000205
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -in @(0,1)) {
        $V220834 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2 -and
              $V220833 -eq $true) {
        $V220834 = $true
    } else {
        $V220834 = $false
    }
} catch {
    $V220834 = $false
}

##
# V-220836
# The Windows Defender SmartScreen for Explorer must be enabled.
#
##
# DISCUSSION: 
# Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be
# malicious. Enabling Windows Defender SmartScreen will warn or prevent users from running potentially malicious
# programs.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# If the following registry values do not exist or are not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
# And
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: ShellSmartScreenLevel
#
# Value Type: REG_SZ
# Value: Block
#
# v1607 LTSB:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
# v1507 LTSB:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000002 (2)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows Defender SmartScreen" to "Enabled" with "Warn and prevent bypass"
# selected. 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Explorer.
#
# v1607 LTSB:
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows SmartScreen" to "Enabled". (Selection options are not available.)
#
# v1507 LTSB:
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows SmartScreen" to "Enabled" with "Require approval from an administrator
# before running downloaded unknown software" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220836r569187_rule
# STIG ID: WN10-CC-000210
# REFERENCE: 
##
try {
    if (($ComputerInfo.OsBuildNumber -eq $v1507) -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 2) {
        $V220836 = $true
    } elseif (($ComputerInfo.OsBuildNumber -eq $v1607) -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1) {
        $V220836 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1 -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name ShellSmartScreenLevel -ErrorAction Stop) -eq "Block") {
        $V220836 = $true
    } else {
        $V220836 = $false
    }
} catch {
    $V220836 = $false
}

##
# V-220837
# Explorer Data Execution Prevention must be enabled.
#
##
# DISCUSSION: 
# Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent
# malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for
# File Explorer.
#
##
# CHECK: 
# The default behavior is for data execution prevention to be turned on for file explorer.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
#
# Value Name: NoDataExecutionPrevention
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for data execution prevention to be turned on for file explorer.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> File Explorer >> "Turn off Data Execution Prevention for Explorer" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220837r851992_rule
# STIG ID: WN10-CC-000215
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -ErrorAction Stop) -eq 0) {
        $V220837 = $true
    } else {
        $V220837 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220837 = $true
} catch {
    $V220837 = $false
}

##
# V-220839
# File Explorer shell protocol must run in protected mode.
#
##
# DISCUSSION: 
# The shell protocol will  limit the set of folders applications can open when run in protected mode. 
#  Restricting files an application can open, to a limited set of folders, increases the security of Windows.
#
##
# CHECK: 
# The default behavior is for shell protected mode to be turned on for file explorer.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
#
# Value Name: PreXPSP2ShellProtocolBehavior
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for shell protected mode to be turned on for file explorer.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> File Explorer >> "Turn off shell protocol protected mode" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220839r569187_rule
# STIG ID: WN10-CC-000225
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -ErrorAction Stop) -eq 0) {
        $V220839 = $true
    } else {
        $V220839 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220839 = $true
} catch {
    $V220839 = $false
}

##
# V-220840
# Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in
# Microsoft Edge.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender
# SmartScreen filter they could still access malicious websites.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: PreventOverride
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for sites" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220840r569187_rule
# STIG ID: WN10-CC-000230
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220840 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverride -ErrorAction Stop) -eq 1) {
        $V220840 = $true
    } else {
        $V220840 = $false
    }
} catch {
    $V220840 = $false
}

##
# V-220841
# Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in
# Microsoft Edge.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender
# SmartScreen filter they could still download potentially malicious files.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: PreventOverrideAppRepUnknown
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for files" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220841r569187_rule
# STIG ID: WN10-CC-000235
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220841 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverrideAppRepUnknown -ErrorAction Stop) -eq 1) {
        $V220841 = $true
    } else {
        $V220841 = $false
    }
} catch {
    $V220841 = $false
}

##
# V-220842
# Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge.
#
##
# DISCUSSION: 
# Web security certificates provide an indication whether a site is legitimate. This policy setting prevents the
# user from ignoring Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt
# browsing.
#
##
# CHECK: 
# This setting is applicable starting with v1809 of Windows 10; it is NA for prior versions.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge; this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\
#
# Value Name: PreventCertErrorOverrides
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent certificate error overrides" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220842r569187_rule
# STIG ID: WN10-CC-000238
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220842 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\" -Name PreventCertErrorOverrides -ErrorAction Stop) -eq 1) {
        $V220842 = $true
    } else {
        $V220842 = $false
    }
} catch {
    $V220842 = $false
}

##
# V-220843
# The password manager function in the Edge browser must be disabled.
#
##
# DISCUSSION: 
# Passwords save locally for re-use when browsing may be subject to compromise.  Disabling the Edge password
# manager will prevent this for the browser.
#
##
# CHECK: 
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\
#
# Value Name: FormSuggest Passwords
#
# Type: REG_SZ
# Value: no
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Configure Password Manager" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220843r569187_rule
# STIG ID: WN10-CC-000245
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220843 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\" -Name FormSuggest Passwords -ErrorAction Stop) -eq "no") {
        $V220843 = $true
    } else {
        $V220843 = $false
    }
} catch {
    $V220843 = $false
}

##
# V-220844
# The Windows Defender SmartScreen filter for Microsoft Edge must be enabled.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: EnabledV9
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Configure Windows Defender SmartScreen" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220844r569187_rule
# STIG ID: WN10-CC-000250
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220844 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name EnabledV9 -ErrorAction Stop) -eq 1) {
        $V220844 = $true
    } else {
        $V220844 = $false
    }
} catch {
    $V220844 = $false
}

##
# V-220845
# Windows 10 must be configured to disable Windows Game Recording and Broadcasting.
#
##
# DISCUSSION: 
# Windows Game Recording and Broadcasting is intended for use with games, however it could potentially record
# screen shots of other applications and expose sensitive data.  Disabling the feature will prevent this from
# occurring.
#
##
# CHECK: 
# This is NA for Windows 10 LTSC\B versions 1507 and 1607.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\GameDVR\
#
# Value Name: AllowGameDVR
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting" to
# "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220845r569187_rule
# STIG ID: WN10-CC-000252
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in @($v1507, $v1607)) {
        $V220845 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\" -Name AllowGameDVR -ErrorAction Stop) -eq 0) {
        $V220845 = $true
    } else {
        $V220845 = $false
    }
} catch {
    $V220845 = $false
}

##
# V-220846
# The use of a hardware security device with Windows Hello for Business must be enabled.
#
##
# DISCUSSION: 
# The use of a Trusted Platform Module (TPM) to store keys for Windows Hello for Business provides additional
# security.  Keys stored in the TPM may only be used on that system while keys stored using software are more
# susceptible to compromise and could be used on other systems.
#
##
# CHECK: 
# Virtual desktop implementations currently may not support the use of TPMs. For virtual desktop implementations
# where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\PassportForWork\
#
# Value Name: RequireSecurityDevice
#
# Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Hello for Business >> "Use a hardware security device" to "Enabled". 
#
# v1507 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft
# Passport for Work.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220846r569187_rule
# STIG ID: WN10-CC-000255
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name RequireSecurityDevice -ErrorAction Stop) -eq 1) {
        $V220846 = $true
    } else {
        $V220846 = $false
    }
} catch {
    $V220846 = $false
}


##
# V-220847
# Windows 10 must be configured to require a minimum pin length of six characters or greater.
#
##
# DISCUSSION: 
# Windows allows the use of PINs as well as biometrics for authentication without sending a password to a
# network or website where it could be compromised.  Longer minimum PIN lengths increase the available
# combinations an attacker would have to attempt.  Shorter minimum length significantly reduces the strength.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\
#
# Value Name:  MinimumPINLength
#
# Type:  REG_DWORD
# Value:  6 (or greater)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> PIN Complexity
# >> "Minimum PIN length" to "6" or greater. 
#
# v1607 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Windows Hello
# for Business >> Pin Complexity.
#
# v1507 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft
# Passport for Work >> Pin Complexity.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220847r569187_rule
# STIG ID: WN10-CC-000260
# REFERENCE: 
##
try {
    if ($MinimumPIN) {
        $pin = $MinimumPIN
    } else {
        $pin = 6
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\" -Name MinimumPINLength -ErrorAction Stop) -ge $pin) {
        $V220847 = $true
    } else {
        $V220847 = $false
    }
} catch {
    $V220847 = $false
}

##
# V-220848
# Passwords must not be saved in the Remote Desktop Client.
#
##
# DISCUSSION: 
# Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop
# session to another system.  The system must be configured to prevent users from saving passwords in the Remote
# Desktop Client.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: DisablePasswordSaving
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Connection Client >> "Do not allow passwords to be saved" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220848r851994_rule
# STIG ID: WN10-CC-000270
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -ErrorAction Stop) -eq 1) {
        $V220848 = $true
    } else {
        $V220848 = $false
    }
} catch {
    $V220848 = $false
}


##
# V-220849
# Local drives must be prevented from sharing with Remote Desktop Session Hosts.
#
##
# DISCUSSION: 
# Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they
# access helps reduce possible exposure of sensitive data.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fDisableCdm
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection >> "Do not allow
# drive redirection" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220849r569187_rule
# STIG ID: WN10-CC-000275
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCdm -ErrorAction Stop) -eq 1) {
        $V220849 = $true
    } else {
        $V220849 = $false
    }
} catch {
    $V220849 = $false
}


##
# V-220850
# Remote Desktop Services must always prompt a client for passwords upon connection.
#
##
# DISCUSSION: 
# This setting controls the ability of users to supply passwords automatically as part of their remote desktop
# connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to
# connect to the terminal server.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fPromptForPassword
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon
# connection" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220850r851995_rule
# STIG ID: WN10-CC-000280
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -ErrorAction Stop) -eq 1) {
        $V220850 = $true
    } else {
        $V220850 = $false
    }
} catch {
    $V220850 = $false
}


##
# V-220851
# The Remote Desktop Session Host must require secure RPC communications.
#
##
# DISCUSSION: 
# Allowing unsecure RPC communication exposes the system to man in the middle attacks and data disclosure
# attacks. A man in the middle attack occurs when an intruder captures packets between a client and server and
# modifies them before allowing the packets to be exchanged. Usually the attacker will modify the information in
# the packets in an attempt to cause either the client or server to reveal sensitive information.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fEncryptRPCTraffic
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Security "Require secure RPC communication" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220851r877394_rule
# STIG ID: WN10-CC-000285
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fEncryptRPCTraffic -ErrorAction Stop) -eq 1) {
        $V220851 = $true
    } else {
        $V220851 = $false
    }
} catch {
    $V220851 = $false
}


##
# V-220852
# Remote Desktop Services must be configured with the client connection encryption set to the required level.
#
##
# DISCUSSION: 
# Remote connections must be encrypted to prevent interception of data or sensitive information. Selecting "High
# Level" will ensure encryption of Remote Desktop Services sessions in both directions.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: MinEncryptionLevel
#
# Value Type: REG_DWORD
# Value: 3
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Set client connection encryption level"
# to "Enabled" and "High Level".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220852r877398_rule
# STIG ID: WN10-CC-000290
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name MinEncryptionLevel -ErrorAction Stop) -eq 3) {
        $V220852 = $true
    } else {
        $V220852 = $false
    }
} catch {
    $V220852 = $false
}


##
# V-220853
# Attachments must be prevented from being downloaded from RSS feeds.
#
##
# DISCUSSION: 
# Attachments from RSS feeds may not be secure.  This setting will prevent attachments from being downloaded
# from RSS feeds.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\
#
# Value Name: DisableEnclosureDownload
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> RSS
# Feeds >> "Prevent downloading of enclosures" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220853r569187_rule
# STIG ID: WN10-CC-000295
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -Name DisableEnclosureDownload -ErrorAction Stop) -eq 1) {
        $V220853 = $true
    } else {
        $V220853 = $false
    }
} catch {
    $V220853 = $false
}


##
# V-220854
# Basic authentication for RSS feeds over HTTP must not be used.
#
##
# DISCUSSION: 
# Basic authentication uses plain text passwords that could be used to compromise a system.
#
##
# CHECK: 
# The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\
#
# Value Name: AllowBasicAuthInClear
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for the Windows RSS platform to not use Basic authentication over HTTP connections.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> RSS Feeds >> "Turn on Basic feed authentication over HTTP" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220854r569187_rule
# STIG ID: WN10-CC-000300
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\" -Name AllowBasicAuthInClear -ErrorAction Stop) -eq 0) {
        $V220854 = $true
    } else {
        $V220854 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220854 = $true
} catch {
    $V220854 = $false
}

##
# V-220855
# Indexing of encrypted files must be turned off.
#
##
# DISCUSSION: 
# Indexing of encrypted files may expose sensitive data.  This setting prevents encrypted files from being
# indexed.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Windows Search\
#
# Value Name: AllowIndexingEncryptedStoresOrItems
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Search >> "Allow indexing of encrypted files" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220855r569187_rule
# STIG ID: WN10-CC-000305
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\" -Name AllowIndexingEncryptedStoresOrItems -ErrorAction Stop) -eq 0) {
        $V220855 = $true
    } else {
        $V220855 = $false
    }
} catch {
    $V220855 = $false
}


##
# V-220856
# Users must be prevented from changing installation options.
#
##
# DISCUSSION: 
# Installation options for applications are typically controlled by administrators.  This setting prevents users
# from changing installation options that may bypass security features.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
#
# Value Name: EnableUserControl
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Installer >> "Allow user control over installs" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220856r851997_rule
# STIG ID: WN10-CC-000310
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name EnableUserControl -ErrorAction Stop) -eq 0) {
        $V220856 = $true
    } else {
        $V220856 = $false
    }
} catch {
    $V220856 = $false
}


##
# V-220858
# Users must be notified if a web-based program attempts to install software.
#
##
# DISCUSSION: 
# Web-based programs may attempt to install malicious software on a system.  Ensuring users are notified if a
# web-based program attempts to install software allows them to refuse the installation.
#
##
# CHECK: 
# The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation
# when a web-based program attempts to install software on the system.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Installer\
#
# Value Name: SafeForScripting
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for Internet Explorer to warn users and select whether to allow or refuse installation
# when a web-based program attempts to install software on the system.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> Windows Installer >> "Prevent Internet Explorer security prompt for Windows
# Installer scripts" to "Not Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220858r569187_rule
# STIG ID: WN10-CC-000320
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\" -Name SafeForScripting -ErrorAction Stop) -eq 0) {
        $V220858 = $true
    } else {
        $V220858 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220858 = $true
} catch {
    $V220858 = $false
}

##
# V-220859
# Automatically signing in the last interactive user after a system-initiated restart must be disabled.
#
##
# DISCUSSION: 
# Windows can be configured to automatically sign the user back in after a Windows Update restart.  Some
# protections are in place to help ensure this is done in a secure fashion; however, disabling this will prevent
# the caching of credentials for this purpose and also ensure the user is aware of the restart.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: DisableAutomaticRestartSignOn
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Logon Options >> "Sign-in last interactive user automatically after a system-initiated restart" to
# "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220859r877377_rule
# STIG ID: WN10-CC-000325
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name DisableAutomaticRestartSignOn -ErrorAction Stop) -eq 1) {
        $V220859 = $true
    } else {
        $V220859 = $false
    }
} catch {
    $V220859 = $false
}


##
# V-220860
# PowerShell script block logging must be enabled on Windows 10.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Enabling PowerShell script block logging will record detailed information from the processing of PowerShell
# commands and scripts.  This can provide additional detail when malware has run on a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE 
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
#
# Value Name: EnableScriptBlockLogging
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows PowerShell >> "Turn on PowerShell Script Block Logging" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220860r569187_rule
# STIG ID: WN10-CC-000326
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\" -Name EnableScriptBlockLogging -ErrorAction Stop) -eq 1) {
        $V220860 = $true
    } else {
        $V220860 = $false
    }
} catch {
    $V220860 = $false
}


##
# V-220861
# The Windows Explorer Preview pane must be disabled for Windows 10. 
#
##
# DISCUSSION: 
# A known vulnerability in Windows 10 could allow the execution of malicious code by either opening a
# compromised document or viewing it in the Windows Preview pane.
#
# Organizations must disable the Windows Preview pane and Windows Detail pane.
#
##
# CHECK: 
# If the following registry values do not exist or are not configured as specified, this is a finding:
#
# Registry Hive: HKEY_CURRENT_USER
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
#
# Value Name: NoPreviewPane
#
# Value Type: REG_DWORD
#
# Value: 1
#
# Registry Hive: HKEY_CURRENT_USER
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer
#
# Value Name: NoReadingPane
#
# Value Type: REG_DWORD
#
# Value: 1
#
##
# FIX: 
# Ensure the following settings are configured for Windows 10 locally or applied through group policy. 
#
# Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File
# Explorer >> Explorer Frame Pane "Turn off Preview Pane" to "Enabled".
#
# Configure the policy value for User Configuration >> Administrative Templates >> Windows Components >> File
# Explorer >> Explorer Frame Pane "Turn on or off details pane" to "Enabled" and "Configure details pane" to
# "Always hide".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220861r877377_rule
# STIG ID: WN10-CC-000328
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoPreviewPane -ErrorAction Stop) -eq 1 -and
        (Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoReadingPane -ErrorAction Stop) -eq 1) {
        $V220861 = $true
    } else {
        $V220861 = $false
    }
} catch {
    $V220861 = $false
}


##
# V-220863
# The Windows Remote Management (WinRM) client must not allow unencrypted traffic.
#
##
# DISCUSSION: 
# Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote
# management connections must be encrypted to prevent this.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
#
# Value Name: AllowUnencryptedTraffic
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Client >> "Allow unencrypted traffic" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220863r877382_rule
# STIG ID: WN10-CC-000335
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowUnencryptedTraffic -ErrorAction Stop) -eq 0) {
        $V220863 = $true
    } else {
        $V220863 = $false
    }
} catch {
    $V220863 = $false
}


##
# V-220866
# The Windows Remote Management (WinRM) service must not allow unencrypted traffic.
#
##
# DISCUSSION: 
# Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote
# management connections must be encrypted to prevent this.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
#
# Value Name: AllowUnencryptedTraffic
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Service >> "Allow unencrypted traffic" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220866r877382_rule
# STIG ID: WN10-CC-000350
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name AllowUnencryptedTraffic -ErrorAction Stop) -eq 0) {
        $V220866 = $true
    } else {
        $V220866 = $false
    }
} catch {
    $V220866 = $false
}


##
# V-220867
# The Windows Remote Management (WinRM) service must not store RunAs credentials.
#
##
# DISCUSSION: 
# Storage of administrative credentials could allow unauthorized access.  Disallowing the storage of RunAs
# credentials for Windows Remote Management will prevent them from being used with plug-ins.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\
#
# Value Name: DisableRunAs
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Service >> "Disallow WinRM from storing RunAs credentials" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220867r852001_rule
# STIG ID: WN10-CC-000355
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\" -Name DisableRunAs -ErrorAction Stop) -eq 1) {
        $V220867 = $true
    } else {
        $V220867 = $false
    }
} catch {
    $V220867 = $false
}


##
# V-220868
# The Windows Remote Management (WinRM) client must not use Digest authentication.
#
##
# DISCUSSION: 
# Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\
#
# Value Name: AllowDigest
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220868r877395_rule
# STIG ID: WN10-CC-000360
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\" -Name AllowDigest -ErrorAction Stop) -eq 0) {
        $V220868 = $true
    } else {
        $V220868 = $false
    }
} catch {
    $V220868 = $false
}


##
# V-220869
# Windows 10 must be configured to prevent Windows apps from being activated by voice while the system is
# locked.
#
##
# DISCUSSION: 
# Allowing Windows apps to be activated by voice from the lock screen could allow for unauthorized use.
# Requiring logon will ensure the apps are only used by authorized personnel.
#
##
# CHECK: 
# This setting requires v1903 or later of Windows 10; it is NA for prior versions.  The setting is NA when the
# "Allow voice activation" policy is configured to disallow applications to be activated with voice for all
# users.
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\
#
# Value Name: LetAppsActivateWithVoiceAboveLock
#
# Type: REG_DWORD
# Value: 0x00000002 (2)
#
# If the following registry value exists and is configured as specified, requirement is NA. 
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\
#
# Value Name: LetAppsActivateWithVoice
#
# Type: REG_DWORD
# Value: 0x00000002 (2)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> App
# Privacy >> "Let Windows apps activate with voice while the system is locked" to "Enabled" with "Default for
# all Apps:" set to "Force Deny". 
#
# The requirement is NA if the policy value for Computer Configuration >> Administrative Templates >> Windows
# Components >> App Privacy >> "Let Windows apps activate with voice" is configured to "Enabled" with "Default
# for all Apps:" set to "Force Deny".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220869r569187_rule
# STIG ID: WN10-CC-000365
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -ge "18362") {
        $V220869 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name LetAppsActivateWithVoice -ErrorAction Stop) -eq 2) {
        $V220869 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\" -Name LetAppsActivateWithVoiceAboveLock -ErrorAction Stop) -eq 2) {
        $V220869 = $true
    } else {
        $V220869 = $false
    }
} catch {
    $V220869 = $false
}

##
# V-220870
# The convenience PIN for Windows 10 must be disabled.  
#
##
# DISCUSSION: 
# This policy controls whether a domain user can sign in using a convenience PIN to prevent enabling (Password
# Stuffer).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \Software\Policies\Microsoft\Windows\System
#
# Value Name: AllowDomainPINLogon
# Value Type: REG_DWORD
# Value data: 0
#
##
# FIX: 
# Disable the convenience PIN sign-in. 
#
# If this needs to be corrected configure the policy value for Computer Configuration >> Administrative
# Templates >> System >> Logon >> Set "Turn on convenience PIN sign-in" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220870r569187_rule
# STIG ID: WN10-CC-000370
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\System" -Name AllowDomainPINLogon -ErrorAction Stop) -eq 0) {
        $V220870 = $true
    } else {
        $V220870 = $false
    }
} catch {
    $V220870 = $false
}

##
# V-220871
# Windows Ink Workspace must be configured to disallow access above the lock.  
#
##
# DISCUSSION: 
# This action secures Windows Ink, which contains applications and features oriented toward pen computing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \Software\Policies\Microsoft\WindowsInkWorkspace
#
# Value Name: AllowWindowsInkWorkspace
# Value Type: REG_DWORD
# Value data: 1
#
##
# FIX: 
# Disable the convenience PIN sign-in. 
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> Windows Ink Workspace >> Set "Allow Windows Ink Workspace" to "Enabled" and
# set Options "On, but disallow access above lock".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220871r642141_rule
# STIG ID: WN10-CC-000385
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace" -Name AllowWindowsInkWorkspace -ErrorAction Stop) -eq 1) {
        $V220871 = $true
    } else {
        $V220871 = $false
    }
} catch {
    $V220871 = $false
}


$hash = [ordered]@{
    'V-220792 - Disable Camera Access From Lockscreen' = $V220792
    'V-220793 - Disable or Cover Camera When Not In Use' = $V220793
    'V-220794 - Disable Lockscreen Slideshow' = $V220794
    'V-220795 - Configure IPv6 Routing' = $V220795
    'V-220796 - Configure Prevent IP Source Routing' = $V220796
    'V-220799 - Configure Local Account Token Filter' = $V220799
    'V-220800 - Disable WDigest Authentication' = $V220800
    'V-220801 - Remove Run as Different User from Context Menu' = $V220801
    'V-220802 - Disable Insecure Logons to SMB Server' = $V220802
    'V-220803 - Disable Internet Connection Sharing' = $V220803
    'V-220805 - Configure Prioritize ECC Curves' = $V220805
    'V-220806 - Limit Simultaneous Connections to Internet and Domain Network' = $V220806
    'V-220807 - Block non-Domain Networks when Connected to Domain Network' = $V220807
    'V-220808 - Disable Wi-fi Sense' = $V220808
    'V-220809 - Configure Include Command Line Data in Process Creation Events' = $V220809
    'V-220810 - Configure Allow Protected Creds' = $V220810
    'V-220813 - Prevent Boot Drivers' = $V220813
    'V-220814 - Configure Reprocess GPO' = $V220814
    'V-220815 - Disable HTTP Print Driver Download' = $V220815
    'V-220816 - Disable Download Web Publishing' = $V220816
    'V-220817 - Disable HTTP Printing' = $V220817
    'V-220818 - Configure Device Attempt Certificate Authentication' = $V220818
    'V-220819 - Disable Network Selection on Logon Screen' = $V220819
    'V-220820 - Disable Local User Enumeration' = $V220820
    'V-220821 - Configure Password Prompt on Resume from Sleep - On Battery' = $V220821
    'V-220822 - Configure Password Prompt on Resume from Sleep - Plugged In' = $V220822
    'V-220824 - Disable Unauthenticated RPC Clients from Connecting' = $V220824
    'V-220830 - Enable Enhanced Facial Anti-spoofing' = $V220830
    'V-220832 - Disable Administrator Account Enumeration' = $V220832
    'V-220833 - Configure Limit Diagnostic Data Collection' = $V220833
    'V-220834 - No Full Windows Telemetry' = $V220834
    'V-220836 - Enable Windows Defender SmartScreen for Explorer' = $V220836
    'V-220837 - Enable Explorer DEP' = $V220837
    'V-220839 - Configure File Explorer Run in Protected Mode' = $V220839
    'V-220840 - Disable Ability to Ignore SmartScreen Warning for Websites' = $V220840
    'V-220841 - Disable Ability to Ignore SmartScreen Warning for Files' = $V220841
    'V-220842 - Configure No Certificate Error Overrides in Edge' = $V220842
    'V-220843 - Disable Edge Password Manager' = $V220843
    'V-220844 - Enable SmartScreen for Edge' = $V220844
    'V-220845 - Disable GameDVR' = $V220845
    'V-220846 - Enable TPM for WHfB' = $V220846
    'V-220847 - Configure Windows Min PIN Length' = $V220847
    'V-220848 - Disable Password Saving in RD Client' = $V220848
    'V-220849 - Disable Sharing Local Drives with RDSH' = $V220849
    'V-220850 - Configure RDS to Always Prompt for Client Password' = $V220850
    'V-220851 - Configure RDSH Must Require Secure RPC' = $V220851
    'V-220852 - Configure RDS Client Connection Encryption' = $V220852
    'V-220853 - Disable Downloading Attachments from RSS' = $V220853
    'V-220854 - Disable Basic Authentication for RSS' = $V220854
    'V-220855 - Disable Indexing of Encrypted Files' = $V220855
    'V-220856 - Prevent User from Changing Installation Options' = $V220856
    'V-220858 - Configure User Notification if Web-based Program Attempts Installation' = $V220858
    'V-220859 - Disable Automatic Sign-on After Restart' = $V220859
    'V-220860 - Enable PowerShell Script Block Logging' = $V220860
    'V-220861 - Disable Windows Explorer Preview Pane' = $V220861
    'V-220863 - Disable Unencrypted Traffic for WinRM Client' = $V220863
    'V-220866 - Disable Unencrypted Traffic for WinRM Server' = $V220866
    'V-220867 - Disable Storage of RunAs Credentials in WinRM' = $V220867
    'V-220868 - Disable use of Digest Authentication for WinRM Client' = $V220868
    'V-220869 - Disable App Activation by Voice while System is Locked' = $V220869
    'V-220870 - Disable Convenience PIN' = $V220870
    'V-220871 - Disable Windows Ink Workspace above the Lock' = $V220871
}

return $hash | ConvertTo-Json -Compress
