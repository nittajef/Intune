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
# V-220902
# Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled.
#
##
# DISCUSSION: 
# Kernel DMA Protection to protect PCs against drive-by Direct Memory Access (DMA) attacks using PCI hot plug
# devices connected to Thunderbolt 3 ports. Drive-by DMA attacks can lead to disclosure of sensitive information
# residing on a PC, or even injection of malware that allows attackers to bypass the lock screen or control PCs
# remotely.
#
##
# CHECK: 
# This is NA prior to v1803 of Windows 10.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \Software\Policies\Microsoft\Windows\Kernel DMA Protection
#
# Value Name: DeviceEnumerationPolicy
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Kernel DMA
# Protection >> "Enumeration policy for external devices incompatible with Kernel DMA Protection" to "Enabled"
# with "Enumeration Policy" set to "Block All".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220902r569187_rule
# STIG ID: WN10-EP-000310
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -ge "17134") {
        $V220902 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection" -Name DeviceEnumerationPolicy -ErrorAction Stop) -eq 0) {
        $V220902 = $true
    } else {
        $V220902 = $false
    }
} catch {
    $V220902 = $false
}

##
# V-220903
# The DoD Root CA certificates must be installed in the Trusted Root Store.
#
##
# DISCUSSION: 
# To ensure secure DoD websites and DoD-signed code are properly validated, the system must trust the DoD Root
# Certificate Authorities (CAs). The DoD root certificates will ensure the trust chain is established for server
# certificates issued from the DoD CAs.
#
##
# CHECK: 
# Verify the DoD Root CA certificates are installed as Trusted Root Certification Authorities.
#
# The certificates and thumbprints referenced below apply to unclassified systems; refer to PKE documentation
# for other networks.
#
# Run "PowerShell" as an administrator.
#
# Execute the following command:
#
# Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*DoD*" | FL Subject, Thumbprint, NotAfter
#
# If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding.
#
# Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
# NotAfter: 12/30/2029
#
# Subject: CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
# NotAfter: 7/25/2032
#
# Subject: CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
# NotAfter: 6/14/2041
#
# Alternately, use the Certificates MMC snap-in:
#
# Run "MMC".
#
# Select "File", "Add/Remove Snap-in".
#
# Select "Certificates", click "Add".
#
# Select "Computer account", click "Next".
#
# Select "Local computer: (the computer this console is running on)", click "Finish".
#
# Click "OK".
#
# Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".
#
# For each of the DoD Root CA certificates noted below:
#
# Right-click on the certificate and select "Open".
#
# Select the "Details" tab.
#
# Scroll to the bottom and select "Thumbprint".
#
# If the DoD Root CA certificates below are not listed or the value for the "Thumbprint" field is not as noted,
# this is a finding.
#        
# DoD Root CA 3
# Thumbprint: D73CA91102A2204A36459ED32213B467D7CE97FB
# Valid to: Sunday, December 30, 2029
#
# DoD Root CA 4
# Thumbprint: B8269F25DBD937ECAFD4C35A9838571723F2D026
# Valid to: Sunday, July 25, 2032
#
# DoD Root CA 5
# Thumbprint: 4ECB5CC3095670454DA1CBD410FC921F46B8564B
# Valid to: Friday, June 14, 2041
#
##
# FIX: 
# Install the DoD Root CA certificates:
# DoD Root CA 3
# DoD Root CA 4
# DoD Root CA 5
#
# The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files.
# Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220903r894651_rule
# STIG ID: WN10-PK-000005
# REFERENCE: 
##
try {
    if ($MachineRoots) {
        $installedRoots = $MachineRoots
    } else {
        $installedRoots = @(
            "D73CA91102A2204A36459ED32213B467D7CE97FB" # DoD Root CA 3
            "B8269F25DBD937ECAFD4C35A9838571723F2D026" # DoD Root CA 4
            "4ECB5CC3095670454DA1CBD410FC921F46B8564B" # DoD Root CA 5
        )
    }

    $LMroots = Get-ChildItem -Path Cert:Localmachine\root | Select-Object -Expand Thumbprint

    $V220903 = $true

    foreach ($root in $installedRoots) {
        if ($root -notin $LMroots) {
            $V220903 = $false
        }
    }
} catch {
    $V220903 = $false
}

##
# V-220904
# The External Root CA certificates must be installed in the Trusted Root Store on unclassified systems.
#
##
# DISCUSSION: 
# To ensure secure websites protected with External Certificate Authority (ECA) server certificates are properly
# validated, the system must trust the ECA Root CAs. The ECA root certificates will ensure the trust chain is
# established for server certificates issued from the External CAs. This requirement only applies to
# unclassified systems.
#
##
# CHECK: 
# Verify the ECA Root CA certificates are installed on unclassified systems as Trusted Root Certification
# Authorities.
#
# Run "PowerShell" as an administrator.
#
# Execute the following command:
#
# Get-ChildItem -Path Cert:Localmachine\root | Where Subject -Like "*ECA*" | FL Subject, Thumbprint, NotAfter
#
# If the following certificate "Subject" and "Thumbprint" information is not displayed, this is a finding. 
#
# Subject: CN=ECA Root CA 4, OU=ECA, O=U.S. Government, C=US
# Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
# NotAfter: 12/30/2029
#
# Alternately use the Certificates MMC snap-in:
#
# Run "MMC".
#
# Select "File", "Add/Remove Snap-in".
#
# Select "Certificates", click "Add".
#
# Select "Computer account", click "Next".
#
# Select "Local computer: (the computer this console is running on)", click "Finish".
#
# Click "OK".
#
# Expand "Certificates" and navigate to "Trusted Root Certification Authorities >> Certificates".
#
# For each of the ECA Root CA certificates noted below:
#
# Right-click on the certificate and select "Open".
#
# Select the "Details" Tab.
#
# Scroll to the bottom and select "Thumbprint".
#
# If the ECA Root CA certificate below is not listed or the value for the "Thumbprint" field is not as noted,
# this is a finding.
#
# ECA Root CA 4
# Thumbprint: 73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582
# Valid to: Sunday, December 30, 2029
#
##
# FIX: 
# Install the ECA Root CA certificate on unclassified systems.
# ECA Root CA 4
#
# The InstallRoot tool is available on Cyber Exchange at https://cyber.mil/pki-pke/tools-configuration-files.
# Certificate bundles published by the PKI can be found at https://crl.gds.disa.mil/.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220904r894652_rule
# STIG ID: WN10-PK-000010
# REFERENCE: 
##
try {
    # ECA Root CA 4
    if (Get-ChildItem -Path Cert:Localmachine\root | Where-Object Thumbprint -eq "73E8BB08E337D6A5A6AEF90CFFDD97D9176CB582") {
        $V220904 = $true
    } else {
        $V220904 = $false
    }
} catch {
    $V220904 = $false
}

##
# V-220905
# The DoD Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates Store on
# unclassified systems.
#
##
# DISCUSSION: 
# To ensure users do not experience denial of service when performing certificate-based authentication to DoD
# websites due to the system chaining to a root other than DoD Root CAs, the DoD Interoperability Root CA
# cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to
# unclassified systems.
#
##
# CHECK: 
# Verify the DoD Interoperability cross-certificates are installed on unclassified systems as Untrusted
# Certificates.
#
# Run "PowerShell" as an administrator.
#
# Execute the following command:
#
# Get-ChildItem -Path Cert:Localmachine\disallowed | Where {$_.Issuer -Like "*DoD Interoperability*" -and
# $_.Subject -Like "*DoD*"} | FL Subject, Issuer, Thumbprint, NotAfter
#
# If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a
# finding.
#
# Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Issuer: CN=DoD Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: 49CBE933151872E17C8EAE7F0ABA97FB610F6477
# NotAfter: 11/16/2024 
#
# Alternately, use the Certificates MMC snap-in:
#
# Run "MMC".
#
# Select "File", "Add/Remove Snap-in".
#
# Select "Certificates", click "Add".
#
# Select "Computer account", click "Next".
#
# Select "Local computer: (the computer this console is running on)", click "Finish".
#
# Click "OK".
#
# Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.
#
# For each certificate with "DoD Root CA..." under "Issued To" and "DoD Interoperability Root CA..." under
# "Issued By":
#
# Right-click on the certificate and select "Open".
#
# Select the "Details" tab.
#
# Scroll to the bottom and select "Thumbprint".
#
# If the certificates below are not listed or the value for the "Thumbprint" field is not as noted, this is a
# finding.
#
# Issued To: DoD Root CA 3
# Issued By: DoD Interoperability Root CA 2
# Thumbprint: 49CBE933151872E17C8EAE7F0ABA97FB610F6477
# Valid to: Wednesday, November 16, 2024
#
##
# FIX: 
# Install the DoD Interoperability Root CA cross-certificates on unclassified systems.
#
# Issued To - Issued By - Thumbprint
#
# DoD Root CA 3 - DoD Interoperability Root CA 2 - 49CBE933151872E17C8EAE7F0ABA97FB610F6477 
#                   
# The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber
# Exchange at https://cyber.mil/pki-pke/tools-configuration-files. PKI can be found at
# https://crl.gds.disa.mil/.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220905r890436_rule
# STIG ID: WN10-PK-000015
# REFERENCE: 
##
try {
    # DoD Root CA 3, issued by DoD Interoperability Root CA 2
    if (Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object Thumbprint -eq "49CBE933151872E17C8EAE7F0ABA97FB610F6477") {
        $V220905 = $true
    } else {
        $V220905 = $false
    }
} catch {
    $V220905 = $false
}

##
# V-220906
# The US DoD CCEB Interoperability Root CA cross-certificates must be installed in the Untrusted Certificates
# Store on unclassified systems.
#
##
# DISCUSSION: 
# To ensure users do not experience denial of service when performing certificate-based authentication to DoD
# websites due to the system chaining to a root other than DoD Root CAs, the US DoD CCEB Interoperability Root
# CA cross-certificates must be installed in the Untrusted Certificate Store. This requirement only applies to
# unclassified systems.
#
##
# CHECK: 
# Verify the US DoD CCEB Interoperability Root CA cross-certificate is installed on unclassified systems as an
# Untrusted Certificate.
#
# Run "PowerShell" as an administrator.
#
# Execute the following command:
#
# Get-ChildItem -Path Cert:Localmachine\disallowed | Where Issuer -Like "*CCEB Interoperability*" | FL Subject,
# Issuer, Thumbprint, NotAfter
#
# If the following certificate "Subject", "Issuer", and "Thumbprint" information is not displayed, this is a
# finding. 
#
# Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
# NotAfter: 7/18/2025 9:56:22 AM
#
# Alternately, use the Certificates MMC snap-in:
#
# Run "MMC".
#
# Select "File", "Add/Remove Snap-in".
#
# Select "Certificates", click "Add".
#
# Select "Computer account", click "Next".
#
# Select "Local computer: (the computer this console is running on)", click "Finish".
#
# Click "OK".
#
# Expand "Certificates" and navigate to Untrusted Certificates >> Certificates.
#
# For each certificate with "US DoD CCEB Interoperability Root CA ..." under "Issued By":
#
# Right-click on the certificate and select "Open".
#
# Select the "Details" tab.
#
# Scroll to the bottom and select "Thumbprint".
#
# If the certificate below is not listed or the value for the "Thumbprint" field is not as noted, this is a
# finding.
#
# Subject: CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Issuer: CN=US DoD CCEB Interoperability Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US
# Thumbprint: 9B74964506C7ED9138070D08D5F8B969866560C8
# NotAfter: 7/18/2025 9:56:22 AM
#
##
# FIX: 
# Install the US DoD CCEB Interoperability Root CA cross-certificate on unclassified systems.
#
# Issued To - Issued By - Thumbprint
# DoD Root CA 3 - US DoD CCEB Interoperability Root CA 2  9B74964506C7ED9138070D08D5F8B969866560C8
#
# The certificates can be installed using the InstallRoot tool. The tool and user guide are available on Cyber
# Exchange at https://cyber.mil/pki-pke/tools-configuration-files. PKI can be found at
# https://crl.gds.disa.mil/.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220906r890439_rule
# STIG ID: WN10-PK-000020
# REFERENCE: 
##
try {
    # DoD Root CA 3, issued by US DoD CCEB Interoperability Root CA 2
    if (Get-ChildItem -Path Cert:Localmachine\disallowed | Where-Object Thumbprint -eq "9B74964506C7ED9138070D08D5F8B969866560C8") {
        $V220906 = $true
    } else {
        $V220906 = $false
    }
} catch {
    $V220906 = $false
}

##
# V-220907
# Default permissions for the HKEY_LOCAL_MACHINE registry hive must be maintained.
#
##
# DISCUSSION: 
# The registry is integral to the function, security, and stability of the Windows system.  Changing the
# system's registry permissions allows the possibility of unauthorized and anonymous modification to the
# operating system.
#
##
# CHECK: 
# Verify the default registry permissions for the keys note below of the HKEY_LOCAL_MACHINE hive.
#
# If any non-privileged groups such as Everyone, Users or Authenticated Users have greater than Read permission,
# this is a finding.
#
# Run "Regedit".
# Right click on the registry areas noted below.
# Select "Permissions..." and the "Advanced" button.
#
# HKEY_LOCAL_MACHINE\SECURITY
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# SYSTEM - Full Control - This key and subkeys
# Administrators - Special - This key and subkeys
#
# HKEY_LOCAL_MACHINE\SOFTWARE
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# Users - Read - This key and subkeys
# Administrators - Full Control - This key and subkeys
# SYSTEM - Full Control - This key and subkeys
# CREATOR OWNER - Full Control - This key and subkeys
# ALL APPLICATION PACKAGES - Read - This key and subkeys
#
# HKEY_LOCAL_MACHINE\SYSTEM
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# Users - Read - This key and subkeys
# Administrators - Full Control - This key and subkeys
# SYSTEM - Full Control - This key and subkeys
# CREATOR OWNER - Full Control - This key and subkeys
# ALL APPLICATION PACKAGES - Read - This key and subkeys
#
# Other subkeys under the noted keys may also be sampled. There may be some instances where non-privileged
# groups have greater than Read permission.
#
# Microsoft has given Read permission to the SOFTWARE and SYSTEM registry keys in later versions of Windows 10
# to the following SID, this is currently not a finding.
#
# S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681
#
# If the defaults have not been changed, these are not a finding.
#
##
# FIX: 
# Maintain the default permissions for the HKEY_LOCAL_MACHINE registry hive.
#
# The default permissions of the higher level keys are noted below.
#
# HKEY_LOCAL_MACHINE\SECURITY
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# SYSTEM - Full Control - This key and subkeys
# Administrators - Special - This key and subkeys
#
# HKEY_LOCAL_MACHINE\SOFTWARE
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# Users - Read - This key and subkeys
# Administrators - Full Control - This key and subkeys
# SYSTEM - Full Control - This key and subkeys
# CREATOR OWNER - Full Control - This key and subkeys
# ALL APPLICATION PACKAGES - Read - This key and subkeys
#
# HKEY_LOCAL_MACHINE\SYSTEM
# Type - "Allow" for all
# Inherited from - "None" for all
# Principal - Access - Applies to
# Users - Read - This key and subkeys
# Administrators - Full Control - This key and subkeys
# SYSTEM - Full Control - This key and subkeys
# CREATOR OWNER - Full Control - This key and subkeys
# ALL APPLICATION PACKAGES - Read - This key and subkeys
#
# Microsoft has also given Read permission to the SOFTWARE and SYSTEM registry keys in later versions of Windows
# 10 to the following SID.
#
# S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681
#
##
# SEVERITY: CAT II
# RULE ID: SV-220907r877392_rule
# STIG ID: WN10-RG-000005
# REFERENCE: 
##
try {
    $V220907 = $true

    $acl = Get-Acl -Path "HKLM:\SECURITY\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -eq "NT AUTHORITY\SYSTEM" -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -eq "BUILTIN\Administrators" -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadPermissions, ChangePermissions" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default special permissions
        } else {
            $V220907 = $false
        }
    }

    $acl = Get-Acl -Path "HKLM:\SOFTWARE\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("CREATOR OWNER", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -in @("BUILTIN\Users", "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default read permissions
        } elseif ($entry.IdentityReference.Value -eq @("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as MS added default read permissions
        } else {
            $V220907 = $false
        }
    }

    $acl = Get-Acl -Path "HKLM:\SYSTEM\"
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("CREATOR OWNER", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.IsInherited -eq "False" -and
            $entry.AccessControlType -eq "Allow" -and
            $entry.RegistryRights -eq "FullControl" -and
            $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default full control permissions        
        } elseif ($entry.IdentityReference.Value -in @("BUILTIN\Users", "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as default read permissions
        } elseif ($entry.IdentityReference.Value -eq @("S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681") -and
                  $entry.IsInherited -eq "False" -and
                  $entry.AccessControlType -eq "Allow" -and
                  $entry.RegistryRights -eq "ReadKey" -and
                  $entry.InheritanceFlags -eq "ContainerInherit") {
            # Okay as MS added default read permissions
        } else {
            $V220907 = $false
        }
    }
} catch {
    $V220907 = $false
}

##
# V-220908
# The built-in administrator account must be disabled.
#
##
# DISCUSSION: 
# The built-in administrator account is a well-known account subject to attack.  It also provides no
# accountability to individual administrators on a system.  It must be disabled to prevent its use.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options.
#
# If the value for "Accounts: Administrator account status" is not set to "Disabled", this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Accounts: Administrator account status" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220908r569187_rule
# STIG ID: WN10-SO-000005
# REFERENCE: 
##
try {
    $V220908 = $true
    foreach ($user in $LocalUsers) {
        if ($user.SID -like "*-500" -and $user.Enabled -eq $true) {
             $V220908 = $false
        }
    }
} catch {
    $V220908 = $false
}

##
# V-220909
# The built-in guest account must be disabled.
#
##
# DISCUSSION: 
# A system faces an increased vulnerability threat if the built-in guest account is not disabled.  This account
# is a known account that exists on all Windows systems and cannot be deleted.  This account is initialized
# during the installation of the operating system with no password assigned.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options.
#
# If the value for "Accounts: Guest account status" is not set to "Disabled", this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Accounts: Guest account status" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220909r569187_rule
# STIG ID: WN10-SO-000010
# REFERENCE: 
##
try {
    $V220909 = $true
    foreach ($user in $LocalUsers) {
        if ($user.SID -like "*-501" -and $user.Enabled -eq $true) {
             $V220909 = $false
        }
    }
} catch {
    $V220909 = $false
}

##
# V-220910
# Local accounts with blank passwords must be restricted to prevent access from the network.
#
##
# DISCUSSION: 
# An account without a password can allow unauthorized access to a system as only the username would be
# required.  Password policies should prevent accounts with blank passwords from existing on a system.  However,
# if a local account with a blank password did exist, enabling this setting will prevent network access,
# limiting the account to local console logon only.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: LimitBlankPasswordUse
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Accounts: Limit local account use of blank passwords to console logon only"
# to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220910r569187_rule
# STIG ID: WN10-SO-000015
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name LimitBlankPasswordUse -ErrorAction Stop) -eq 1) {
        $V220910 = $true
    } else {
        $V220910 = $false
    }
} catch {
    $V220910 = $false
}


##
# V-220911
# The built-in administrator account must be renamed.
#
##
# DISCUSSION: 
# The built-in administrator account is a well-known account subject to attack.  Renaming this account to an
# unidentified name improves the protection of this account and the system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options.
#
# If the value for "Accounts: Rename administrator account" is set to "Administrator", this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Accounts: Rename administrator account" to a name other than "Administrator".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220911r569187_rule
# STIG ID: WN10-SO-000020
# REFERENCE: 
##
try {
    if ((Get-LocalUser -Name "Administrator" -ErrorAction Stop | Select-Object SID).SID -like "*-500") {
        $V220911 = $false
    } else {
        $V220911 = $true
    }
} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    $V220911 = $true
} catch {
    $V220911 = $false
}

##
# V-220912
# The built-in guest account must be renamed.
#
##
# DISCUSSION: 
# The built-in guest account is a well-known user account on all Windows systems and, as initially installed,
# does not require a password.  This can allow access to system resources by unauthorized users.  Renaming this
# account to an unidentified name improves the protection of this account and the system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options.
#
# If the value for "Accounts: Rename guest account" is set to "Guest", this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Accounts: Rename guest account" to a name other than "Guest".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220912r569187_rule
# STIG ID: WN10-SO-000025
# REFERENCE: 
##
try {
    if ((Get-LocalUser -Name "Guest" -ErrorAction Stop | Select-Object SID).SID -like "*-501") {
        $V220912 = $false
    } else {
        $V220912 = $true
    }
} catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
    $V220912 = $true
} catch {
    $V220912 = $false
}

##
# V-220913
# Audit policy using subcategories must be enabled.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.  This setting allows administrators to enable more precise auditing capabilities.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: SCENoApplyLegacyAuditPolicy
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Audit: Force audit policy subcategory settings (Windows Vista or later) to
# override audit policy category settings" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220913r569187_rule
# STIG ID: WN10-SO-000030
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1) {
        $V220913 = $true
    } else {
        $V220913 = $false
    }
} catch {
    $V220913 = $false
}


##
# V-220914
# Outgoing secure channel traffic must be encrypted or signed.
#
##
# DISCUSSION: 
# Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is
# encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic
# will be encrypted and signed.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: RequireSignOrSeal
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Digitally encrypt or sign secure channel data (always)" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220914r852008_rule
# STIG ID: WN10-SO-000035
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireSignOrSeal -ErrorAction Stop) -eq 1) {
        $V220914 = $true
    } else {
        $V220914 = $false
    }
} catch {
    $V220914 = $false
}


##
# V-220915
# Outgoing secure channel traffic must be encrypted when possible.
#
##
# DISCUSSION: 
# Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is
# encrypted, but not all information is encrypted.  If this policy is enabled, outgoing secure channel traffic
# will be encrypted.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: SealSecureChannel
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Digitally encrypt secure channel data (when possible)" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220915r852009_rule
# STIG ID: WN10-SO-000040
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name SealSecureChannel -ErrorAction Stop) -eq 1) {
        $V220915 = $true
    } else {
        $V220915 = $false
    }
} catch {
    $V220915 = $false
}


##
# V-220916
# Outgoing secure channel traffic must be signed when possible.
#
##
# DISCUSSION: 
# Requests sent on the secure channel are authenticated, and sensitive information (such as passwords) is
# encrypted, but the channel is not integrity checked.  If this policy is enabled, outgoing secure channel
# traffic will be signed.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: SignSecureChannel
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Digitally sign secure channel data (when possible)" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220916r852010_rule
# STIG ID: WN10-SO-000045
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name SignSecureChannel -ErrorAction Stop) -eq 1) {
        $V220916 = $true
    } else {
        $V220916 = $false
    }
} catch {
    $V220916 = $false
}


##
# V-220919
# The system must be configured to require a strong session key.
#
##
# DISCUSSION: 
# A computer connecting to a domain controller will establish a secure channel.  Requiring strong session keys
# enforces 128-bit encryption between systems.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#
# Value Name: RequireStrongKey
#
# Value Type: REG_DWORD
# Value: 1
#  
# Warning: This setting may prevent a system from being joined to a domain if not configured consistently
# between systems.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Domain member: Require strong (Windows 2000 or Later) session key" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220919r852011_rule
# STIG ID: WN10-SO-000060
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\" -Name RequireStrongKey -ErrorAction Stop) -eq 1) {
        $V220919 = $true
    } else {
        $V220919 = $false
    }
} catch {
    $V220919 = $false
}


##
# V-220920
# The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.
#
##
# DISCUSSION: 
# Unattended systems are susceptible to unauthorized use and should be locked when unattended.  The screen saver
# should be set at a maximum of 15 minutes and be password protected.  This protects critical and sensitive data
# from exposure to unauthorized personnel with physical access to the computer.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: InactivityTimeoutSecs
#
# Value Type: REG_DWORD
# Value: 0x00000384 (900) (or less, excluding "0" which is effectively disabled)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Machine inactivity limit" to "900" seconds" or less,
# excluding "0" which is effectively disabled.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220920r569187_rule
# STIG ID: WN10-SO-000070
# REFERENCE: 
##
try {
    if ($InactivityTimeout) {
        $sec = $InactivityTimeout
    } else {
        $sec = 900
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name InactivityTimeoutSecs -ErrorAction Stop) -ne 1..$sec) {
        $V220920 = $true
    } else {
        $V220920 = $false
    }
} catch {
    $V220920 = $false
}

##
# V-220921
# The required legal notice must be configured to display before console logon.
#
##
# DISCUSSION: 
# Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from
# unauthorized access to system resources.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: LegalNoticeText
#
# Value Type: REG_SZ
# Value: 
# You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use
# only.
#
# By using this IS (which includes any device attached to this IS), you consent to the following conditions:
#
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited
# to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
# enforcement (LE), and counterintelligence (CI) investigations.
#
# -At any time, the USG may inspect and seize data stored on this IS.
#
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring,
# interception, and search, and may be disclosed or used for any USG-authorized purpose.
#
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not
# for your personal benefit or privacy.
#
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching
# or monitoring of the content of privileged communications, or work product, related to personal representation
# or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work
# product are private and confidential.  See User Agreement for details.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Message text for users attempting to log on" to the
# following.
#
# You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use
# only.
#
# By using this IS (which includes any device attached to this IS), you consent to the following conditions:
#
# -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited
# to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law
# enforcement (LE), and counterintelligence (CI) investigations.
#
# -At any time, the USG may inspect and seize data stored on this IS.
#
# -Communications using, or data stored on, this IS are not private, are subject to routine monitoring,
# interception, and search, and may be disclosed or used for any USG-authorized purpose.
#
# -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not
# for your personal benefit or privacy.
#
# -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching
# or monitoring of the content of privileged communications, or work product, related to personal representation
# or services by attorneys, psychotherapists, or clergy, and their assistants.  Such communications and work
# product are private and confidential.  See User Agreement for details.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220921r569187_rule
# STIG ID: WN10-SO-000075
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LegalNoticeText -ErrorAction Stop) -ne "") {
        $V220921 = $true
    } else {
        $V220921 = $false
    }
} catch {
    $V220921 = $false
}

##
# V-220924
# The Smart Card removal option must be configured to Force Logoff or Lock Workstation.
#
##
# DISCUSSION: 
# Unattended systems are susceptible to unauthorized use and must be locked.  Configuring a system to lock when
# a smart card is removed will ensure the system is inaccessible when unattended.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\
#
# Value Name:  SCRemoveOption
#
# Value Type:  REG_SZ
# Value:  1 (Lock Workstation) or 2 (Force Logoff)
#
# This can be left not configured or set to "No action" on workstations with the following conditions.  This
# must be documented with the ISSO.
# -The setting cannot be configured due to mission needs, or because it interferes with applications.
# -Policy must be in place that users manually lock workstations when leaving them unattended.
# -The screen saver is properly configured to lock as required.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Interactive logon: Smart card removal behavior" to  "Lock Workstation" or
# "Force Logoff".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220924r569187_rule
# STIG ID: WN10-SO-000095
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Name SCRemoveOption -ErrorAction Stop) -in @(1, 2)) {
        $V220924 = $true
    } else {
        $V220924 = $false
    }
} catch {
    $V220924 = $false
}

##
# V-220925
# The Windows SMB client must be configured to always perform SMB packet signing.
#
##
# DISCUSSION: 
# The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB
# packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB client will only
# communicate with an SMB server that performs SMB packet signing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
#
# Value Name: RequireSecuritySignature
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Microsoft network client: Digitally sign communications (always)" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220925r852012_rule
# STIG ID: WN10-SO-000100
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name RequireSecuritySignature -ErrorAction Stop) -eq 1) {
        $V220925 = $true
    } else {
        $V220925 = $false
    }
} catch {
    $V220925 = $false
}


##
# V-220926
# Unencrypted passwords must not be sent to third-party SMB Servers.
#
##
# DISCUSSION: 
# Some non-Microsoft SMB servers only support unencrypted (plain text) password authentication.  Sending plain
# text passwords across the network, when authenticating to an SMB server, reduces the overall security of the
# environment.  Check with the vendor of the SMB server to see if there is a way to support encrypted password
# authentication.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\
#
# Value Name:  EnablePlainTextPassword
#
# Value Type:  REG_DWORD
# Value:  0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Microsoft network client: Send unencrypted password to third-party SMB
# servers" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220926r877396_rule
# STIG ID: WN10-SO-000110
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\" -Name EnablePlainTextPassword -ErrorAction Stop) -eq 0) {
        $V220926 = $true
    } else {
        $V220926 = $false
    }
} catch {
    $V220926 = $false
}


##
# V-220927
# The Windows SMB server must be configured to always perform SMB packet signing.
#
##
# DISCUSSION: 
# The server message block (SMB) protocol provides the basis for many network operations.  Digitally signed SMB
# packets aid in preventing man-in-the-middle attacks.  If this policy is enabled, the SMB server will only
# communicate with an SMB client that performs SMB packet signing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\
#
# Value Name: RequireSecuritySignature
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Microsoft network server: Digitally sign communications (always)" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220927r852013_rule
# STIG ID: WN10-SO-000120
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\" -Name RequireSecuritySignature -ErrorAction Stop) -eq 1) {
        $V220927 = $true
    } else {
        $V220927 = $false
    }
} catch {
    $V220927 = $false
}


##
# V-220931
# The system must be configured to prevent anonymous users from having the same rights as the Everyone group.
#
##
# DISCUSSION: 
# Access by anonymous users must be restricted.  If this setting is enabled, then anonymous users have the same
# rights and permissions as the built-in Everyone group.  Anonymous users must not have these permissions or
# rights.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: EveryoneIncludesAnonymous
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network access: Let Everyone permissions apply to anonymous users" to
# "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220931r569187_rule
# STIG ID: WN10-SO-000160
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name EveryoneIncludesAnonymous -ErrorAction Stop) -eq 0) {
        $V220931 = $true
    } else {
        $V220931 = $false
    }
} catch {
    $V220931 = $false
}


##
# V-220933
# Remote calls to the Security Account Manager (SAM) must be restricted to Administrators.
#
##
# DISCUSSION: 
# The Windows Security Account Manager (SAM) stores users' passwords.  Restricting remote rpc connections to the
# SAM to Administrators helps protect those credentials.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting, it is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\
#
# Value Name: RestrictRemoteSAM
#
# Value Type: REG_SZ
# Value: O:BAG:BAD:(A;;RC;;;BA)
#
##
# FIX: 
# Navigate to the policy Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >>
# Security Options >> "Network access: Restrict clients allowed to make remote calls to SAM".
#
# Select "Edit Security" to configure the "Security descriptor:".
#
# Add "Administrators" in "Group or user names:" if it is not already listed (this is the default).
#
# Select "Administrators" in "Group or user names:".
#
# Select "Allow" for "Remote Access" in "Permissions for "Administrators".
#
# Click "OK".
#
# The "Security descriptor:" must be populated with "O:BAG:BAD:(A;;RC;;;BA) for the policy to be enforced.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220933r877392_rule
# STIG ID: WN10-SO-000167
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name RestrictRemoteSAM -ErrorAction Stop) -eq 0) {
        $V220933 = $true
    } else {
        $V220933 = $false
    }
} catch {
    $V220933 = $false
}


##
# V-220934
# NTLM must be prevented from falling back to a Null session.
#
##
# DISCUSSION: 
# NTLM sessions that are allowed to fall back to Null (unauthenticated) sessions may gain unauthorized access.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\
#
# Value Name: allownullsessionfallback
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Allow LocalSystem NULL session fallback" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220934r569187_rule
# STIG ID: WN10-SO-000180
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\" -Name allownullsessionfallback -ErrorAction Stop) -eq 0) {
        $V220934 = $true
    } else {
        $V220934 = $false
    }
} catch {
    $V220934 = $false
}


##
# V-220935
# PKU2U authentication using online identities must be prevented.
#
##
# DISCUSSION: 
# PKU2U is a peer-to-peer authentication protocol.   This setting prevents online identities from authenticating
# to domain-joined systems.  Authentication will be centrally managed with Windows user accounts.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\LSA\pku2u\
#
# Value Name: AllowOnlineID
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Allow PKU2U authentication requests to this computer to use
# online identities" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220935r569187_rule
# STIG ID: WN10-SO-000185
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u\" -Name AllowOnlineID -ErrorAction Stop) -eq 0) {
        $V220935 = $true
    } else {
        $V220935 = $false
    }
} catch {
    $V220935 = $false
}


##
# V-220936
# Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites.
#
##
# DISCUSSION: 
# Certain encryption types are no longer considered secure.  This setting configures a minimum encryption type
# for Kerberos, preventing the use of the DES and RC4 encryption suites.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
#
# Value Name: SupportedEncryptionTypes
#
# Value Type: REG_DWORD
# Value: 0x7ffffff8 (2147483640)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Configure encryption types allowed for Kerberos" to
# "Enabled" with only the following selected:
#
# AES128_HMAC_SHA1
# AES256_HMAC_SHA1
# Future encryption types
#
##
# SEVERITY: CAT II
# RULE ID: SV-220936r569187_rule
# STIG ID: WN10-SO-000190
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name SupportedEncryptionTypes -ErrorAction Stop) -eq 2147483640) {
        $V220936 = $true
    } else {
        $V220936 = $false
    }
} catch {
    $V220936 = $false
}


##
# V-220939
# The system must be configured to the required LDAP client signing level.
#
##
# DISCUSSION: 
# This setting controls the signing requirements for LDAP clients.  This setting must be set to Negotiate
# signing or Require signing, depending on the environment and type of LDAP server in use.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\LDAP\
#
# Value Name: LDAPClientIntegrity
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: LDAP client signing requirements" to "Negotiate signing" at
# a minimum.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220939r569187_rule
# STIG ID: WN10-SO-000210
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\" -Name LDAPClientIntegrity -ErrorAction Stop) -eq 1) {
        $V220939 = $true
    } else {
        $V220939 = $false
    }
} catch {
    $V220939 = $false
}


##
# V-220940
# The system must be configured to meet the minimum session security requirement for NTLM SSP based clients.
#
##
# DISCUSSION: 
# Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the
# options must be enabled to ensure the maximum security level.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
#
# Value Name: NTLMMinClientSec
#
# Value Type: REG_DWORD
# Value: 0x20080000 (537395200)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Minimum session security for NTLM SSP based (including
# secure RPC) clients" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options
# selected).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220940r569187_rule
# STIG ID: WN10-SO-000215
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinClientSec -ErrorAction Stop) -eq 537395200) {
        $V220940 = $true
    } else {
        $V220940 = $false
    }
} catch {
    $V220940 = $false
}


##
# V-220941
# The system must be configured to meet the minimum session security requirement for NTLM SSP based servers.
#
##
# DISCUSSION: 
# Microsoft has implemented a variety of security support providers for use with RPC sessions.  All of the
# options must be enabled to ensure the maximum security level.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
#
# Value Name: NTLMMinServerSec
#
# Value Type: REG_DWORD
# Value: 0x20080000 (537395200)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "Network security: Minimum session security for NTLM SSP based (including
# secure RPC) servers" to "Require NTLMv2 session security" and "Require 128-bit encryption" (all options
# selected).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220941r569187_rule
# STIG ID: WN10-SO-000220
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\" -Name NTLMMinServerSec -ErrorAction Stop) -eq 537395200) {
        $V220941 = $true
    } else {
        $V220941 = $false
    }
} catch {
    $V220941 = $false
}


##
# V-220942
# The system must be configured to use FIPS-compliant algorithms for encryption, hashing, and signing.
#
##
# DISCUSSION: 
# This setting ensures that the system uses algorithms that are FIPS-compliant for encryption, hashing, and
# signing.  FIPS-compliant algorithms meet specific standards established by the U.S. Government and must be the
# algorithms used for all OS encryption functions.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\
#
# Value Name: Enabled
#
# Value Type: REG_DWORD
# Value: 1
#  
# Warning: Clients with this setting enabled will not be able to communicate via digitally encrypted or signed
# protocols with servers that do not support these algorithms.  Both the browser and web server must be
# configured to use TLS otherwise the browser will not be able to connect to a secure site.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "System cryptography: Use FIPS compliant algorithms for encryption, hashing,
# and signing" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220942r877466_rule
# STIG ID: WN10-SO-000230
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" -Name Enabled -ErrorAction Stop) -eq 1 -or
        (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy\" -Name MDMEnabled -ErrorAction Stop) -eq 1) {
        $V220942 = $true
    } else {
        $V220942 = $false
    }
} catch {
    $V220942 = $false
}

##
# V-220944
# User Account Control approval mode for the built-in Administrator must be enabled.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting configures the built-in Administrator account so
# that it runs in Admin Approval Mode.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: FilterAdministratorToken
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Admin Approval Mode for the Built-in Administrator
# account" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220944r852016_rule
# STIG ID: WN10-SO-000245
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name FilterAdministratorToken -ErrorAction Stop) -eq 1) {
        $V220944 = $true
    } else {
        $V220944 = $false
    }
} catch {
    $V220944 = $false
}


##
# V-220945
# User Account Control must, at minimum, prompt administrators for consent on the secure desktop.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting configures the elevation requirements for logged on
# administrators to complete a task that requires raised privileges.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: ConsentPromptBehaviorAdmin
#
# Value Type: REG_DWORD
# Value: 2 (Prompt for consent on the secure desktop)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for administrators in
# Admin Approval Mode" to "Prompt for consent on the secure desktop".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220945r569187_rule
# STIG ID: WN10-SO-000250
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorAdmin -ErrorAction Stop) -eq 2) {
        $V220945 = $true
    } else {
        $V220945 = $false
    }
} catch {
    $V220945 = $false
}

##
# V-220946
# Windows 10 must use multifactor authentication for local and network access to privileged and nonprivileged
# accounts.
#
##
# DISCUSSION: 
# Without the use of multifactor authentication, the ease of access to privileged and nonprivileged functions is
# greatly increased. 
#
# All domain accounts must be enabled for multifactor authentication with the exception of local emergency
# accounts. 
#
# Multifactor authentication requires using two or more factors to achieve authentication.
#
# Factors include: 
#
# 1) Something a user knows (e.g., password/PIN);
#
# 2) Something a user has (e.g., cryptographic identification device, token); and
#
# 3) Something a user is (e.g., biometric).
#
# A privileged account is defined as an information system account with authorizations of a privileged user.
#
# Network access is defined as access to an information system by a user (or a process acting on behalf of a
# user) communicating through a network (e.g., local area network, wide area network, or the internet).
#
# Local access is defined as access to an organizational information system by a user (or process acting on
# behalf of a user) communicating through a direct connection without the use of a network.
#
# The DoD CAC with DoD-approved PKI is an example of multifactor authentication.
#
# Satisfies: SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000108-GPOS-00055
#
##
# CHECK: 
# If the system is a member of a domain, this is Not Applicable.
#
# If one of the following settings does not exist and is not populated, this is a finding: 
#
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\Readers
# Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\Calais\SmartCards
#
##
# FIX: 
# For non-domain joined systems, configuring Windows Hello for sign-on options is suggested based on the
# organization's needs and capabilities.
#  
#
##
# SEVERITY: CAT II
# RULE ID: SV-220946r890441_rule
# STIG ID: WN10-SO-000251
# REFERENCE: 
##
$V220946 = $true

##
# V-220947
# User Account Control must automatically deny elevation requests for standard users.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  Denying elevation requests from standard user accounts requires
# tasks that need elevation to be initiated by accounts with administrative privileges.  This ensures correct
# accounts are used on the system for privileged tasks to help mitigate credential theft.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: ConsentPromptBehaviorUser
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Behavior of the elevation prompt for standard users" to
# "Automatically deny elevation requests".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220947r852017_rule
# STIG ID: WN10-SO-000255
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name ConsentPromptBehaviorUser -ErrorAction Stop) -eq 0) {
        $V220947 = $true
    } else {
        $V220947 = $false
    }
} catch {
    $V220947 = $false
}


##
# V-220948
# User Account Control must be configured to detect application installations and prompt for elevation.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting requires Windows to respond to application
# installation requests by prompting for credentials.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: EnableInstallerDetection
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Detect application installations and prompt for
# elevation" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220948r569187_rule
# STIG ID: WN10-SO-000260
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name EnableInstallerDetection -ErrorAction Stop) -eq 1) {
        $V220948 = $true
    } else {
        $V220948 = $false
    }
} catch {
    $V220948 = $false
}


##
# V-220949
# User Account Control must only elevate UIAccess applications that are installed in secure locations.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting configures Windows to only allow applications
# installed in a secure location on the file system, such as the Program Files or the Windows\System32 folders,
# to run with elevated privileges.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: EnableSecureUIAPaths
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Only elevate UIAccess applications that are installed
# in secure locations" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220949r569187_rule
# STIG ID: WN10-SO-000265
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name EnableSecureUIAPaths -ErrorAction Stop) -eq 1) {
        $V220949 = $true
    } else {
        $V220949 = $false
    }
} catch {
    $V220949 = $false
}


##
# V-220950
# User Account Control must run all administrators in Admin Approval Mode, enabling UAC.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting enables UAC.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: EnableLUA
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Run all administrators in Admin Approval Mode" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220950r852018_rule
# STIG ID: WN10-SO-000270
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name EnableLUA -ErrorAction Stop) -eq 1) {
        $V220950 = $true
    } else {
        $V220950 = $false
    }
} catch {
    $V220950 = $false
}


##
# V-220951
# User Account Control must virtualize file and registry write failures to per-user locations.
#
##
# DISCUSSION: 
# User Account Control (UAC) is a security mechanism for limiting the elevation of privileges, including
# administrative accounts, unless authorized.  This setting configures non-UAC compliant applications to run in
# virtualized file and registry entries in per-user locations, allowing them to run.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: EnableVirtualization
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> Security Options >> "User Account Control: Virtualize file and registry write failures to per-user
# locations" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220951r569187_rule
# STIG ID: WN10-SO-000275
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name EnableVirtualization -ErrorAction Stop) -eq 1) {
        $V220951 = $true
    } else {
        $V220951 = $false
    }
} catch {
    $V220951 = $false
}


##
# V-220952
# Passwords for enabled local Administrator accounts must be changed at least every 60 days.
#
##
# DISCUSSION: 
# The longer a password is in use, the greater the opportunity for someone to gain unauthorized knowledge of the
# password. A local Administrator account is not generally used and its password may not be changed as
# frequently as necessary. Changing the password for enabled Administrator accounts on a regular basis will
# limit its exposure.
#
# Windows LAPS must be used  to change the built-in Administrator account password.
#
##
# CHECK: 
# Review the password last set date for the enabled local Administrator account.
#
# On the local domain-joined workstation:
#
# Open "PowerShell".
#
# Enter "Get-LocalUser -Name * | Select-Object *".
#
# If the "PasswordLastSet" date is greater than "60" days old for the local Administrator account for
# administering the computer/domain, this is a finding.
#
##
# FIX: 
# Change the enabled local Administrator account password at least every 60 days. Windows LAPS must be used to
# change the built-in Administrator account password. Domain-joined systems can configure this to occur more
# frequently. LAPS will change the password every 30 days by default. 
#
##
# SEVERITY: CAT II
# RULE ID: SV-220952r915610_rule
# STIG ID: WN10-SO-000280
# REFERENCE: 
##
try {
    $localAdmins = Get-LocalGroupMember -Name "Administrators"
    $V220952 = $true
    foreach ($acct in $localAdmins) {
    if ($acct.PrincipalSource -eq "Local" -and ($LocalUsers | Where-Object { $_.SID -eq $acct.SID }).Enabled -eq $true) {
        if ((Get-Date).AddDays(-60) -gt ($LocalUsers | Where-Object { $_.SID -eq $acct.SID }).PasswordLastSet) {
            $V220952 = $false
        }
    }
}
} catch {
    $V220952 = $false
}

##
# V-220955
# Zone information must be preserved when saving attachments.
#
##
# DISCUSSION: 
# Preserving zone of origin (internet, intranet, local, restricted) information on file attachments allows
# Windows to determine risk.
#
##
# CHECK: 
# The default behavior is for Windows to mark file attachments with their zone information.
#
# If the registry Value Name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "2", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_CURRENT_USER
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\
#
# Value Name: SaveZoneInformation
#
# Value Type: REG_DWORD
# Value: 0x00000002 (2) (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for Windows to mark file attachments with their zone information.
#
# If this needs to be corrected, configure the policy value for User Configuration >> Administrative Templates
# >> Windows Components >> Attachment Manager >> "Do not preserve zone information in file attachments" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220955r569187_rule
# STIG ID: WN10-UC-000020
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments\" -Name SaveZoneInformation -ErrorAction Stop) -eq 2) {
        $V220955 = $true
    } else {
        $V220955 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220955 = $true
} catch {
    $V220955 = $false
}

##
# V-220956
# The Access Credential Manager as a trusted caller user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Access Credential Manager as a trusted caller" user right may be able to retrieve the
# credentials of other accounts from Credential Manager.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts are granted the "Access Credential Manager as a trusted caller" user right, this is
# a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Access Credential Manager as a trusted caller" to be defined but
# containing no entries (blank).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220956r877392_rule
# STIG ID: WN10-UR-000005
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeTrustedCredManAccessPrivilege -eq $null) {
        $V220956 = $true
    } else {
        $V220956 = $false
    }
} catch {
    $V220956 = $false
}

##
# V-220957
# The Access this computer from the network user right must only be assigned to the Administrators and Remote
# Desktop Users groups.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Access this computer from the network" user right may access resources on the system, and
# must be limited to those that require it.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Access this computer from the network"
# user right, this is a finding:
#
# Administrators
# Remote Desktop Users
#
# If a domain application account such as for a management tool requires this user right, this would not be a
# finding.
#
# Vendor documentation must support the requirement for having the user right.
#
# The requirement must be documented with the ISSO.
#
# The application account, managed at the domain level, must meet requirements for application account
# passwords, such as length and frequency of changes as defined in the Windows server STIGs.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Access this computer from the network" to only include the following
# groups or accounts:
#
# Administrators   
# Remote Desktop Users
#
##
# SEVERITY: CAT II
# RULE ID: SV-220957r569187_rule
# STIG ID: WN10-UR-000010
# REFERENCE: 
##
try {
    $V220957 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeNetworkLogonRight).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-32-555")) {
            $V220957 = $false
        }
    }
} catch {
    $V220957 = $false
}

##
# V-220959
# The Allow log on locally user right must only be assigned to the Administrators and Users groups.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# Accounts with the "Allow log on locally" user right can log on interactively to a system.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
#
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Allow log on locally" user right, this is
# a finding:
#
# Administrators
# Users
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Allow log on locally" to only include the following groups or accounts:
#
# Administrators
# Users
#
##
# SEVERITY: CAT II
# RULE ID: SV-220959r569187_rule
# STIG ID: WN10-UR-000025
# REFERENCE: 
##
try {
    $V220959 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeInteractiveLogonRight).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-32-545")) {
            $V220959 = $false
        }
    }
} catch {
    $V220959 = $false
}

##
# V-220960
# The Back up files and directories user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Back up files and directories" user right can circumvent file and directory permissions and
# could allow access to sensitive data."
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Back up files and directories" user right,
# this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Back up files and directories" to only include the following groups or
# accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220960r877392_rule
# STIG ID: WN10-UR-000030
# REFERENCE: 
##
try {
    $V220960 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeBackupPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220960 = $false
        }
    }
} catch {
    $V220960 = $false
}

##
# V-220961
# The Change the system time user right must only be assigned to Administrators and Local Service and NT
# SERVICE\autotimesvc.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Change the system time" user right can change the system time, which can impact
# authentication, as well as affect time stamps on event log entries.
#
# The NT SERVICE\autotimesvc is added in v1909 cumulative update. 
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Change the system time" user right, this
# is a finding:
#
# Administrators
# LOCAL SERVICE
# NT SERVICE\autotimesvc is added in v1909 cumulative update.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Change the system time" to only include the following groups or
# accounts:
#
# Administrators
# LOCAL SERVICE
# NT SERVICE\autotimesvc is added in v1909 cumulative update.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220961r877392_rule
# STIG ID: WN10-UR-000035
# REFERENCE: 
##
try {
    $V220961 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeBackupPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19")) {
            $V220961 = $false
        }
    }
} catch {
    $V220961 = $false
}

##
# V-220962
# The Create a pagefile user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Create a pagefile" user right can change the size of a pagefile, which could affect system
# performance.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Create a pagefile" user right, this is a
# finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Create a pagefile" to only include the following groups or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220962r877392_rule
# STIG ID: WN10-UR-000040
# REFERENCE: 
##
try {
    $V220962 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreatePagefilePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220962 = $false
        }
    }
} catch {
    $V220962 = $false
}

##
# V-220964
# The Create global objects user right must only be assigned to Administrators, Service, Local Service, and
# Network Service.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Create global objects" user right can create objects that are available to all sessions,
# which could affect processes in other users' sessions.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Create global objects" user right, this is
# a finding:
#
# Administrators
# LOCAL SERVICE
# NETWORK SERVICE
# SERVICE
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Create global objects" to only include the following groups or
# accounts:
#
# Administrators
# LOCAL SERVICE
# NETWORK SERVICE
# SERVICE
#
##
# SEVERITY: CAT II
# RULE ID: SV-220964r877392_rule
# STIG ID: WN10-UR-000050
# REFERENCE: 
##
try {
    $V220964 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreateGlobalPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")) {
            $V220964 = $false
        }
    }
} catch {
    $V220964 = $false
}

##
# V-220965
# The Create permanent shared objects user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Create permanent shared objects" user right could expose sensitive data by creating shared
# objects.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts are granted the "Create permanent shared objects" user right, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Create permanent shared objects" to be defined but containing no
# entries (blank).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220965r877392_rule
# STIG ID: WN10-UR-000055
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeCreatePermanentPrivilege -eq $null) {
        $V220965 = $true
    } else {
        $V220965 = $false
    }
} catch {
    $V220965 = $false
}

##
# V-220966
# The Create symbolic links user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Create symbolic links" user right can create pointers to other objects, which could
# potentially expose the system to attack.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Create symbolic links" user right, this is
# a finding:
#
# Administrators
#
# If the workstation has an approved use of Hyper-V, such as being used as a dedicated admin workstation using
# Hyper-V to separate administration and standard user functions, "NT VIRTUAL MACHINES\VIRTUAL MACHINE" may be
# assigned this user right and is not a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Create symbolic links" to only include the following groups or
# accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220966r877392_rule
# STIG ID: WN10-UR-000060
# REFERENCE: 
##
try {
    $V220966 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeCreateSymbolicLinkPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220966 = $false
        }
    }
} catch {
    $V220966 = $false
}

##
# V-220968
# The Deny access to this computer from the network user right on workstations must be configured to prevent
# access from highly privileged domain accounts and local accounts on domain systems and unauthenticated access
# on all systems.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# The "Deny access to this computer from the network" right defines the accounts that are prevented from logging
# on from the network.
#
# In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the
# compromise of an entire domain.
#
# Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral
# movement resulting from credential theft attacks.
#
# The Guests group must be assigned this right to prevent unauthenticated access.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
#
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If the following groups or accounts are not defined for the "Deny access to this computer from the network"
# right, this is a finding:
#
# Domain Systems Only:
# Enterprise Admins group
# Domain Admins group
# Local account (see Note below)
#
# All Systems:
# Guests group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# Note: "Local account" is a built-in security group used to assign user rights and permissions to all local
# accounts.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Deny access to this computer from the network" to include the
# following.
#
# Domain Systems Only:
# Enterprise Admins group
# Domain Admins group
# Local account (see Note below)
#
# All Systems:
# Guests group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# Note: "Local account" is a built-in security group used to assign user rights and permissions to all local
# accounts.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220968r569187_rule
# STIG ID: WN10-UR-000070
# REFERENCE: 
##
try {
    $V220968 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyNetworkLogonRight).Split(",")

    if ($rights -notcontains "*S-1-5-32-546" -or           # Guests group
        $rights -notcontains "*S-1-5-113" -or              # Local account (https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers)
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220968 = $false
    }

} catch {
    $V220968 = $false
}

##
# V-220969
# The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access
# from highly privileged domain accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a
# batch job, such as Task Scheduler.
#
# In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks that could lead to the
# compromise of an entire domain.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If the following groups or accounts are not defined for the "Deny log on as a batch job" right, this is a
# finding.
#
# Domain Systems Only:
# Enterprise Admin Group
# Domain Admin Group
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Deny log on as a batch job" to include the following:
#
# Domain Systems Only:
# Enterprise Admin Group
# Domain Admin Group
#
##
# SEVERITY: CAT II
# RULE ID: SV-220969r857200_rule
# STIG ID: WN10-UR-000075
# REFERENCE: 
##
try {
    $V220969 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyBatchLogonRight).Split(",")

    if ($rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220969 = $false
    }

} catch {
    $V220969 = $false
}

##
# V-220970
# The Deny log on as a service user right on Windows 10 domain-joined workstations must be configured to prevent
# access from highly privileged domain accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Deny log on as a service" right defines accounts that are denied log on as a service.
#
# In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the
# compromise of an entire domain.
#
# Incorrect configurations could prevent services from starting and result in a DoS.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If the following groups or accounts are not defined for the "Deny log on as a service" right , this is a
# finding.
#
# Domain Systems Only:
# Enterprise Admins Group
# Domain Admins Group
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Deny log on as a service" to include the following:
#
# Domain Systems Only:
# Enterprise Admins Group
# Domain Admins Group
#
##
# SEVERITY: CAT II
# RULE ID: SV-220970r857203_rule
# STIG ID: WN10-UR-000080
# REFERENCE: 
##
try {
    $V220970 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyServiceLogonRight).Split(",")

    if ($rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220970 = $false
    }

} catch {
    $V220970 = $false
}

##
# V-220971
# The Deny log on locally user right on workstations must be configured to prevent access from highly privileged
# domain accounts on domain systems and unauthenticated access on all systems.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# The "Deny log on locally" right defines accounts that are prevented from logging on interactively.
#
# In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the
# compromise of an entire domain.
#
# The Guests group must be assigned this right to prevent unauthenticated access.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
#
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If the following groups or accounts are not defined for the "Deny log on locally" right, this is a finding.
#
# Domain Systems Only:
# Enterprise Admins Group
# Domain Admins Group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# All Systems:
# Guests Group
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Deny log on locally" to include the following.
#
# Domain Systems Only:
# Enterprise Admins Group
# Domain Admins Group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# All Systems:
# Guests Group
#
##
# SEVERITY: CAT II
# RULE ID: SV-220971r569187_rule
# STIG ID: WN10-UR-000085
# REFERENCE: 
##
try {
    $V220971 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyInteractiveLogonRight).Split(",")

    if ($rights -notcontains "*S-1-5-32-546" -or           # Guests group
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220971 = $false
    }

} catch {
    $V220971 = $false
}

##
# V-220972
# The Deny log on through Remote Desktop Services user right on Windows 10 workstations must at a minimum be
# configured to prevent access from highly privileged domain accounts and local accounts on domain systems and
# unauthenticated access on all systems.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.
#
# The "Deny log on through Remote Desktop Services" right defines the accounts that are prevented from logging
# on using Remote Desktop Services.
#
# If Remote Desktop Services is not used by the organization, the Everyone group must be assigned this right to
# prevent all access.
#
# In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust
# systems helps mitigate the risk of privilege escalation from credential theft attacks, which could lead to the
# compromise of an entire domain.
#
# Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral
# movement resulting from credential theft attacks.
#
# The Guests group must be assigned this right to prevent unauthenticated access.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
#
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If the following groups or accounts are not defined for the "Deny log on through Remote Desktop Services"
# right, this is a finding:
#
# If Remote Desktop Services is not used by the organization, the "Everyone" group can replace all of the groups
# listed below.
#
# Domain Systems Only:
# Enterprise Admins group
# Domain Admins group
# Local account (see Note below)
#
# All Systems:
# Guests group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# Note: "Local account" is a built-in security group used to assign user rights and permissions to all local
# accounts.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Deny log on through Remote Desktop Services" to include the following.
#
# If Remote Desktop Services is not used by the organization, assign the Everyone group this right to prevent
# all access.
#
# Domain Systems Only:
# Enterprise Admins group
# Domain Admins group
# Local account (see Note below)
#
# All Systems:
# Guests group
#
# Privileged Access Workstations (PAWs) dedicated to the management of Active Directory are exempt from denying
# the Enterprise Admins and Domain Admins groups. (See the Windows Privileged Access Workstation STIG for PAW
# requirements.)
#
# Note: "Local account" is a built-in security group used to assign user rights and permissions to all local
# accounts.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220972r852029_rule
# STIG ID: WN10-UR-000090
# REFERENCE: 
##
try {
    $V220972 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDenyInteractiveLogonRight).Split(",")
    
    if ($rights -contains "*S-1-1-0") {
        # If RDS is not used, adding "Everyone" group is okay
    } elseif ($rights -notcontains "*S-1-5-32-546" -or     # Guests group
        $rights -notcontains "*S-1-5-113" -or              # Local account
        $rights -notcontains "*" + $DomainSID + "512" -or  # Domain Admins
        $rights -notcontains "*" + $DomainSID + "519") {   # Enterprise Admins
        $V220972 = $false
    }

} catch {
    $V220972 = $false
}

##
# V-220973
# The Enable computer and user accounts to be trusted for delegation user right must not be assigned to any
# groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Enable computer and user accounts to be trusted for delegation" user right allows the "Trusted for
# Delegation" setting to be changed. This could potentially allow unauthorized users to impersonate other users.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts are granted the "Enable computer and user accounts to be trusted for delegation"
# user right, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Enable computer and user accounts to be trusted for delegation" to be
# defined but containing no entries (blank).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220973r877392_rule
# STIG ID: WN10-UR-000095
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeEnableDelegationPrivilege -eq $null) {
        $V220973 = $true
    } else {
        $V220973 = $false
    }
} catch {
    $V220973 = $false
}

##
# V-220974
# The Force shutdown from a remote system user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system which could
# result in a DoS.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Force shutdown from a remote system" user
# right, this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Force shutdown from a remote system" to only include the following
# groups or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220974r877392_rule
# STIG ID: WN10-UR-000100
# REFERENCE: 
##
try {
    $V220974 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeDebugPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220974 = $false
        }
    }
} catch {
    $V220974 = $false
}

##
# V-220975
# The Impersonate a client after authentication user right must only be assigned to Administrators, Service,
# Local Service, and Network Service.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Impersonate a client after authentication" user right allows a program to impersonate another user or
# account to run on their behalf. An attacker could potentially use this to elevate privileges.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Impersonate a client after authentication"
# user right, this is a finding:
#
# Administrators
# LOCAL SERVICE
# NETWORK SERVICE
# SERVICE
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Impersonate a client after authentication" to only include the
# following groups or accounts:
#
# Administrators
# LOCAL SERVICE
# NETWORK SERVICE
# SERVICE
#
##
# SEVERITY: CAT II
# RULE ID: SV-220975r877392_rule
# STIG ID: WN10-UR-000110
# REFERENCE: 
##
try {
    $V220975 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeImpersonatePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544", "*S-1-5-19", "*S-1-5-20", "*S-1-5-6")) {
            $V220975 = $false
        }
    }
} catch {
    $V220975 = $false
}

##
# V-220976
# The Load and unload device drivers user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by
# a user. This could potentially be used to install malicious code by an attacker.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Load and unload device drivers" user
# right, this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Load and unload device drivers" to only include the following groups or
# accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220976r877392_rule
# STIG ID: WN10-UR-000120
# REFERENCE: 
##
try {
    $V220976 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeLoadDriverPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220976 = $false
        }
    }
} catch {
    $V220976 = $false
}

##
# V-220977
# The Lock pages in memory user right must not be assigned to any groups or accounts.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# The "Lock pages in memory" user right allows physical memory to be assigned to processes, which could cause
# performance issues or a DoS.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts are granted the "Lock pages in memory" user right, this is a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Lock pages in memory" to be defined but containing no entries (blank).
#
##
# SEVERITY: CAT II
# RULE ID: SV-220977r877392_rule
# STIG ID: WN10-UR-000125
# REFERENCE: 
##
try {
    if ($SecurityPolicy.'Privilege Rights'.SeLockMemoryPrivilege -eq $null) {
        $V220977 = $true
    } else {
        $V220977 = $false
    }
} catch {
    $V220977 = $false
}

##
# V-220978
# The Manage auditing and security log user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Manage auditing and security log" user right can manage the security log and change
# auditing configurations. This could be used to clear evidence of tampering.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Manage auditing and security log" user
# right, this is a finding:
#
# Administrators
#
# If the organization has an "Auditors" group the assignment of this group to the user right would not be a
# finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Manage auditing and security log" to only include the following groups
# or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220978r852035_rule
# STIG ID: WN10-UR-000130
# REFERENCE: 
##
try {
    $V220978 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeSecurityPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220978 = $false
        }
    }
} catch {
    $V220978 = $false
}

##
# V-220979
# The Modify firmware environment values user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Modify firmware environment values" user right can change hardware configuration
# environment variables. This could result in hardware failures or a DoS.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Modify firmware environment values" user
# right, this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Modify firmware environment values" to only include the following
# groups or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220979r877392_rule
# STIG ID: WN10-UR-000140
# REFERENCE: 
##
try {
    $V220979 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeSystemEnvironmentPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220979 = $false
        }
    }
} catch {
    $V220979 = $false
}

##
# V-220980
# The Perform volume maintenance tasks user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Perform volume maintenance tasks" user right can manage volume and disk configurations.
# They could potentially delete volumes, resulting in, data loss or a DoS.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Perform volume maintenance tasks" user
# right, this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Perform volume maintenance tasks" to only include the following groups
# or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220980r877392_rule
# STIG ID: WN10-UR-000145
# REFERENCE: 
##
try {
    $V220980 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeManageVolumePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220980 = $false
        }
    }
} catch {
    $V220980 = $false
}

##
# V-220981
# The Profile single process user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Profile single process" user right can monitor non-system processes performance. An
# attacker could potentially use this to identify processes to attack.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Profile single process" user right, this
# is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Profile single process" to only include the following groups or
# accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220981r877392_rule
# STIG ID: WN10-UR-000150
# REFERENCE: 
##
try {
    $V220981 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeProfileSingleProcessPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220981 = $false
        }
    }
} catch {
    $V220981 = $false
}

##
# V-220982
# The Restore files and directories user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Restore files and directories" user right can circumvent file and directory permissions and
# could allow access to sensitive data. It could also be used to over-write more current data.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Restore files and directories" user right,
# this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Restore files and directories" to only include the following groups or
# accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220982r877392_rule
# STIG ID: WN10-UR-000160
# REFERENCE: 
##
try {
    $V220982 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeRestorePrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220982 = $false
        }
    }
} catch {
    $V220982 = $false
}

##
# V-220983
# The Take ownership of files or other objects user right must only be assigned to the Administrators group.
#
##
# DISCUSSION: 
# Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.
#
# Accounts with the "Take ownership of files or other objects" user right can take ownership of objects and make
# changes.
#
##
# CHECK: 
# Verify the effective setting in Local Group Policy Editor.
# Run "gpedit.msc".
#
# Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment.
#
# If any groups or accounts other than the following are granted the "Take ownership of files or other objects"
# user right, this is a finding:
#
# Administrators
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local
# Policies >> User Rights Assignment >> "Take ownership of files or other objects" to only include the following
# groups or accounts:
#
# Administrators
#
##
# SEVERITY: CAT II
# RULE ID: SV-220983r877392_rule
# STIG ID: WN10-UR-000165
# REFERENCE: 
##
try {
    $V220983 = $true
    $rights = ($SecurityPolicy.'Privilege Rights'.SeTakeOwnershipPrivilege).Split(",")
    foreach ($member in $rights) {
        if ($member -notin @("*S-1-5-32-544")) {
            $V220983 = $false
        }
    }
} catch {
    $V220983 = $false
}

##
# V-250319
# Hardened UNC paths must be defined to require mutual authentication and integrity for at least the \\*\SYSVOL
# and \\*\NETLOGON shares.
#
##
# DISCUSSION: 
# Additional security requirements are applied to Universal Naming Convention (UNC) paths specified in Hardened
# UNC paths before allowing access to them. This aids in preventing tampering with or spoofing of connections to
# these paths.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# If the following registry values do not exist or are not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
#
# Value Name: \\*\NETLOGON
# Value Type: REG_SZ
# Value: RequireMutualAuthentication=1, RequireIntegrity=1
#
# Value Name: \\*\SYSVOL
# Value Type: REG_SZ
# Value: RequireMutualAuthentication=1, RequireIntegrity=1
#
# Additional entries would not be a finding.
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network
# Provider >> "Hardened UNC Paths" to "Enabled" with at least the following configured in "Hardened UNC Paths:"
# (click the "Show" button to display).
#
# Value Name: \\*\SYSVOL
# Value: RequireMutualAuthentication=1, RequireIntegrity=1
#
# Value Name: \\*\NETLOGON
# Value: RequireMutualAuthentication=1, RequireIntegrity=1
#
##
# SEVERITY: CAT II
# RULE ID: SV-250319r857185_rule
# STIG ID: WN10-CC-000050
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" -Name \\*\NETLOGON -ErrorAction Stop) -eq 2 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\" -Name \\*\SYSVOL -ErrorAction Stop) -eq 2) {
        $V250319 = $true
    } else {
        $V250319 = $false
    }
} catch {
    $V250319 = $false
}


##
# V-252896
# PowerShell Transcription must be enabled on Windows 10.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Enabling PowerShell Transcription will record detailed information from the processing of PowerShell commands
# and scripts. This can provide additional detail when malware has run on a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\
#
# Value Name: EnableTranscripting
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows PowerShell >> "Turn on PowerShell Transcription" to "Enabled".
#
# Specify the Transcript output directory to point to a Central Log Server or another secure location to prevent
# user access.
#
##
# SEVERITY: CAT II
# RULE ID: SV-252896r821863_rule
# STIG ID: WN10-CC-000327
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\" -Name EnableTranscripting -ErrorAction Stop) -eq 1) {
        $V252896 = $true
    } else {
        $V252896 = $false
    }
} catch {
    $V252896 = $false
}


##
# V-256894
# Internet Explorer must be disabled for Windows 10.
#
##
# DISCUSSION: 
# Internet Explorer 11 (IE11) is no longer supported on Windows 10 semi-annual channel. 
#
##
# CHECK: 
# Determine if IE11 is installed or enabled on Windows 10 semi-annual channel.
#
# If IE11 is installed or not disabled on Windows 10 semi-annual channel, this is a finding.
#
# If IE11 is installed on a unsupported operating system and is enabled or installed, this is a finding.
#
# For more information, visit:
#
##
# FIX: 
# For Windows 10 semi-annual channel, remove or disable the IE11 application. 
#
# To disable IE11 as a standalone browser:
#
# Set the policy value for "Computer Configuration/Administrative Templates/Windows Components/Internet
# Explorer/Disable Internet Explorer 11 as a standalone browser" to "Enabled" with the option value set to
# "Never".
#
##
# SEVERITY: CAT II
# RULE ID: SV-256894r891287_rule
# STIG ID: WN10-CC-000391
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name NotifyDisableIEOptions -ErrorAction Stop) -eq 0) {
        $V256894 = $true
    } else {
        $V256894 = $false
    }
} catch {
    $V256894 = $false
}

$hash = [ordered]@{
    'V-220902 - Enable Kernel DMA Protection' = $V220902
    'V-220903 - Installed DoD Root CA Certificates in Trusted Root Store' = $V220903
    'V-220904 - Installed ECA Root CA Certificates in Trusted Root Store' = $V220904
    'V-220905 - Installed DoD Interopability Root CA Cross-certificates in Unstrusted Certificates Store' = $V220905
    'V-220906 - Installed DoD CCEB Interoperability Root CA Cross-certificates in Untrusted Certificates Store' = $V220906
    'V-220907 - Configure Default Permissions of HKLM Registry Hive' = $V220907
    'V-220908 - Disable Built-in Administrator Account' = $V220908
    'V-220909 - Disable Built-in Guest Account' = $V220909
    'V-220910 - Configure Restrict Local Account with Blank Password Network Access' = $V220910
    'V-220911 - Rename Built-in Administrator Account' = $V220911
    'V-220912 - Rename Built-in Guest Account' = $V220912
    'V-220913 - Enable Audit Policy using Subcategories' = $V220913
    'V-220914 - Require Outgoing Secure Channel Traffic be Encrypted or Signed' = $V220914
    'V-220915 - Configure Encrypt Outgoing Secure Channel Traffic' = $V220915
    'V-220916 - Configure Sign Outgoing Secure Channel Traffic' = $V220916
    'V-220919 - Configure Requre Strong Session Key' = $V220919
    'V-220920 - Configure Inactivity Screen Lock' = $V220920
    'V-220921 - Configure Legal Notice/Banner' = $V220921
    'V-220924 - Configure Smart Card Removal to Logoff or Lock' = $V220924
    'V-220925 - Configure SMB Client to Always Perform Packet Signing' = $V220925
    'V-220926 - Disable Sending of Unencrypted Passwords to 3rd Party SMB Servers' = $V220926
    'V-220927 - Configure SMB Server to Always Perform Packet Signing' = $V220927
    'V-220931 - Disable Anonymous Users from Inclusion in Everyone Group' = $V220931
    'V-220933 - Restrict Calls to Security Account Manage to Administrators' = $V220933
    'V-220934 - Disable NTLM Fallback to Null Session' = $V220934
    'V-220935 - Disable PKU2U Authentication Using Online Identities' = $V220935
    'V-220936 - Disable Use of DES and RC4 Encryption Suites in Kerberos Encryption Types' = $V220936
    'V-220939 - Configure Required LDAP Signing Level' = $V220939
    'V-220940 - Configure Session Security for NTLM SSP Clients' = $V220940
    'V-220941 - Configure Session Security for NTLM SSP Servers' = $V220941
    'V-220942 - Configure Usage of FIPS-compliant Algorithms' = $V220942
    'V-220944 - Enable UAC for Built-in Administrator' = $V220944
    'V-220945 - Enable UAC Prompt on Secure Desktop' = $V220945
    'V-220946-NoChk - Require MFA for All Accounts' = $V220946
    'V-220947 - Configure UAC to Automatically Deny Elevation Requests from Standard Users' = $V220947
    'V-220948 - Configure UAC to Detect and Prompt for Application Installations' = $V220948
    'V-220949 - Configure UAC  to only Elevate UIAccess Applications Installed to Secure Locations' = $V220949
    'V-220950 - Enable UAC' = $V220950
    'V-220951 - Configure UAC to Virtualize File and Registry to per-User Locations' = $V220951
    'V-220952 - Configure Local Administrator Accounts Max Password Age' = $V220952
    'V-220955 - Configure Preservation of Zone Info when Saving Attachments' = $V220955
    'V-220956 - Restrict Right - Access Credential Manager' = $V220956
    'V-220957 - Restrict Right - Access this Computer from Network' = $V220957
    'V-220959 - Restrict Right - Allow Log on Locally' = $V220959
    'V-220960 - Restrict Right - Backup Files and Directories' = $V220960
    'V-220961 - Restrict Right - Change System Time' = $V220961
    'V-220962 - Restrict Right - Create a Pagefile' = $V220962
    'V-220964 - Restrict Right - Create Global Ojects' = $V220964
    'V-220965 - Restrict Right - Create Permanent Shared Objects' = $V220965
    'V-220966 - Restrict Right - Create Symbolic Links' = $V220966
    'V-220968 - Restrict Right - Deny Access to Computer from Network' = $V220968
    'V-220969 - Restrict Right - Deny Log on as a Batch Job' = $V220969
    'V-220970 - Restrict Right - Deny Log on as a Service' = $V220970
    'V-220971 - Restrict Right - Deny Log on Locally' = $V220971
    'V-220972 - Restrict Right - Deny Log on through Remote Desktop Services' = $V220972
    'V-220973 - Restrict Right - Enable Computer and User Accounts to be Trusted for Delegation' = $V220973
    'V-220974 - Restrict Right - Force Shutdown from a Remote System' = $V220974
    'V-220975 - Restrict Right - Impersonate a Client after Authentication' = $V220975
    'V-220976 - Restrict Right - Load and Unload Device Drivers' = $V220976
    'V-220977 - Restrict Right - Lock Pages in Memory' = $V220977
    'V-220978 - Restrict Right - Manage Auditing and Security Log' = $V220978
    'V-220979 - Restrict Right - Modify Firmware Environment Values' = $V220979
    'V-220980 - Restrict Right - Perform Volume Maintenance Tasks' = $V220980
    'V-220981 - Restrict Right - Profile Single Process' = $V220981
    'V-220982 - Restrict Right - Restore Files and Directories' = $V220982
    'V-220983 - Restrict Right - Take Ownership of Files or Other Objects' = $V220983
    'V-250319 - Harden SYSVOL and NETLOGON UNC Paths' = $V250319
    'V-252896 - Enable PowerShell Transcription' = $V252896
    'V-256894 - Disable Internet Explorer' = $V256894
}

return $hash | ConvertTo-Json -Compress
