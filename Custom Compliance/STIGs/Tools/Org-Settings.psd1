@{
    InputSTIGFile = "C:\stig.xccdf"

    # JSON output to upload in to Intune Custom Compliance policy
    # Style:   verbose - 
    #          mini - 
    #          debug - 
    # NoCheck: include - Keep rules with no technical checks in compliance policy (append rule name w/NoChk)
    #          exclude - Remove rules with no technical checks from compliance policy
    #
    OutputJSONFile = "C:\stig.json"
    JSONFileStyle = "debug"
    JSONFileInfoURL = "https://contoso.com"
    JSONFileNoCheckRules = "include"
    
    OutputPSFile = "C:\stig.ps1"
    PSFileStyle = ""

    # List all accounts that should not be evaluated in STIG rule checks
    LocalAdminAccounts = "root"
    LocalBackupOperatorAccounts = ""
    LocalHyperVAdminAccounts = ""
    
    AllNodes = @(
        @{
            NodeName = 'DSC-01'
        }
        @{
            NodeName = 'DSC-02'
        }
    )
}
