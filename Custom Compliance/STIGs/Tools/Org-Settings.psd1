$OrgSettings = Import-PowerShellDataFile "Org-Settings-W10.psd1"
$RuleChecks = Import-PowerShellDataFile $OrgSettings.input.Checks
[xml]$stig = Get-Content -Path $OrgSettings.input.STIG -Encoding UTF8

$checks = @()
$results = [ordered]@{}

$header = @(
    "##"
    "# " + $stig.Benchmark.title
    "# Version: " + $stig.Benchmark.version + ", " + $stig.Benchmark.'plain-text'.'#text'[0]
    "#"
    "# PowerShell script and accompanying JSON file for Intune Custom Compliance"
    "# were generated with: https://github.com/nittajef/Intune/"
    "##`r`n`r`n"
)

$checks += $header

function Generate-CCPolicy() {
    $rules = @()

    foreach ($rule in $stig.Benchmark.Group.Rule) {
        # Continue if rule is in a CAT category specified above
        if (($OrgSettings.severity.CAT1 -and $rule.severity -eq "high") -or
            ($OrgSettings.severity.CAT2 -and $rule.severity -eq "medium") -or
            ($OrgSettings.severity.CAT3 -and $rule.severity -eq "low")) {
        } else {
            continue
        }

        $settingName = $rule.id.Substring(1,8)

        if ($OrgSettings.nocode -contains $settingName) {
            if ($OrgSettings.output.JSONNoCheckRules -eq "exclude") {
                continue
            } else {
                $settingName = $settingName + "-NoChk"
            }
        } elseif ($OrgSettings.exemptions -contains $settingName) {
            $settingName = $settingName + "-EXM"
        } elseif ($OrgSettings.overrides.ContainsKey($settingName)) {
            $settingName = $settingName + "-OvR"
        }

        # Fill out reference section of entry, which is not used by Intune CC
        $reference = [ordered]@{}
        $reference.Add('Severity', $rule.severity)
        $reference.Add('Rule_ID', $rule.id)
        $reference.Add('STIG_ID', $rule.version)

        $cciId = @()
        $legacyId = @() 

        foreach ($ident in $rule.ident) {
            if ($ident.system -eq 'http://cyber.mil/cci') {
                $cciId += $ident.'#text'
            } elseif ($ident.system -eq 'http://cyber.mil/legacy') {
                $legacyId += $ident.'#text'
            }
        }
        if ($cciId.Count -gt 0) {$reference.Add('CCI', $cciId -join ',')}
        if ($legacyId.Count -gt 0) {$reference.Add('Legacy_IDs', $legacyId -join ',')}

        $description = switch ($OrgSettings.output.JSONStyle) {
                           "description" { [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value }
                           "fix"    { $rule.fixtext.'#text' }
                           "debug"   { "Rule check return value: {ActualValue}" } # Need to adjust PS check returns to make this useful
                       }
        $setting = [ordered]@{
                        SettingName = $settingName
                        Operator = "IsEquals"
                        DataType = "Boolean"
                        Operand = $true
                        MoreInfoUrl = $OrgSettings.output.JSONInfoURL
                        RemediationStrings = @(([ordered]@{
                            Language = "en_US"
                            Title = $settingName + " - " + $rule.title
                            Description = $description
                        }))
                        Reference = $reference
                    }
        $rules += $setting
    }

    @{"Rules" = $rules}
}

function Format-Text ($input_txt) {
    # Replace non-Latin characters that Intune doesn't like
    $input_txt = $input_txt -replace ('“|”', '"')
    $input_txt = $input_txt -replace ('…', '...')
    $input_txt = $input_txt -replace ('™', '')
    $input_txt = $input_txt -replace ('–', '-')

    foreach ($sub_txt in $input_txt) {
        if ($sub_txt -eq "`n") {
            # Add the blank lines back in for spacing
            $formatted_text += "#`r`n"
        } else {
            $sub_txt = [regex]::Matches($sub_txt,'(?<=\s|^)(.{1,110})(?=\s|$)')
            foreach ($snip in $sub_txt) {
                $formatted_text += "# " + $snip.Groups[1].Value + "`r`n"
            }
        }
        $formatted_text += "#`r`n"
    }

    # Remove last extra blank line
    $formatted_text = $formatted_text.TrimEnd("`r`n")

    $formatted_text
}

# Add any shared info needed by multiple rule checks
$SharedInfo = @()
$AccountInfo = @()
if ($OrgSettings.severity.CAT1) {
    foreach ($list in $OrgSettings.accounts.Keys) {
        if ($OrgSettings.accounts[$list].Length -gt 0) {
            $AccountInfo += "$" + $list + " = @(`"" + ($OrgSettings.accounts[$list] -join '", "') + "`")`r`n"
        }
    }
    $SharedInfo += $RuleChecks.CAT1
}
if ($OrgSettings.severity.CAT2) {
    foreach ($list in $OrgSettings.accounts.Keys) {
        if ($OrgSettings.accounts[$list].Length -gt 0) {
            $AccountInfo += "$" + $list + " = @(`"" + ($OrgSettings.accounts[$list] -join '", "') + "`")`r`n"
        }
    }
    $SharedInfo += $RuleChecks.CAT2
}
if ($OrgSettings.severity.CAT3) {
    if (!$AccountInfo) {
            foreach ($list in $OrgSettings.accounts.Keys) {
            if ($OrgSettings.accounts[$list].Length -gt 0) {
                $AccountInfo += "$" + $list + " = @(`"" + ($OrgSettings.accounts[$list] -join '", "') + "`")`r`n"
            }
        }
    }
    $SharedInfo += $RuleChecks.CAT3
}
if ($SharedInfo) {
    $checks += "#`r`n# Gather data used across multiple rule checks`r`n#`r`n"
    foreach ($data in $SharedInfo) {
        $checks += $RuleChecks.$data + "`r`n"
    }
    $checks += "`r`n"
}
if ($AccountInfo) {
    $checks += "#`r`n# List of accounts used across multiple rule checks`r`n#"
    $checks += $AccountInfo
    $checks += "`r`n"
}

$EmptyRules = 0

# Iterate through all rules in the STIG document
foreach ($rule in $stig.Benchmark.Group.Rule) {
    #
    # Skip rule if it's not in a selected severity level or in "nocheck" or "exemptions" list
    #
    if (($OrgSettings.severity.CAT1 -and $rule.severity -eq "high") -or
        ($OrgSettings.severity.CAT2 -and $rule.severity -eq "medium") -or
        ($OrgSettings.severity.CAT3 -and $rule.severity -eq "low")) {
    } else {
        continue
    }

    $ruleId = $rule.id.Substring(1,8)
    $ruleVarName = $ruleId -replace "-"

    if ($OrgSettings.nocode -contains $ruleId) {
        if ($OrgSettings.output.JSONNoCheckRules -eq "exclude") {
            continue
        }
    }

    #
    # Create rule comments (title, description, check, fix, ids)
    #
    # Split description/check/fix fields by blank lines to preserver spacing
    $formatted_title = Format-Text($rule.title)
    # Match text in VulnDiscussion section, but remove the VulnDiscussion tags
    $desc_txt = [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value
    $formatted_description = Format-Text($desc_txt -split "(?:\r?\n){2,}")
    $formatted_check = Format-Text($rule.check.'check-content' -split "(?:\r?\n){2,}")
    $formatted_fix = Format-Text($rule.fixtext.'#text' -split "(?:\r?\n){2,}")
    # Convert severity to CAT I/II/III
    $severity = switch ($rule.severity) {
                    "low" {"CAT III"}
                    "medium" {"CAT II"}
                    "high" {"CAT I"}
                }

    # If there are registry tests in rule, generate checks
    # $registryChecks holds a collection of individual registry checks, some rules have multiple
    $registryChecks = [System.Collections.ArrayList]@()
    $registryCheck = @()
    foreach ($line in $rule.check.'check-content'.Split("`n")) {
        if ($line.Contains("Registry Hive")) {
            $hive = switch -regex ($line) {
                'Registry Hive:\s+HKEY_LOCAL_MACHINE' { "HKLM:" }
                'Registry Hive:\s+HKEY_CURRENT_USER' { "HKCU:" }
                default { $null }
            }
        } elseif ($line.Contains("Registry Path:")) {
            $regPath = $line -replace 'Registry Path:\s+', "".Trim()
        } elseif ($line.Contains("Value Name:")) {
            $regName = $line -replace 'Value Name:\s+', "".Trim()
        } elseif ($line.Contains("Value:")) {
            # Match these: Value: 0x00000001 (1) (Enabled with UEFI lock)
            #              Value: 1
            if ($line.TrimEnd() -match '0x.{8}\s+\((\d+)\)') {
                $regValue = $Matches[1]
            } elseif ($line.TrimEnd() -match "(?m)Value:\s+(\d+)$") {
                $regValue = $Matches[1]
            }
            $registryCheck = $hive, $regPath, $regName, $regValue
            $registryChecks.Add($registryCheck) | Out-Null
        }
    }

    # Create check rule logic template
    $override = @{}
    $check_template = ""
    
    #
    # Create PowerShell logic check for the rule, looking in this order
    # 1. Rule in "exemptions" list
    # 2. Rule in "nocheck" list
    # 3. Rule in "overrides" list
    # 4. Rule in "checks" PSDataFile
    # 5. Rule has generated registry checks
    # 6. Empty rule template created
    #
    if ($OrgSettings.exemptions -contains $ruleId) {
        $ruleId = $ruleId + "-EXM"
        $check_template = @(
            "$" + $ruleVarName + ' = $true'
        ) -join "`r`n"
    } elseif ($OrgSettings.nocode -contains $ruleId) {
        $ruleId = $ruleId + "-NoChk"
        $check_template = @(
            "$" + $ruleVarName + ' = $true'
        ) -join "`r`n"
    } elseif ($OrgSettings.overrides.ContainsKey($ruleId)) {
        $override = $OrgSettings.overrides.$ruleId
        foreach ($setting in $override.Keys) {
            if ($override.$setting -is [array]) {
                $value = "@("
                foreach ($val in $override.$setting) {
                    $value += "`"$val`","
                }
                $value = $value.TrimEnd(",")
                $value += ")"
            } elseif ($override.$setting -is [int]) {
                $value = $override.$setting
            } else {
                $value = '"' + $override.$setting + '"'
            }
            $check_template += "`$${setting} = $value`r`n"
        }
        $check_template += $RuleChecks.$ruleId
        $ruleId = $ruleId + "-OvR"
    } elseif ($RuleChecks.$ruleId) {
        $check_template = $RuleChecks.$ruleId
    } elseif ($registryChecks) {
        # Template for the PowerShell registry check for the rule
        $psRegChecks = "    if ("
        foreach ($check in $registryChecks) {
            $psRegChecks += "(Get-ItemPropertyValue -Path `""+ $check[0] + $check[1] + "`" -Name " + $check[2] + " -ErrorAction Stop) -eq " + $check[3] + " -and`r`n        "
        }
        # Replace last entries "-and" and close the "if" conditional
        $psRegChecks = $psRegChecks.TrimEnd(" -and`r`n")
        $psRegChecks += ") {"

        $check_template = @(
            "try {"
                $psRegChecks
            "        $" + $ruleVarName + ' = $true'
            "    } else {"
            "        $" + $ruleVarName + ' = $false'
            "    }"
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n"
        ) -join "`r`n"
    } else {
        $check_template = @(
            "try {"
            "    "
            "    #$" + $ruleVarName + ' = $true'
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n`r`n"
        ) -join "`r`n"
        $EmptyRules++
    }

    # Output full check/logic test text for each rule
    $check = "##`r`n"
    $check += "# " + $ruleId + "`r`n"
    $check += $formatted_title + "`r`n"
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# DISCUSSION: `r`n"
        $check += $formatted_description + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# CHECK: `r`n"
        $check += $formatted_check + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# FIX: `r`n"
        $check += $formatted_fix + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -ne 'zen') {
        $check += "##`r`n"
        $check += "# SEVERITY: " + $severity + "`r`n"
        $check += "# RULE ID: " + $rule.id + "`r`n"
        $check += "# STIG ID: " + $rule.version + "`r`n"
        $check += "# REFERENCE: `r`n"
    }
    $check += "##`r`n"
    $check += $check_template + "`r`n"

    $checks += $check
    $results.Add($ruleId, "$" + $ruleVarName)
}

# Create the return hash of check values
$ret_hash = '$hash = [ordered]@{' + "`r`n"
foreach ($key in $results.Keys) {
    $ret_hash += "    '" + $key + "' = " + $($results[$key]) + "`r`n"
}
$ret_hash += "}`r`n`r`n"
$ret_hash += 'return $hash | ConvertTo-Json -Compress'
$checks += $ret_hash  

Generate-CCPolicy | ConvertTo-Json -Depth 4 | Out-File $OrgSettings.output.JSON
$checks | Out-File -FilePath $OrgSettings.output.PS
Write-Host("There are $EmptyRules unfinished rule checks")
