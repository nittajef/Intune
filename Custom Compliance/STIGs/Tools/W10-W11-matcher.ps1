
[xml]$stig10 = Get-Content -Path "U_MS_Windows_10_STIG_V2R7_Manual-xccdf.xml" -Encoding UTF8
[xml]$stig11 = Get-Content -Path "U_MS_Windows_11_STIG_V1R4_Manual-xccdf.xml" -Encoding UTF8

$matches = @{}

$list10 = @{}
$list11 = @{}

[System.Collections.ArrayList]$nomatch10 = @()
[System.Collections.ArrayList]$nomatch11 = @()

foreach ($rule10 in $stig10.Benchmark.Group.Rule) {
    $list10.Add($rule10.id.Substring(1,8), $rule10.version)
}
foreach ($rule11 in $stig11.Benchmark.Group.Rule) {
    $list11.Add($rule11.id.Substring(1,8), $rule11.version)
}

:w10 foreach ($key10 in $list10.Keys) {
    $count11 = 0
    foreach ($key11 in $list11.Keys) {
        if ($list10[$key10].Substring(5,9) -eq $list11[$key11].Substring(5,9)) {
            $matches.Add($key10, $key11)
            $list11.Remove($key11)
            continue w10
        }          
    }
    $nomatch10.Add($key10)
}
