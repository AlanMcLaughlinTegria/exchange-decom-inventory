# Checks the pure helper functions of the inventory scripts against known inputs.
# Run: powershell -ExecutionPolicy Bypass -File .\tests\Test-Helpers.ps1   (exit code = number of failures)
# Under ConstrainedLanguage the quoted-field Split-CsvLine cases are skipped; run in FullLanguage for all of them.
param([string]$RepoDir = (Split-Path $PSScriptRoot -Parent))
$tmp = Join-Path $env:TEMP 'decom-extracted-helpers.ps1'
$text = @()
foreach ($pair in @(
    @('Get-ExchOnPremDecomInventory.ps1', @('ConvertTo-FlatValue', 'Split-CsvLine', 'ConvertFrom-6to4', 'Get-EntraTenantHint', 'Get-SourceClass', 'Get-EndpointIp')),
    @('Get-EXODecomInventory.ps1', @('ConvertTo-Ip4Number', 'ConvertTo-Ip4Range', 'Test-Ip4InRanges', 'Get-MxProvider')))) {
    $src = Get-Content -Raw (Join-Path $RepoDir $pair[0])
    foreach ($fn in $pair[1]) {
        $m = [regex]::Match($src, "(?ms)^function $fn \{.*?^\}")
        if (-not $m.Success) { "MISSING $fn"; continue }
        $text += $m.Value
    }
}
$text -join "`r`n`r`n" | Out-File -FilePath $tmp -Encoding utf8
. $tmp

$fail = 0
function Check($name, $got, $want) {
    $g = ($got | ForEach-Object { "$_" }) -join '|'; $w = ($want | ForEach-Object { "$_" }) -join '|'
    if ($g -ceq $w) { "PASS $name" } else { "FAIL $name`n  got:  $g`n  want: $w"; $script:fail++ }
}

# Split-CsvLine (uses .NET List/StringBuilder: FullLanguage only)
$full = ($ExecutionContext.SessionState.LanguageMode -eq "FullLanguage")
if (-not $full) { "SKIP Split-CsvLine quoted cases (ConstrainedLanguage)" }
Check 'csv plain' (Split-CsvLine 'a,b,c') @('a', 'b', 'c')
if ($full) { Check 'csv quoted comma' (Split-CsvLine 'a,"b,c",d') @('a', 'b,c', 'd')
Check 'csv escaped quote' (Split-CsvLine 'a,"say ""hi""",z') @('a', 'say "hi"', 'z')
Check 'csv trailing empty' (Split-CsvLine 'a,b,') @('a', 'b', '')
Check 'csv quoted last' (Split-CsvLine 'a,"b,c"') @('a', 'b,c')
Check 'csv count with quotes' ((Split-CsvLine '2026-10-01T00:00:00Z,"x,y",,Smtp~u@d.com,"Microsoft Office/16.0 (Windows NT 10.0, x)",10.1.1.1').Count) @(6)
Check 'csv field after quoted' ((Split-CsvLine '2026,"x,y",,Smtp~u@d.com')[3]) @('Smtp~u@d.com') }

# 6to4
Check '6to4 server' (ConvertFrom-6to4 '2002:0a14:1e28::0a14:1e28') @('10.20.30.40')
Check '6to4 none' (ConvertFrom-6to4 'fe80::1') @('')

# Tenant hint
Check 'tenant' (Get-EntraTenantHint 'Account created by Microsoft Azure Active Directory Connect with installation identifier 99 running on computer SYNC02 configured to synchronize to tenant fabrikam.onmicrosoft.com. This account must') @('fabrikam.onmicrosoft.com')
Check 'tenant none' (Get-EntraTenantHint 'Service account') @('')

# Source class
$script:ExchangeServerIps = @{ '10.20.30.40' = 'EX01' }
Check 'class probe' (Get-SourceClass '10.20.30.41' 'smtp.availability.contoso.com') @('HealthProbe')
Check 'class 6to4 server' (Get-SourceClass '2002:0a14:1e28::0a14:1e28' 'EX01.contoso.local') @('ExchangeServer:EX01')
Check 'class client' (Get-SourceClass '10.1.2.3' 'nms.contoso.local') @('Client')
Check 'class loopback' (Get-SourceClass '127.0.0.1' '') @('Loopback')

# MX provider
Check 'mx barracuda' (Get-MxProvider 'd123456a.ess.barracudanetworks.com') @('Barracuda Email Gateway Defense')
Check 'mx eop' (Get-MxProvider 'contoso-com.mail.protection.outlook.com.') @('Exchange Online Protection')
Check 'mx mimecast' (Get-MxProvider 'us-smtp-inbound-1.mimecast.com') @('Mimecast')
Check 'mx other' (Get-MxProvider 'mail.contoso.com') @('Other (on-prem or unrecognised)')
Check 'mx empty' (Get-MxProvider '') @('')

# CIDR
$r = @(ConvertTo-Ip4Range '198.51.100.0/24')
Check 'cidr in' (Test-Ip4InRanges '198.51.100.251' $r) @('True')
Check 'cidr out' (Test-Ip4InRanges '198.51.101.1' $r) @('False')
Check 'cidr single' (Test-Ip4InRanges '203.0.113.44' @(ConvertTo-Ip4Range '203.0.113.44')) @('True')
Check 'cidr /28 edge' ((Test-Ip4InRanges '203.0.113.48' @(ConvertTo-Ip4Range '203.0.113.60/28')), (Test-Ip4InRanges '203.0.113.63' @(ConvertTo-Ip4Range '203.0.113.60/28')), (Test-Ip4InRanges '203.0.113.47' @(ConvertTo-Ip4Range '203.0.113.60/28'))) @('True', 'True', 'False')
Check 'cidr ipv6 skip' (Test-Ip4InRanges '2a01:111::1' $r) @('False')
Check 'cidr /32' ((Test-Ip4InRanges '10.0.0.5' @(ConvertTo-Ip4Range '10.0.0.5/32')), (Test-Ip4InRanges '10.0.0.6' @(ConvertTo-Ip4Range '10.0.0.5/32'))) @('True', 'False')
Check 'cidr /0' (Test-Ip4InRanges '203.0.113.9' @(ConvertTo-Ip4Range '0.0.0.0/0')) @('True')
Check 'cidr dash range' ((Test-Ip4InRanges '10.20.30.40' @(ConvertTo-Ip4Range '10.20.30.39-10.20.30.41')), (Test-Ip4InRanges '10.20.30.42' @(ConvertTo-Ip4Range '10.20.30.39-10.20.30.41'))) @('True', 'False')
Check 'cidr bad input' (($null -eq (ConvertTo-Ip4Range '300.1.1.1')), ($null -eq (ConvertTo-Ip4Range 'mail.contoso.com')), ($null -eq (ConvertTo-Ip4Range '10.0.0.0/33'))) @('True', 'True', 'True')
Check 'cidr unaligned base' ((Test-Ip4InRanges '198.51.96.1' @(ConvertTo-Ip4Range '198.51.98.0/21')), (Test-Ip4InRanges '198.51.104.0' @(ConvertTo-Ip4Range '198.51.98.0/21'))) @('True', 'False')

"`n$fail failure(s)"
exit $fail
