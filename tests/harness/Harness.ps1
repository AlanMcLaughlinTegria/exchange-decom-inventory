# Runs one of the decom scripts with every Exchange/Graph/AD/Windows-only command stubbed.
# Fixture files define $global:Fix['Cmd-Name'] = { param($p) ... } for specific behaviour;
# anything else named Get-*/Search-* returns two generic objects.
# Normally driven by Run-AllTests.ps1; can also be run directly for one scenario.
param(
    [Parameter(Mandatory)][string]$Target,
    [string[]]$Fixtures = @(),
    [hashtable]$ScriptArgs = @{},
    [string]$ScriptArgsJson,        # alternative to -ScriptArgs when called through pwsh -File
    [string[]]$ForceStub = @(),     # real cmdlets to shadow (Start-Sleep, Invoke-RestMethod, ...)
    [string[]]$NoStub = @()         # commands to leave missing (simulate absent cmdlets)
)
$ErrorActionPreference = 'Continue'
if ($ScriptArgsJson) { $ScriptArgs = @{}; (ConvertFrom-Json $ScriptArgsJson).PSObject.Properties | ForEach-Object { $ScriptArgs[$_.Name] = $_.Value } }
# pwsh -File passes "a,b" as one string
$Fixtures = @($Fixtures | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$ForceStub = @($ForceStub | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$NoStub = @($NoStub | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$global:StubCalls = [System.Collections.Generic.List[object]]::new()
$global:Fix = @{}
$global:FixState = @{}

function global:ConvertTo-StubParams {
    param([object[]]$Arguments)
    $p = [ordered]@{}; $pos = 0; $i = 0
    while ($i -lt $Arguments.Count) {
        $a = $Arguments[$i]
        if ($a -is [string] -and $a -match '^-([A-Za-z][\w]*)(:?)$') {
            $name = $Matches[1]
            if ($Matches[2] -eq ':' -or ($i + 1 -lt $Arguments.Count -and -not ($Arguments[$i + 1] -is [string] -and $Arguments[$i + 1] -match '^-[A-Za-z]'))) {
                $p[$name] = $Arguments[$i + 1]; $i += 2; continue
            }
            $p[$name] = $true; $i++; continue
        }
        $p["Pos$pos"] = $a; $pos++; $i++
    }
    $p
}

function global:New-GenericObj {
    param([string]$Cmd, [int]$Count = 2)
    $base = $Cmd -replace '^(Get|Search)-', ''
    foreach ($n in 1..$Count) {
        $o = [PSCustomObject]@{
            Name = "$base-$n"; Identity = "$base-$n"; DisplayName = "$base Display $n"
            PrimarySmtpAddress = "$($base.ToLower())$n@contoso.com"; Alias = "$($base.ToLower())$n"
            DistinguishedName = "CN=$base-$n,OU=Test,DC=contoso,DC=com"
            Guid = [guid]::NewGuid(); ExchangeGuid = [guid]::NewGuid(); ArchiveGuid = [guid]::Empty
            Enabled = $true; State = 'Enabled'; Status = 'Active'
            WhenCreated = (Get-Date).AddDays(-400 + $n); WhenChanged = (Get-Date).AddDays(-$n)
            WhenChangedOffset = [DateTimeOffset]::Now
            EmailAddresses = @("SMTP:$($base.ToLower())$n@contoso.com", "smtp:$($base.ToLower())$n@contoso.mail.onmicrosoft.com")
            Members = @('CONTOSO\alice', 'CONTOSO\bob')
            Settings = @{ KeyA = 'ValA'; KeyB = 2 }
            Blob = [byte[]](1, 2, 3, 4)
            NullProp = $null
            Dates = @((Get-Date), (Get-Date).AddDays(-1))
        }
        # property whose getter throws, to exercise ConvertTo-Flat's try/catch
        $o | Add-Member -MemberType ScriptProperty -Name Broken -Value { throw 'getter exploded' }
        $o
    }
}

# Fixtures first, so they can also define real functions (with param blocks)
foreach ($f in $Fixtures) { . $f }

# Collect every command the target script calls
$tok = $null; $err = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $Target).Path, [ref]$tok, [ref]$err)
$defined = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object { $_.Name })
$names = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
# Commands only referenced by string (Get-Safe 'Get-Foo', $map values)
$strCmds = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value } | Where-Object { $_ -match '^(Get|Search|Connect|Disconnect)-[A-Za-z0-9]+$' } | Sort-Object -Unique)
$names = @($names + $strCmds + @($global:Fix.Keys) | Sort-Object -Unique)

$stubbed = @()
foreach ($n in $names) {
    if ($n -in $defined -or $n -in $NoStub) { continue }
    if ($n -notin $ForceStub -and (Get-Command -Name $n -ErrorAction SilentlyContinue)) { continue }
    $body = @"
`$p = ConvertTo-StubParams `$args
`$global:StubCalls.Add([PSCustomObject]@{ Cmd = '$n'; Params = ((`$p.Keys | ForEach-Object { "`$_=`$(`$p[`$_])" }) -join ' ') })
if (`$global:Fix.ContainsKey('$n')) { & `$global:Fix['$n'] `$p `$input }
elseif ('$n' -match '^(Get|Search)-') { New-GenericObj '$n' }
"@
    Set-Item -Path "function:global:$n" -Value ([scriptblock]::Create($body))
    $stubbed += $n
}
foreach ($n in $NoStub) { if (Test-Path "function:global:$n") { Remove-Item "function:global:$n" } }
Write-Host "[harness] stubbed $($stubbed.Count) commands; running $Target" -ForegroundColor Cyan

& $Target @ScriptArgs

Write-Host "[harness] $($global:StubCalls.Count) stub calls" -ForegroundColor Cyan
$global:StubCalls | Group-Object Cmd | Sort-Object Count -Descending | Select-Object Count, Name | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
