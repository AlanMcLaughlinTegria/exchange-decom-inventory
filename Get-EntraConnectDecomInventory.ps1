#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only inventory of the Entra Connect (Azure AD Connect) server,
    collected ahead of on-prem Exchange decommissioning.

.DESCRIPTION
    Run ON the Entra Connect server, elevated ("Run as administrator"), as a
    member of ADSyncAdmins or a local administrator. Uses the ADSync module that
    ships with Entra Connect. Makes NO changes. Nothing is emailed or uploaded;
    all output is saved locally.

    Why this matters for the decom: running without Exchange servers (the
    Exchange management tools only) depends on Exchange hybrid writeback being
    enabled and working, and on knowing which OUs and attributes are in scope.

    Output: folder of CSV/JSON + Manifest.csv, RunLog.txt, Transcript.txt, zipped.

.PARAMETER OutputRoot
    Folder to write into. Default: timestamped folder next to the script;
    falls back to C:\DecomInventory, then %TEMP%, if that is not writable.
.PARAMETER NoZip
    Leave the output folder unzipped.

.NOTES
    Version 1.1
      Fixed
      - Get-ADSyncAADCompanyFeature is skipped if this ADSync version has mandatory parameters (credentials),
        so the script cannot stop at a prompt.
      Changed
      - Recent sync errors are read from the Application log and filtered by provider name, instead of passing
        provider names to Get-WinEvent (a provider name not registered on the server raises an error).
      - Connector forest/account values are read from list- or dictionary-style parameter collections.
      - Run history shows the connector name where available; dates are written as yyyy-MM-dd HH:mm:ss.
      Added
      - Transcript.txt, output folder fallback.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [switch]$NoZip
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:ScriptVersion = '1.1'
$script:StartTime = Get-Date

function New-OutputFolder {
    param([string]$Requested, [string]$Leaf)
    $candidates = @()
    if ($Requested) { $candidates += $Requested }
    else {
        if ($PSScriptRoot) { $candidates += (Join-Path $PSScriptRoot $Leaf) }
        if ($env:SystemDrive) { $candidates += (Join-Path "$env:SystemDrive\DecomInventory" $Leaf) }
        if ($env:TEMP) { $candidates += (Join-Path $env:TEMP $Leaf) }
        $candidates += (Join-Path (Get-Location).Path $Leaf)
    }
    foreach ($c in $candidates) {
        try {
            New-Item -ItemType Directory -Path $c -Force -ErrorAction Stop | Out-Null
            $probe = Join-Path $c '.writetest'
            Set-Content -Path $probe -Value 'x' -ErrorAction Stop
            Remove-Item -Path $probe -Force -ErrorAction SilentlyContinue
            return $c
        } catch { }
    }
    throw "No writable output folder. Tried: $($candidates -join '; ')"
}

$leaf = 'DecomInventory_EntraConnect_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
try { $OutputRoot = New-OutputFolder -Requested $OutputRoot -Leaf $leaf }
catch { Write-Host $_.Exception.Message -ForegroundColor Red; return }

$script:Out = $OutputRoot
$script:Manifest = [System.Collections.Generic.List[object]]::new()
$script:LogFile = Join-Path $OutputRoot 'RunLog.txt'
$script:TranscriptOn = $false
try { Start-Transcript -Path (Join-Path $OutputRoot 'Transcript.txt') -ErrorAction Stop | Out-Null; $script:TranscriptOn = $true } catch { }

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $script:LogFile -Value $line
    switch ($Level) { 'WARN' { Write-Host $line -ForegroundColor Yellow } 'ERROR' { Write-Host $line -ForegroundColor Red } default { Write-Host $line } }
}
function Stop-RunTranscript {
    if ($script:TranscriptOn) { try { Stop-Transcript | Out-Null } catch { }; $script:TranscriptOn = $false }
}
function ConvertTo-FlatValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss') }
    if ($Value -is [System.DateTimeOffset]) { return $Value.ToString('yyyy-MM-dd HH:mm:ss zzz') }
    if ($Value -is [byte[]]) { return "<$($Value.Length) bytes>" }
    if ($Value -is [System.Collections.IDictionary]) { return (($Value.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ') }
    if ($Value -is [System.Collections.IEnumerable]) {
        return (($Value | ForEach-Object { if ($null -ne $_) { if ($_ -is [datetime]) { $_.ToString('yyyy-MM-dd HH:mm:ss') } else { "$_" } } }) -join '; ')
    }
    return "$Value"
}
function ConvertTo-Flat {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        if ($null -eq $InputObject) { return }
        $o = [ordered]@{}
        foreach ($p in $InputObject.PSObject.Properties) {
            $v = $null
            try { $v = $p.Value } catch { $v = "ERR: $($_.Exception.Message)" }
            $o[$p.Name] = ConvertTo-FlatValue $v
        }
        [PSCustomObject]$o
    }
}
function Save-Csv {
    param([object[]]$Data, [string]$Name)
    $path = Join-Path $script:Out "$Name.csv"
    $items = @($Data | Where-Object { $null -ne $_ })
    if ($items.Count -eq 0) { Set-Content -Path $path -Value '' -Encoding UTF8; return 0 }
    $items | ConvertTo-Flat | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    return $items.Count
}
function Save-Json { param($Data, [string]$Name, [int]$Depth = 6) $Data | ConvertTo-Json -Depth $Depth | Set-Content -Path (Join-Path $script:Out "$Name.json") -Encoding UTF8 }
function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, [string]$SkipReason)
    $entry = [PSCustomObject]@{ Section = $Name; Status = ''; Rows = ''; Seconds = ''; Detail = '' }
    if ($SkipReason) { $entry.Status = 'Skipped'; $entry.Detail = $SkipReason; Write-Log "SKIP  $Name - $SkipReason" 'WARN'; $script:Manifest.Add($entry); return }
    Write-Log "START $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $rows = & $Script
        $sw.Stop(); $entry.Status = 'Collected'; $entry.Rows = $(if ($null -ne $rows) { "$($rows | Select-Object -Last 1)" } else { '' }); $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Write-Log ('DONE  {0} ({1}s, rows={2})' -f $Name, $entry.Seconds, $entry.Rows)
    } catch {
        $sw.Stop(); $entry.Status = 'Failed'; $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); $entry.Detail = $_.Exception.Message
        Write-Log "FAIL  $Name - $($_.Exception.Message)" 'ERROR'
    }
    $script:Manifest.Add($entry)
}
function Get-ParamValue {
    param($Collection, [string]$Pattern)
    try {
        if ($Collection -is [System.Collections.IDictionary]) {
            foreach ($k in @($Collection.Keys)) {
                if ("$k" -match $Pattern) { $v = $Collection[$k]; if ($null -ne $v -and $null -ne $v.Value) { return "$($v.Value)" } else { return "$v" } }
            }
            return ''
        }
        $p = @($Collection | Where-Object { "$($_.Name)" -match $Pattern } | Select-Object -First 1)
        if ($p.Count) { return "$($p[0].Value)" }
    } catch { }
    return ''
}

Write-Log "Entra Connect decom inventory v$($script:ScriptVersion) starting on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion))"
Write-Log "Output: $OutputRoot"
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $isAdmin) { Write-Log 'Not elevated; ADSync cmdlets may fail.' 'WARN' }

$adsyncOk = $false
try { Import-Module ADSync -ErrorAction Stop; $adsyncOk = $true } catch { Write-Log "ADSync module not found. Is this the Entra Connect server? $($_.Exception.Message)" 'ERROR' }
$adsSkip = $(if (-not $adsyncOk) { 'ADSync module unavailable' } else { $null })

Invoke-Section 'EntraConnect-Version' {
    $rows = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $rows += Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match 'Azure AD Connect|Entra Connect|Microsoft Entra|AAD Connect|Azure Active Directory Connect|Health Agent|Password Protection' } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    $svc = Get-Service ADSync -ErrorAction SilentlyContinue
    $rows += [PSCustomObject]@{ DisplayName = 'ADSync service'; DisplayVersion = $(if ($svc) { "$($svc.Status)/$($svc.StartType)" } else { 'not found' }); Publisher = ''; InstallDate = '' }
    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $rows += [PSCustomObject]@{ DisplayName = 'Computer'; DisplayVersion = $env:COMPUTERNAME; Publisher = $(if ($os) { $os.Caption } else { '' }); InstallDate = $(if ($os) { $os.LastBootUpTime } else { '' }) }
    Save-Csv @($rows) 'EntraConnect-Version'
}

Invoke-Section 'EntraConnect-GlobalSettings' -SkipReason $adsSkip -Script {
    $gs = Get-ADSyncGlobalSettings -ErrorAction Stop
    $rows = foreach ($p in $gs.Parameters) { [PSCustomObject]@{ Name = $p.Name; Value = $p.Value } }
    Save-Csv @($rows) 'EntraConnect-GlobalSettings'
}

Invoke-Section 'EntraConnect-Scheduler' -SkipReason $adsSkip -Script {
    $s = Get-ADSyncScheduler -ErrorAction Stop
    Save-Csv @($s) 'EntraConnect-Scheduler' | Out-Null
    1
}

Invoke-Section 'EntraConnect-Connectors' -SkipReason $adsSkip -Script {
    $conns = @(Get-ADSyncConnector -ErrorAction Stop)
    $rows = foreach ($c in $conns) {
        [PSCustomObject]@{
            Name = $c.Name; Type = $c.ConnectorTypeName; Identifier = $c.Identifier
            Forest = (Get-ParamValue $c.ConnectivityParameters '^forest-name$')
            ConnectorAccount = (Get-ParamValue $c.ConnectivityParameters '^forest-login-user$|UserName')
            Partitions = ((@($c.Partitions) | ForEach-Object { $_.Name }) -join '; ')
            AttributeInclusionCount = @($c.AttributeInclusionList).Count
            ObjectInclusionList = (@($c.ObjectInclusionList) -join '; ')
            AnchorAttribute = (@($c.AnchorConstructionSettings | ForEach-Object { "$($_.ObjectType):$(@($_.AnchorAttributes) -join '+')" }) -join '; ')
        }
    }
    Save-Csv @($rows) 'EntraConnect-Connectors' | Out-Null
    # OU filtering per AD connector
    $ou = foreach ($c in $conns | Where-Object { $_.ConnectorTypeName -eq 'AD' }) {
        foreach ($p in @($c.Partitions)) {
            [PSCustomObject]@{ Connector = $c.Name; Partition = $p.Name; Selected = $p.Selected; ConnectorPartitionSelected = $p.ConnectorPartitionSelected; InclusionCount = @($p.ConnectorPartitionScope.ContainerInclusionList).Count; ExclusionCount = @($p.ConnectorPartitionScope.ContainerExclusionList).Count; Inclusions = (@($p.ConnectorPartitionScope.ContainerInclusionList) -join ' | '); Exclusions = (@($p.ConnectorPartitionScope.ContainerExclusionList) -join ' | ') }
        }
    }
    Save-Csv @($ou) 'EntraConnect-OUFiltering' | Out-Null
    # Exchange-relevant attributes in the inclusion list
    $exAttrs = foreach ($c in $conns | Where-Object { $_.ConnectorTypeName -eq 'AD' }) {
        @($c.AttributeInclusionList) | Where-Object { "$_" -match 'msExch|proxyAddresses|^mail$|mailNickname|targetAddress|legacyExchangeDN|msDS-HAB' } | ForEach-Object { [PSCustomObject]@{ Connector = $c.Name; Attribute = "$_" } }
    }
    Save-Csv @($exAttrs) 'EntraConnect-ExchangeAttributesInScope' | Out-Null
    @($rows).Count
}

Invoke-Section 'EntraConnect-SyncRules' -SkipReason $adsSkip -Script {
    $rules = @(Get-ADSyncRule -ErrorAction Stop)
    $rows = foreach ($r in $rules) {
        [PSCustomObject]@{
            Name = $r.Name; Direction = "$($r.Direction)"; Precedence = $r.Precedence; Disabled = $r.Disabled; IsStandardRule = $r.IsStandardRule
            Connector = $r.Connector; SourceObjectType = $r.SourceObjectType; TargetObjectType = $r.TargetObjectType; LinkType = $r.LinkType
            ScopeFilterCount = @($r.ScopeFilter).Count; JoinFilterCount = @($r.JoinFilter).Count; AttributeFlowCount = @($r.AttributeFlowMappings).Count
            IsExchangeHybridRule = ("$($r.Name)" -match 'Exchange Hybrid|ExchangeOnline|Out to AD - User Exchange|Out to AD - Group Exchange')
            Description = $r.Description; VersionAdded = $r.VersionAdded
        }
    }
    Save-Csv @($rows | Sort-Object Direction, Precedence) 'EntraConnect-SyncRules' | Out-Null
    # Custom rules: dump attribute flows for review
    $custom = foreach ($r in $rules | Where-Object { -not $_.IsStandardRule }) {
        foreach ($f in @($r.AttributeFlowMappings)) { [PSCustomObject]@{ Rule = $r.Name; Direction = "$($r.Direction)"; Destination = $f.Destination; Source = (@($f.Source) -join '+'); FlowType = $f.FlowType; ExecuteOnce = $f.ExecuteOnce; Expression = $f.Expression } }
    }
    Save-Csv @($custom) 'EntraConnect-CustomRuleFlows' | Out-Null
    # Hybrid writeback evidence: outbound rules to AD touching msExch* attributes
    $wb = foreach ($r in $rules | Where-Object { "$($_.Direction)" -eq 'Outbound' -and "$($_.TargetObjectType)" -in 'user', 'group', 'contact' }) {
        foreach ($f in @($r.AttributeFlowMappings) | Where-Object { "$($_.Destination)" -match '^msExch|^proxyAddresses$' }) { [PSCustomObject]@{ Rule = $r.Name; Disabled = $r.Disabled; TargetObjectType = $r.TargetObjectType; Destination = $f.Destination; Source = (@($f.Source) -join '+'); Expression = $f.Expression } }
    }
    Save-Csv @($wb) 'EntraConnect-ExchangeWritebackFlows' | Out-Null
    Save-Csv @([PSCustomObject]@{ TotalRules = $rules.Count; CustomRules = @($rules | Where-Object { -not $_.IsStandardRule }).Count; DisabledRules = @($rules | Where-Object { $_.Disabled }).Count; ExchangeHybridRulePresent = (@($rows | Where-Object { $_.IsExchangeHybridRule -and -not $_.Disabled }).Count -gt 0); ExchangeWritebackFlowCount = @($wb).Count }) 'EntraConnect-SyncRules-Summary' | Out-Null
    @($rows).Count
}

Invoke-Section 'EntraConnect-OptionalFeatures' -SkipReason $adsSkip -Script {
    # Optional features live in the global settings and the Entra ID connector's parameters; surface what the cmdlets expose.
    $rows = @()
    try { $rows += (Get-ADSyncGlobalSettings -ErrorAction Stop).Parameters | Where-Object { "$($_.Name)" -match 'Microsoft.OptionalFeature|Microsoft.Synchronize|PasswordHash|PasswordWriteback|GroupWriteback|DeviceWriteback|ExchangeMailPublicFolder|UserWriteback|DirectoryExtension|Anchor|JoinCriteria' } | ForEach-Object { [PSCustomObject]@{ Setting = $_.Name; Value = $_.Value } } } catch { }
    try {
        $aad = Get-ADSyncConnector -ErrorAction Stop | Where-Object { $_.ConnectorTypeName -eq 'Extensible2' } | Select-Object -First 1
        if ($aad) { $rows += @($aad.GlobalParameters) | Where-Object { "$($_.Name)" -match 'OptionalFeature|Exchange|Writeback|Hybrid' } | ForEach-Object { [PSCustomObject]@{ Setting = "AADConnector:$($_.Name)"; Value = $_.Value } } }
    } catch { }
    $cf = Get-Command Get-ADSyncAADCompanyFeature -ErrorAction SilentlyContinue
    if ($cf) {
        $mandatory = @($cf.Parameters.Values | Where-Object { $_.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory } })
        if ($mandatory.Count -eq 0) {
            try { $rows += Get-ADSyncAADCompanyFeature -ErrorAction Stop | ForEach-Object { $o = $_; $o.PSObject.Properties | ForEach-Object { [PSCustomObject]@{ Setting = "CompanyFeature:$($_.Name)"; Value = $_.Value } } } } catch { Write-Log "  Get-ADSyncAADCompanyFeature failed: $($_.Exception.Message)" 'WARN' }
        } else { Write-Log "  Get-ADSyncAADCompanyFeature needs $(($mandatory | ForEach-Object { $_.Name }) -join ', ') on this version; skipped" 'WARN' }
    }
    try { $rows += Get-ADSyncAutoUpgrade -ErrorAction Stop | ForEach-Object { [PSCustomObject]@{ Setting = 'AutoUpgrade'; Value = "$_" } } } catch { }
    Save-Csv @($rows) 'EntraConnect-OptionalFeatures'
}

Invoke-Section 'EntraConnect-LastRuns' -SkipReason $adsSkip -Script {
    $rows = @()
    $connNames = @{}
    try { Get-ADSyncConnector -ErrorAction Stop | ForEach-Object { $connNames["$($_.Identifier)"] = $_.Name } } catch { }
    try { $rows += Get-ADSyncConnectorRunStatus -ErrorAction Stop | ForEach-Object { [PSCustomObject]@{ Type = 'RunningNow'; Connector = $_.ConnectorName; RunProfile = $_.RunProfileName; Start = ''; End = ''; Result = 'Running' } } } catch { }
    try {
        $hist = Get-ADSyncRunProfileResult -NumberRequested 40 -ErrorAction Stop
        $rows += $hist | ForEach-Object {
            $name = $(if ($_.ConnectorName) { $_.ConnectorName } elseif ($connNames.ContainsKey("$($_.ConnectorId)")) { $connNames["$($_.ConnectorId)"] } else { "$($_.ConnectorId)" })
            [PSCustomObject]@{ Type = 'History'; Connector = $name; RunProfile = $_.RunProfileName; Start = $_.StartDate; End = $_.EndDate; Result = "$($_.Result)" }
        }
    } catch { Write-Log "  Run history unavailable: $($_.Exception.Message)" 'WARN' }
    Save-Csv @($rows) 'EntraConnect-LastRuns' | Out-Null
    # Sync errors and warnings from the Application log (last 7 days)
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = (Get-Date).AddDays(-7) } -ErrorAction SilentlyContinue |
        Where-Object { "$($_.ProviderName)" -match 'Directory Synchronization|ADSync|Entra|Azure AD|AAD' })
    Save-Csv @($ev | Group-Object ProviderName, Id | ForEach-Object { $m = ("$($_.Group[0].Message)" -split "`n")[0]; [PSCustomObject]@{ Provider = $_.Group[0].ProviderName; EventId = $_.Group[0].Id; Count = $_.Count; Last = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated; Sample = $m.Substring(0, [math]::Min(200, $m.Length)) } } | Sort-Object Count -Descending) 'EntraConnect-RecentErrors' | Out-Null
    $rows.Count
}

Invoke-Section 'EntraConnect-Local' {
    $rows = @()
    $rows += Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { [PSCustomObject]@{ Type = 'ScheduledTask'; Name = "$($_.TaskPath)$($_.TaskName)"; Detail = (($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' || '); State = "$($_.State)" } }
    $rows += Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.PathName)" -notmatch '\\Windows\\|svchost' -and $_.Name -notmatch '^ADSync$|AzureADConnect' } | ForEach-Object { [PSCustomObject]@{ Type = 'NonDefaultService'; Name = $_.DisplayName; Detail = $_.PathName; State = $_.State } }
    Save-Csv @($rows) 'EntraConnect-Local'
}

$script:Manifest | Export-Csv -Path (Join-Path $script:Out 'Manifest.csv') -NoTypeInformation -Encoding UTF8
$meta = [PSCustomObject]@{
    ScriptVersion = $script:ScriptVersion; Script = 'EntraConnect'; RunOn = $env:COMPUTERNAME; RunBy = "$env:USERDOMAIN\$env:USERNAME"
    Started = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'); Finished = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'); Elevated = $isAdmin; PSVersion = $PSVersionTable.PSVersion.ToString()
    Sections = $script:Manifest.Count; Collected = @($script:Manifest | Where-Object { $_.Status -eq 'Collected' }).Count; Failed = @($script:Manifest | Where-Object { $_.Status -eq 'Failed' }).Count; Skipped = @($script:Manifest | Where-Object { $_.Status -eq 'Skipped' }).Count
}
Save-Json $meta 'RunInfo'
Write-Log ('Finished. Sections: {0} collected, {1} failed, {2} skipped.' -f $meta.Collected, $meta.Failed, $meta.Skipped)
Stop-RunTranscript
if (-not $NoZip) {
    $zip = "$OutputRoot.zip"
    try { Compress-Archive -Path (Join-Path $OutputRoot '*') -DestinationPath $zip -Force -ErrorAction Stop; Write-Log "ZIP written: $zip"; Write-Host "`nReturn this file for analysis:`n  $zip`n" -ForegroundColor Green }
    catch { Write-Log "Zip failed: $($_.Exception.Message). Return the folder $OutputRoot instead." 'WARN' }
} else { Write-Host "`nOutput folder: $OutputRoot`n" -ForegroundColor Green }
