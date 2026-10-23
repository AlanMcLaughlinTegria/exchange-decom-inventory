#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only discovery inventory of an on-premises Exchange (2016/2019) hybrid
    environment, collected ahead of on-prem Exchange decommissioning.

.DESCRIPTION
    Run ON an Exchange server, elevated ("Run as administrator"), either in the
    Exchange Management Shell or in a normal Windows PowerShell 5.1 window (the
    script then loads the Exchange snap-in).

    The script makes NO configuration changes. It only calls Get-*/Search-*
    cmdlets, reads log and configuration files, queries AD via ADSI and performs
    DNS lookups. The only outbound web request is an optional download of the
    public Microsoft 365 IP list from endpoints.office.com. Nothing is emailed
    or uploaded; all output is saved locally.

    Organisation-wide sections run once. Log-file sections read every Exchange
    server over the admin share (\\server\C$) unless -SkipRemoteServers is used.
    Server-local sections (Local-*) describe the server the script runs on.

    Output: a folder of CSV/JSON/TXT files plus Manifest.csv (every section with
    Collected / Skipped / Failed status), RunLog.txt and Transcript.txt. The
    folder is zipped at the end. Return the ZIP for analysis.

.PARAMETER OutputRoot
    Folder to write into. Default: a timestamped folder next to the script;
    falls back to C:\DecomInventory, then %TEMP%, if that is not writable.
.PARAMETER TrackingDays
    Days of message tracking logs to analyse. 0 (default) = everything on disk.
.PARAMETER IisDays
    Days of IIS logs to analyse. Default 90.
.PARAMETER AuditDays
    Days of admin audit log to summarise. Default 90.
.PARAMETER PublicDnsServer
    Resolver for the "public" DNS view. Default 8.8.8.8, falls back to 1.1.1.1.
.PARAMETER IncludeSubjects
    Include truncated message subjects in the message tracking evidence. Off by
    default because subjects can contain sensitive data.
.PARAMETER IncludeBackEndIisLogs
    Also parse the "Exchange Back End" IIS site. Off by default: it repeats the
    front-end traffic as server-to-server proxy requests and doubles run time.
.PARAMETER SkipTrackingLogs
    Skip the message tracking log analysis.
.PARAMETER SkipProtocolLogs
    Skip the SMTP receive protocol log analysis.
.PARAMETER SkipIisLogs
    Skip the IIS log analysis.
.PARAMETER SkipRemoteServers
    Read log files on this server only.
.PARAMETER SkipHttpProxyLogs
    Skip the HttpProxy log analysis (which mailbox each Autodiscover, MAPI, EWS,
    RPC/HTTP and ActiveSync request was for).
.PARAMETER TrustedForest
    Extra forest names to check for Exchange objects, Autodiscover SCPs and SCP
    pointers. Forests with a trust to this one are checked automatically.
.PARAMETER ForestCredential
    Credential for reading other forests (only needed when the trust does not
    let the current account read their configuration partition).
.PARAMETER NoZip
    Leave the output folder unzipped.

.EXAMPLE
    .\Get-ExchOnPremDecomInventory.ps1
.EXAMPLE
    .\Get-ExchOnPremDecomInventory.ps1 -TrackingDays 30 -IisDays 30

.NOTES
    Version 1.2
      Added
      - Topology-ForestExchangePresence / -ForestSCPs: Exchange organizations, servers, Autodiscover
        SCPs and SCP pointers in every trusted forest, and the tenant each Entra Connect account syncs to.
      - Evidence-HttpProxy-ByUserTarget / -ByTarget: which mailbox each Autodiscover, MAPI, EWS, RPC/HTTP
        and ActiveSync request opened (shows remote public-folder and delegate access), all servers.
      - Evidence-ReceiveConnectorUsage: every receive connector with its client sessions, mail and
        accepted messages in the protocol-log window, including connectors with none.
      - Evidence-MessageTracking-OutcomeBySource: per original sender IP, how many messages were
        delivered, sent on, or failed, with the failed recipients and reason.
      - SMTP protocol log sources now carry recipients, accepted/rejected counts and a source class
        (health probe, Exchange server, client).
      - Recipients-PublicFolderStatistics / -PublicFolderPermissions: per-folder size, items, dates and
        non-default permissions.
      - Topology-NamespaceCheck: every Exchange host name with its internal and public addresses, flagging
        names that resolve to the DAG cluster IP and public wildcard records.
      - Findings: rule-based summary of what the evidence shows (unused connectors, failing relay sources,
        namespace on the DAG IP, other Exchange orgs, multiple tenants, Hybrid Agent location, system
        mailboxes on dismounted databases, remote public-folder access).
      Changed
      - Hybrid Agent detection checks every Exchange server, not only the local one.
      - Evidence-HttpProxyLogs-Depth covers all servers.
    Version 1.1
      Fixed
      - Admin audit log depth summary failed at run time ("The term 'if' is not recognized").
      - Microsoft 365 IP matching never worked (subnet mask conversion threw); IsMicrosoftIP is now populated.
      - AD naming contexts are read by value; .ToString() on an ADSI property returns the collection type name,
        which broke the schema/organisation version, Autodiscover SCP and Entra Connect account lookups.
      - SMTP protocol log parser now takes the authenticated account from the data field
        (context "authenticated"); previously the AuthUsers column stayed empty.
      - Log files that are currently being written (today's log) are read with shared access instead of skipped.
      - POP3/IMAP4 log columns are located from the #Fields header (previously a fixed column index).
      - IIS noise filter no longer drops real clients such as the EWS Managed API ("ExchangeServicesClient").
      - IIS sections read applicationHost.config directly; the WebAdministration module is no longer needed.
      - A cmdlet or switch missing on a given build (Get-Mailbox -AuditLog, Get-DlpPolicy, UM cmdlets, ...)
        no longer aborts the whole section.
      - Wildcard accepted domains (*.contoso.com) no longer produce invalid DNS lookups.
      Changed
      - Message subjects are excluded unless -IncludeSubjects is used.
      - The "Exchange Back End" IIS site is skipped unless -IncludeBackEndIisLogs is used.
      - Mailbox statistics are read per database (one call per database) with a per-mailbox fallback.
      - Dates in CSV files are written as yyyy-MM-dd HH:mm:ss.
      Added
      - OriginalClientIp in the message tracking evidence, Transcript.txt, output folder fallback.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [int]$TrackingDays = 0,
    [int]$IisDays = 90,
    [int]$AuditDays = 90,
    [string]$PublicDnsServer = '8.8.8.8',
    [switch]$IncludeSubjects,
    [switch]$IncludeBackEndIisLogs,
    [switch]$SkipTrackingLogs,
    [switch]$SkipProtocolLogs,
    [switch]$SkipIisLogs,
    [switch]$SkipRemoteServers,
    [switch]$SkipHttpProxyLogs,
    [string[]]$TrustedForest,
    [pscredential]$ForestCredential,
    [switch]$NoZip
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$WarningPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$script:ScriptVersion = '1.2'
$script:StartTime = Get-Date

# ---------------------------------------------------------------------------
# Output folder, logging and export helpers
# ---------------------------------------------------------------------------
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

$leaf = 'DecomInventory_OnPrem_{0}_{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd_HHmmss')
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
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
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
            if ($p.Name -in 'PSComputerName', 'RunspaceId', 'PSShowComputerName') { continue }
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

function Save-Text {
    param([object[]]$Data, [string]$Name)
    $Data | Format-List * | Out-String -Width 4096 | Set-Content -Path (Join-Path $script:Out "$Name.txt") -Encoding UTF8
}

function Save-Json {
    param($Data, [string]$Name, [int]$Depth = 6)
    $Data | ConvertTo-Json -Depth $Depth | Set-Content -Path (Join-Path $script:Out "$Name.json") -Encoding UTF8
}

function Invoke-Section {
    param([string]$Name, [scriptblock]$Script, [string]$SkipReason)
    $entry = [PSCustomObject]@{ Section = $Name; Status = ''; Rows = ''; Seconds = ''; Detail = '' }
    if ($SkipReason) {
        $entry.Status = 'Skipped'; $entry.Detail = $SkipReason
        Write-Log "SKIP  $Name - $SkipReason" 'WARN'
        $script:Manifest.Add($entry); return
    }
    Write-Log "START $Name"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $rows = & $Script
        $sw.Stop()
        $entry.Status = 'Collected'
        $entry.Rows = $(if ($null -ne $rows) { "$($rows | Select-Object -Last 1)" } else { '' })
        $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1)
        Write-Log ('DONE  {0} ({1}s, rows={2})' -f $Name, $entry.Seconds, $entry.Rows)
    } catch {
        $sw.Stop()
        $entry.Status = 'Failed'; $entry.Seconds = [math]::Round($sw.Elapsed.TotalSeconds, 1); $entry.Detail = $_.Exception.Message
        Write-Log "FAIL  $Name - $($_.Exception.Message)" 'ERROR'
    }
    $script:Manifest.Add($entry)
}

# Runs a Get-* command only if it exists on this build; a missing command, an
# unsupported parameter or a terminating error is logged and returns nothing
# instead of aborting the calling section.
function Get-Safe {
    param([Parameter(Mandatory = $true)][string]$Command, [hashtable]$Params = @{})
    if (-not (Get-Command -Name $Command -ErrorAction SilentlyContinue)) { Write-Log "  $Command is not available on this build; skipped" 'WARN'; return }
    $ev = $null
    try { & $Command @Params -ErrorAction SilentlyContinue -ErrorVariable ev }
    catch { Write-Log "  $Command failed: $($_.Exception.Message)" 'WARN'; return }
    if ($ev) { Write-Log ('  {0}: {1} error(s), first: {2}' -f $Command, @($ev).Count, "$(@($ev)[0])") 'WARN' }
}

function Get-DirStats {
    param([string]$Path, [string]$Filter = '*')
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return [PSCustomObject]@{ Exists = $false; Files = 0; SizeMB = 0; Oldest = ''; Newest = '' } }
    $files = @(Get-ChildItem -LiteralPath $Path -Filter $Filter -File -Recurse -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) { return [PSCustomObject]@{ Exists = $true; Files = 0; SizeMB = 0; Oldest = ''; Newest = '' } }
    $sorted = $files | Sort-Object LastWriteTime
    [PSCustomObject]@{
        Exists = $true; Files = $files.Count
        SizeMB = [math]::Round(($files | Measure-Object Length -Sum).Sum / 1MB, 1)
        Oldest = $sorted[0].LastWriteTime; Newest = $sorted[-1].LastWriteTime
    }
}

function ConvertTo-UncPath {
    param([string]$Server, [string]$LocalPath)
    if (-not $LocalPath -or $LocalPath -notmatch '^([A-Za-z]):\\(.*)$') { return $null }
    return "\\$Server\$($Matches[1])`$\$($Matches[2])"
}

function Get-DaysAvailable { param($Oldest) if ($Oldest -is [datetime]) { [math]::Round(((Get-Date) - $Oldest).TotalDays, 1) } else { '' } }

# "10.1.2.3:25" -> 10.1.2.3, "[fe80::1]:25" -> fe80::1, bare addresses unchanged
function Get-EndpointIp {
    param([string]$Endpoint)
    if (-not $Endpoint) { return '' }
    $e = $Endpoint.Trim().Trim('"')
    if ($e -match '^\[([^\]]+)\](:\d+)?$') { return $Matches[1] }
    if ($e -match '^(\d{1,3}(\.\d{1,3}){3})(:\d+)?$') { return $Matches[1] }
    return $e
}

# Opens a log file that the owning service may still be writing to.
function Open-LogReader {
    param([string]$Path)
    $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    [System.IO.StreamReader]::new($fs)
}

function Find-FieldIndex {
    param([string[]]$Fields, [string[]]$Names, [int]$Default)
    for ($i = 0; $i -lt $Fields.Count; $i++) { if ($Names -contains $Fields[$i].Trim()) { return $i } }
    return $Default
}

function Get-AdsiValue {
    param($Entry, [string]$Name)
    try { return "$(@($Entry.$Name)[0])" } catch { return "ERR: $($_.Exception.Message)" }
}

function Get-AccountDisabled {
    param($User)
    if (-not $User) { return '' }
    if ($null -ne $User.AccountDisabled -and "$($User.AccountDisabled)" -ne '') { return "$($User.AccountDisabled)" }
    return ("$($User.UserAccountControl)" -match 'AccountDisabled').ToString()
}

# Splits one comma-separated log line, honouring "quoted, fields" (HttpProxy logs quote some values)
function Split-CsvLine {
    param([string]$Line)
    if ($Line.IndexOf('"') -lt 0) { return , $Line.Split(',') }
    $out = New-Object System.Collections.Generic.List[string]
    $i = 0; $n = $Line.Length
    while ($i -le $n) {
        if ($i -lt $n -and $Line[$i] -eq '"') {
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $n) {
                $q = $Line.IndexOf('"', $i)
                if ($q -lt 0) { [void]$sb.Append($Line.Substring($i)); $i = $n; break }
                [void]$sb.Append($Line.Substring($i, $q - $i))
                if ($q + 1 -lt $n -and $Line[$q + 1] -eq '"') { [void]$sb.Append('"'); $i = $q + 2 } else { $i = $q + 1; break }
            }
            $out.Add($sb.ToString())
            $c = $Line.IndexOf(',', $i)
            if ($c -lt 0) { break }
            $i = $c + 1
        } else {
            $c = $Line.IndexOf(',', $i)
            if ($c -lt 0) { $out.Add($Line.Substring($i)); break }
            $out.Add($Line.Substring($i, $c - $i)); $i = $c + 1
        }
    }
    return , $out.ToArray()
}

# ADSI entry, using -ForestCredential when given
function Get-DirEntry {
    param([string]$Path)
    if ($ForestCredential) { return New-Object System.DirectoryServices.DirectoryEntry($Path, $ForestCredential.UserName, $ForestCredential.GetNetworkCredential().Password) }
    New-Object System.DirectoryServices.DirectoryEntry($Path)
}

# LDAP search returning flat objects (property values joined with '; ')
function Find-Adsi {
    param($Root, [string]$Filter, [string[]]$Properties, [string]$Scope = 'Subtree')
    $searcher = New-Object System.DirectoryServices.DirectorySearcher($Root)
    $searcher.Filter = $Filter; $searcher.PageSize = 500; $searcher.SearchScope = $Scope
    $null = $searcher.PropertiesToLoad.AddRange($Properties)
    $found = $searcher.FindAll()
    try {
        foreach ($r in $found) {
            $o = [ordered]@{}
            foreach ($p in $Properties) { $o[$p] = (@($r.Properties[$p.ToLower()]) | ForEach-Object { ConvertTo-FlatValue $_ }) -join '; ' }
            [PSCustomObject]$o
        }
    } finally { $found.Dispose() }
}

# 2002:0a14:1e28::0a14:1e28 (6to4) -> 10.20.30.40, anything else -> ''
function ConvertFrom-6to4 {
    param([string]$Ip)
    if ($Ip -notmatch '^2002:([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):') { return '' }
    $a = [int]"0x$($Matches[1])"; $b = [int]"0x$($Matches[2])"
    '{0}.{1}.{2}.{3}' -f ($a -shr 8), ($a -band 255), ($b -shr 8), ($b -band 255)
}

# "...configured to synchronize to tenant contoso.onmicrosoft.com. This account..." -> contoso.onmicrosoft.com
function Get-EntraTenantHint {
    param([string]$Description)
    if ("$Description" -match '(?i)tenant\s+([a-z0-9-]+\.onmicrosoft\.(com|us|de|cn))') { return $Matches[1].ToLower() }
    ''
}

# Probe / ExchangeServer / Client for an SMTP or HTTP source address
function Get-SourceClass {
    param([string]$Ip, [string]$Ehlo)
    if ($Ehlo -match '(?i)^smtp\.availability\.contoso\.com$') { return 'HealthProbe' }
    if ($Ip -in '127.0.0.1', '::1') { return 'Loopback' }
    if ($Ip -match '^(?i)fe80:|^169\.254\.') { return 'LinkLocal' }
    $v4 = ConvertFrom-6to4 $Ip
    foreach ($x in @($Ip, $v4)) { if ($x -and $script:ExchangeServerIps.ContainsKey($x)) { return "ExchangeServer:$($script:ExchangeServerIps[$x])" } }
    'Client'
}

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
Write-Log "Exchange on-prem decom inventory v$($script:ScriptVersion) starting on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion))"
Write-Log "Output: $OutputRoot"

$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $isAdmin) { Write-Log 'Not running elevated. Log file reads and some local sections may fail.' 'WARN' }

if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) {
    Write-Log 'Exchange cmdlets not loaded; adding the Exchange snap-in.'
    try { Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop } catch { }
    if (-not (Get-Command Get-ExchangeServer -ErrorAction SilentlyContinue)) {
        Write-Log 'Could not load the Exchange cmdlets. Run this on an Exchange server, from the Exchange Management Shell or an elevated Windows PowerShell.' 'ERROR'
        Stop-RunTranscript
        return
    }
}
$script:ExchMode = $(if ((Get-Command Get-ExchangeServer).CommandType -eq 'Cmdlet') { 'Snap-in' } else { 'Remote EMS session' })
Write-Log "Exchange cmdlets: $($script:ExchMode)"
try { Set-ADServerSettings -ViewEntireForest $true -ErrorAction SilentlyContinue } catch { }

$script:ExchInstall = $env:ExchangeInstallPath
if (-not $script:ExchInstall) { try { $script:ExchInstall = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' -ErrorAction Stop).MsiInstallPath } catch { } }
if (-not $script:ExchInstall) { Write-Log 'Exchange install path not found; local log sections will be limited.' 'WARN' }
$script:LocalServer = $env:COMPUTERNAME

$script:AcceptedDomains = @(Get-Safe 'Get-AcceptedDomain')
$script:AcceptedDomainNames = @($script:AcceptedDomains | ForEach-Object { ("$($_.DomainName)".ToLower()) -replace '^\*\.', '' } | Where-Object { $_ } | Sort-Object -Unique)
$script:WildcardDomains = @($script:AcceptedDomains | Where-Object { "$($_.DomainName)".StartsWith('*.') -or "$($_.MatchSubDomains)" -eq 'True' } | ForEach-Object { ("$($_.DomainName)".ToLower()) -replace '^\*\.', '' })

function Test-InternalRecipient {
    param([string]$Address)
    if (-not $Address -or $Address -notmatch '@') { return $false }
    $d = $Address.Split('@')[-1].ToLower()
    if ($script:AcceptedDomainNames -contains $d) { return $true }
    foreach ($w in $script:WildcardDomains) { if ($d.EndsWith(".$w")) { return $true } }
    return $false
}

# Microsoft 365 IP ranges for tagging EXO/EOP traffic (best effort, needs internet)
$script:MsCidrs = @()
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $ep = Invoke-RestMethod -Uri ('https://endpoints.office.com/endpoints/worldwide?clientrequestid={0}' -f [guid]::NewGuid()) -TimeoutSec 20 -ErrorAction Stop
    $script:MsCidrs = @($ep | Where-Object { $_.serviceArea -eq 'Exchange' -and $_.ips } | ForEach-Object { $_.ips } | Where-Object { $_ -notmatch ':' } | Sort-Object -Unique)
    Write-Log "Loaded $($script:MsCidrs.Count) Microsoft 365 Exchange IPv4 ranges."
} catch { Write-Log 'Could not download Microsoft 365 IP ranges (no internet access?). IsMicrosoftIP will be blank.' 'WARN' }

$script:MsCidrParsed = @(foreach ($c in $script:MsCidrs) {
    try {
        $parts = "$c".Split('/')
        $b = [System.Net.IPAddress]::Parse($parts[0]).GetAddressBytes(); [Array]::Reverse($b)
        $net = [BitConverter]::ToUInt32($b, 0)
        $bits = [int]$parts[1]
        $mask = $(if ($bits -le 0) { [uint32]0 } else { [uint32](([uint64][uint32]::MaxValue -shl (32 - $bits)) -band [uint64][uint32]::MaxValue) })
        [PSCustomObject]@{ Net = [uint32]($net -band $mask); Mask = $mask }
    } catch { }
})

function Test-MicrosoftIP {
    param([string]$Ip)
    if ($script:MsCidrParsed.Count -eq 0 -or -not $Ip) { return '' }
    $clean = Get-EndpointIp $Ip
    if ($clean -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return '' }
    try {
        $b = [System.Net.IPAddress]::Parse($clean).GetAddressBytes(); [Array]::Reverse($b)
        $n = [BitConverter]::ToUInt32($b, 0)
        foreach ($r in $script:MsCidrParsed) { if ([uint32]($n -band $r.Mask) -eq $r.Net) { return 'True' } }
        return 'False'
    } catch { return '' }
}

# IIS site list for a server, read from its applicationHost.config (no WebAdministration module needed)
function Get-IisSiteInfo {
    param([string]$Server)
    $cfgLocal = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    $cfg = $(if ($Server -eq $script:LocalServer) { $cfgLocal } else { ConvertTo-UncPath $Server $cfgLocal })
    if (-not $cfg -or -not (Test-Path -LiteralPath $cfg)) { return }
    $x = New-Object System.Xml.XmlDocument
    $x.LoadXml((Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop))
    $sitesNode = $x.SelectSingleNode('/configuration/system.applicationHost/sites')
    if (-not $sitesNode) { return }
    $defDir = ''
    $dl = $sitesNode.SelectSingleNode('siteDefaults/logFile')
    if ($dl) { $defDir = $dl.GetAttribute('directory') }
    if (-not $defDir) { $defDir = '%SystemDrive%\inetpub\logs\LogFiles' }
    foreach ($s in @($sitesNode.SelectNodes('site'))) {
        $dir = ''
        $lf = $s.SelectSingleNode('logFile')
        if ($lf) { $dir = $lf.GetAttribute('directory') }
        if (-not $dir) { $dir = $defDir }
        $bind = @($s.SelectNodes('bindings/binding') | ForEach-Object { '{0} {1}' -f $_.GetAttribute('protocol'), $_.GetAttribute('bindingInformation') }) -join '; '
        [PSCustomObject]@{ Server = $Server; Name = $s.GetAttribute('name'); Id = $s.GetAttribute('id'); LogDir = $dir; Bindings = $bind }
    }
}

# ===========================================================================
# 1. TOPOLOGY
# ===========================================================================
$script:Servers = @()
$script:Databases = @()
Invoke-Section 'Topology-ExchangeServers' {
    $script:Servers = @(Get-ExchangeServer -ErrorAction SilentlyContinue)
    $localVer = ''
    if ($script:ExchInstall) { try { $localVer = (Get-Item (Join-Path $script:ExchInstall 'Bin\ExSetup.exe') -ErrorAction Stop).VersionInfo.ProductVersion } catch { } }
    $rows = foreach ($s in $script:Servers) {
        [PSCustomObject]@{
            Name = $s.Name; Fqdn = $s.Fqdn; Site = $s.Site; Edition = $s.Edition
            AdminDisplayVersion = $s.AdminDisplayVersion; ServerRole = $s.ServerRole
            IsMailboxServer = $s.IsMailboxServer; IsEdgeServer = $s.IsEdgeServer
            IsHubTransportServer = $s.IsHubTransportServer; IsClientAccessServer = $s.IsClientAccessServer
            IsLocal = ($s.Name -eq $script:LocalServer)
            LocalExSetupVersion = $(if ($s.Name -eq $script:LocalServer) { $localVer } else { '' })
            WhenCreated = $s.WhenCreated
        }
    }
    Save-Csv @($rows) 'Topology-ExchangeServers'
}

# Exchange server addresses, so log sources can be told apart from clients
$script:ExchangeServerIps = @{}
foreach ($s in $script:Servers) {
    try { foreach ($a in [System.Net.Dns]::GetHostAddresses("$($s.Fqdn)")) { $script:ExchangeServerIps[$a.IPAddressToString] = "$($s.Name)" } } catch { }
}

# Transport/mailbox servers whose logs are read (this server only with -SkipRemoteServers)
function Get-LogServers {
    $s = @($script:Servers | Where-Object { ($_.IsHubTransportServer -or $_.IsMailboxServer) -and -not $_.IsEdgeServer })
    if ($SkipRemoteServers) { $s = @($s | Where-Object { $_.Name -eq $script:LocalServer }) }
    $s
}

Invoke-Section 'Topology-ServerComponentState' {
    $rows = foreach ($s in $script:Servers | Where-Object { -not $_.IsEdgeServer }) {
        Get-ServerComponentState -Identity $s.Name -ErrorAction SilentlyContinue | Select-Object @{ n = 'Server'; e = { $s.Name } }, Component, State
    }
    Save-Csv @($rows) 'Topology-ServerComponentState'
}

Invoke-Section 'Topology-EdgeSubscriptions' { Save-Csv @(Get-Safe 'Get-EdgeSubscription') 'Topology-EdgeSubscriptions' }

Invoke-Section 'Topology-DAG' { Save-Csv @(Get-Safe 'Get-DatabaseAvailabilityGroup' @{ Status = $true }) 'Topology-DAG' }

Invoke-Section 'Topology-MailboxDatabases' {
    $dbs = @(Get-Safe 'Get-MailboxDatabase' @{ Status = $true; IncludePreExchange2013 = $true })
    if ($dbs.Count -eq 0) { $dbs = @(Get-Safe 'Get-MailboxDatabase' @{ Status = $true }) }
    if ($dbs.Count -eq 0) { $dbs = @(Get-Safe 'Get-MailboxDatabase') }
    $script:Databases = $dbs
    $rows = foreach ($db in $dbs) {
        $count = ''
        try { $count = @(Get-Mailbox -Database "$($db.Identity)" -ResultSize Unlimited -ErrorAction SilentlyContinue).Count } catch { }
        [PSCustomObject]@{
            Name = $db.Name; Server = $db.Server; Mounted = $db.Mounted; DatabaseSize = $db.DatabaseSize
            AvailableNewMailboxSpace = $db.AvailableNewMailboxSpace; MailboxCount = $count
            LastFullBackup = $db.LastFullBackup; LastIncrementalBackup = $db.LastIncrementalBackup
            LastDifferentialBackup = $db.LastDifferentialBackup; LastCopyBackup = $db.LastCopyBackup
            BackupInProgress = $db.BackupInProgress; CircularLoggingEnabled = $db.CircularLoggingEnabled
            ReplicationType = $db.ReplicationType; Servers = $db.Servers
            EdbFilePath = $db.EdbFilePath; LogFolderPath = $db.LogFolderPath
            IsExcludedFromProvisioning = $db.IsExcludedFromProvisioning; ProhibitSendReceiveQuota = $db.ProhibitSendReceiveQuota
        }
    }
    Save-Csv @($rows) 'Topology-MailboxDatabases'
    Save-Csv @(Get-Safe 'Get-MailboxDatabaseCopyStatus' @{ Identity = '*' }) 'Topology-MailboxDatabaseCopies'
    @($rows).Count
}

Invoke-Section 'Topology-ActiveDirectory' {
    $rootDse = [ADSI]'LDAP://RootDSE'
    $configNC = Get-AdsiValue $rootDse 'configurationNamingContext'
    $schemaNC = Get-AdsiValue $rootDse 'schemaNamingContext'
    $defaultNC = Get-AdsiValue $rootDse 'defaultNamingContext'
    if (-not $configNC -or $configNC -like 'ERR:*') { throw "Cannot read RootDSE: $configNC" }
    $info = [ordered]@{}
    $info.ForestFunctionality = Get-AdsiValue $rootDse 'forestFunctionality'
    $info.DomainFunctionality = Get-AdsiValue $rootDse 'domainFunctionality'
    $info.DefaultNamingContext = $defaultNC
    $info.RootDomainNamingContext = Get-AdsiValue $rootDse 'rootDomainNamingContext'
    $info.DnsHostNameOfDC = Get-AdsiValue $rootDse 'dnsHostName'
    $info.ExchangeSchemaRangeUpper = Get-AdsiValue ([ADSI]"LDAP://CN=ms-Exch-Schema-Version-Pt,$schemaNC") 'rangeUpper'
    try {
        $org = Get-OrganizationConfig -ErrorAction Stop
        $info.ExchangeOrgName = "$($org.Name)"
        $info.ExchangeOrgObjectVersion = Get-AdsiValue ([ADSI]"LDAP://$($org.DistinguishedName)") 'objectVersion'
    } catch { $info.ExchangeOrgObjectVersion = "ERR: $($_.Exception.Message)" }
    $info.MESO_ObjectVersion = Get-AdsiValue ([ADSI]"LDAP://CN=Microsoft Exchange System Objects,$defaultNC") 'objectVersion'
    try {
        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        $script:LocalForestName = "$($forest.Name)"
        $script:TrustedForests = @($forest.GetAllTrustRelationships() | ForEach-Object { "$($_.TargetName)" })
        $info.ForestName = $forest.Name
        $info.ForestDomains = ($forest.Domains | ForEach-Object { $_.Name }) -join '; '
        $info.ForestTrusts = ($forest.GetAllTrustRelationships() | ForEach-Object { "$($_.TargetName) [$($_.TrustType)/$($_.TrustDirection)]" }) -join '; '
        $info.GlobalCatalogs = ($forest.GlobalCatalogs | ForEach-Object { $_.Name }) -join '; '
    } catch { $info.ForestTrusts = "ERR: $($_.Exception.Message)" }
    # Autodiscover SCPs
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$configNC")
        $searcher.Filter = '(&(objectClass=serviceConnectionPoint)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596))'
        $searcher.PageSize = 500
        $null = $searcher.PropertiesToLoad.AddRange([string[]]@('cn', 'serviceBindingInformation', 'keywords', 'whenChanged', 'distinguishedName'))
        $found = $searcher.FindAll()
        $scps = @(foreach ($r in $found) {
            [PSCustomObject]@{
                CN = "$(@($r.Properties['cn'])[0])"
                ServiceBindingInformation = (@($r.Properties['servicebindinginformation']) -join '; ')
                Keywords = (@($r.Properties['keywords']) -join '; ')
                WhenChanged = @($r.Properties['whenchanged'])[0]
                DistinguishedName = "$(@($r.Properties['distinguishedname'])[0])"
            }
        })
        $found.Dispose()
        $script:Scps = $scps
        Save-Csv $scps 'Topology-AutodiscoverSCP' | Out-Null
        $info.AutodiscoverSCPCount = $scps.Count
    } catch { $info.AutodiscoverSCPCount = "ERR: $($_.Exception.Message)" }
    # Entra Connect server hint via MSOL_/AAD_ account description
    try {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]"LDAP://$defaultNC")
        $searcher.Filter = '(&(objectClass=user)(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*)))'
        $searcher.PageSize = 500
        $null = $searcher.PropertiesToLoad.AddRange([string[]]@('sAMAccountName', 'description', 'whenCreated'))
        $found = $searcher.FindAll()
        $acc = @(foreach ($r in $found) {
            [PSCustomObject]@{
                Account = "$(@($r.Properties['samaccountname'])[0])"
                Description = "$(@($r.Properties['description'])[0])"
                WhenCreated = @($r.Properties['whencreated'])[0]
            }
        })
        $found.Dispose()
        Save-Csv $acc 'Topology-EntraConnectAccounts' | Out-Null
        $info.EntraConnectAccountsFound = $acc.Count
        $info.EntraConnectServerHint = (($acc | ForEach-Object { if ("$($_.Description)" -match 'computer\s+(\S+)') { $Matches[1] } }) -join '; ')
        $info.EntraConnectTenants = ((@($acc | ForEach-Object { Get-EntraTenantHint $_.Description }) | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
    } catch { $info.EntraConnectAccountsFound = "ERR: $($_.Exception.Message)" }
    Save-Json ([PSCustomObject]$info) 'Topology-ActiveDirectory'
    Save-Csv @([PSCustomObject]$info) 'Topology-ActiveDirectory' | Out-Null
    1
}

# Every trusted forest (and any named with -TrustedForest): Exchange organizations and servers,
# Autodiscover SCPs and SCP pointers, and the tenant each Entra Connect account syncs to.
# Outlook on a PC in an account forest follows SCPs or SCP pointers there, not in this forest.
$script:ForestPresence = @()
Invoke-Section 'Topology-ForestExchangePresence' {
    $forests = @(@($script:LocalForestName) + @($script:TrustedForests) + @($TrustedForest) | Where-Object { $_ } | ForEach-Object { "$_".ToLower() } | Sort-Object -Unique)
    $summary = @(); $detail = @()
    foreach ($f in $forests) {
        $row = [ordered]@{ Forest = $f; IsLocalForest = ($f -eq "$($script:LocalForestName)".ToLower()); Reachable = $false; Error = ''
            ExchangeSchemaRangeUpper = ''; ExchangeOrganizations = ''; ExchangeServerCount = 0; ExchangeServers = ''
            AutodiscoverSCPs = 0; SCPPointers = 0; EntraConnectAccounts = ''; EntraConnectTenants = '' }
        try {
            $rootDse = Get-DirEntry "LDAP://$f/RootDSE"
            $cfg = Get-AdsiValue $rootDse 'configurationNamingContext'
            if (-not $cfg -or $cfg -like 'ERR:*') { throw "RootDSE not readable: $cfg" }
            $schema = Get-AdsiValue $rootDse 'schemaNamingContext'
            $rootNc = Get-AdsiValue $rootDse 'rootDomainNamingContext'
            $row.Reachable = $true
            $row.ExchangeSchemaRangeUpper = Get-AdsiValue (Get-DirEntry "LDAP://$f/CN=ms-Exch-Schema-Version-Pt,$schema") 'rangeUpper'
            if ($row.ExchangeSchemaRangeUpper -like 'ERR:*') { $row.ExchangeSchemaRangeUpper = 'Not extended' }
            $exRoot = Get-DirEntry "LDAP://$f/CN=Microsoft Exchange,CN=Services,$cfg"
            $orgs = @(); $srv = @()
            try { $orgs = @(Find-Adsi $exRoot '(objectClass=msExchOrganizationContainer)' @('name') 'OneLevel') } catch { }
            try { $srv = @(Find-Adsi $exRoot '(&(objectClass=msExchExchangeServer)(!(objectClass=msExchExchangeServerPolicy)))' @('name', 'serialNumber', 'whenChanged')) } catch { }
            $row.ExchangeOrganizations = (@($orgs | ForEach-Object { $_.name }) -join '; ')
            $row.ExchangeServerCount = $srv.Count
            $row.ExchangeServers = (@($srv | ForEach-Object { '{0} ({1})' -f $_.name, $_.serialNumber }) -join '; ')
            $scpFilter = '(&(objectClass=serviceConnectionPoint)(|(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596)(keywords=67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68)))'
            foreach ($scp in @(Find-Adsi (Get-DirEntry "LDAP://$f/$cfg") $scpFilter @('cn', 'serviceBindingInformation', 'keywords', 'whenChanged', 'distinguishedName'))) {
                $type = $(if ("$($scp.keywords)" -match '(?i)67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68') { 'SCPPointer' } else { 'AutodiscoverSCP' })
                if ($type -eq 'SCPPointer') { $row.SCPPointers++ } else { $row.AutodiscoverSCPs++ }
                $detail += [PSCustomObject]@{ Forest = $f; Type = $type; CN = $scp.cn; ServiceBindingInformation = $scp.serviceBindingInformation; Keywords = $scp.keywords; WhenChanged = $scp.whenChanged; DistinguishedName = $scp.distinguishedName }
            }
            $syncFilter = '(&(objectCategory=person)(objectClass=user)(|(sAMAccountName=MSOL_*)(sAMAccountName=AAD_*)(sAMAccountName=Sync_*)))'
            $acc = @()
            try { $acc = @(Find-Adsi (Get-DirEntry "GC://$f/$rootNc") $syncFilter @('sAMAccountName', 'description')) }
            catch { try { $acc = @(Find-Adsi (Get-DirEntry "LDAP://$f/$rootNc") $syncFilter @('sAMAccountName', 'description')) } catch { } }
            $row.EntraConnectAccounts = (@($acc | ForEach-Object { $h = $(if ("$($_.description)" -match 'computer\s+(\S+)') { $Matches[1] } else { '?' }); "$($_.sAMAccountName) (server $h)" }) -join '; ')
            $row.EntraConnectTenants = ((@($acc | ForEach-Object { Get-EntraTenantHint $_.description }) | Where-Object { $_ } | Sort-Object -Unique) -join '; ')
        } catch { $row.Error = $_.Exception.Message }
        $summary += [PSCustomObject]$row
    }
    $script:ForestPresence = $summary
    Save-Csv $detail 'Topology-ForestSCPs' | Out-Null
    Save-Csv $summary 'Topology-ForestExchangePresence'
}

# ===========================================================================
# 2. HYBRID
# ===========================================================================
Invoke-Section 'Hybrid-Configuration' {
    $h = @(Get-Safe 'Get-HybridConfiguration')
    Save-Text $h 'Hybrid-Configuration'
    Save-Csv $h 'Hybrid-Configuration'
}

Invoke-Section 'Hybrid-HCWLogs' {
    $drive = $(if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' })
    $paths = @("$drive\Users\*\AppData\Roaming\Microsoft\Exchange Hybrid Configuration")
    if ($script:ExchInstall) { $paths += (Join-Path $script:ExchInstall 'Logging\Update-HybridConfiguration') }
    $rows = foreach ($p in $paths) {
        foreach ($dir in @(Get-Item -Path $p -ErrorAction SilentlyContinue)) {
            $files = Get-ChildItem -LiteralPath $dir.FullName -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 15
            foreach ($f in $files) {
                $ver = ''
                try { $ver = (Select-String -LiteralPath $f.FullName -Pattern 'HCW\s*Version|Version\s*:\s*\d' -List -ErrorAction SilentlyContinue | Select-Object -First 1).Line } catch { }
                [PSCustomObject]@{ Folder = $dir.FullName; File = $f.Name; LastWriteTime = $f.LastWriteTime; SizeKB = [math]::Round($f.Length / 1KB, 1); VersionHint = $ver }
            }
        }
    }
    Save-Csv @($rows) 'Hybrid-HCWLogs'
}

Invoke-Section 'Hybrid-OAuth' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-IntraOrganizationConnector') 'Hybrid-IntraOrganizationConnector'
    $n += Save-Csv @(Get-Safe 'Get-IntraOrganizationConfiguration') 'Hybrid-IntraOrganizationConfiguration'
    $n += Save-Csv @(Get-Safe 'Get-AuthServer') 'Hybrid-AuthServer'
    $n += Save-Csv @(Get-Safe 'Get-PartnerApplication') 'Hybrid-PartnerApplication'
    $n += Save-Csv @(Get-Safe 'Get-AuthConfig') 'Hybrid-AuthConfig'
    $n
}

Invoke-Section 'Hybrid-Federation' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-FederationTrust') 'Hybrid-FederationTrust'
    $n += Save-Csv @(Get-Safe 'Get-FederatedOrganizationIdentifier') 'Hybrid-FederatedOrganizationIdentifier'
    $n += Save-Csv @(Get-Safe 'Get-OrganizationRelationship') 'Hybrid-OrganizationRelationship'
    $n += Save-Csv @(Get-Safe 'Get-AvailabilityAddressSpace') 'Hybrid-AvailabilityAddressSpace'
    $n += Save-Csv @(Get-Safe 'Get-SharingPolicy') 'Hybrid-SharingPolicy'
    $n
}

Invoke-Section 'Hybrid-Migration' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-MigrationEndpoint') 'Hybrid-MigrationEndpoint'
    $n += Save-Csv @(Get-Safe 'Get-MigrationBatch') 'Hybrid-MigrationBatch'
    $n += Save-Csv @(Get-Safe 'Get-MoveRequest' @{ ResultSize = 'Unlimited' }) 'Hybrid-MoveRequest'
    $n += Save-Csv @(Get-Safe 'Get-MigrationConfig') 'Hybrid-MigrationConfig'
    $n
}

# Modern Hybrid Agent ("Microsoft Hybrid Service", MSHybridService) on any Exchange server.
# It can live on any domain-joined server; a miss here is not proof it is absent.
$script:HybridAgentRows = @()
Invoke-Section 'Hybrid-ModernHybridAgent' {
    $rows = @()
    foreach ($s in @($script:Servers | Where-Object { -not $_.IsEdgeServer })) {
        $svc = @()
        try {
            $svc = @($(if ($s.Name -eq $script:LocalServer) { Get-Service -ErrorAction SilentlyContinue } else { Get-Service -ComputerName $s.Name -ErrorAction Stop }) |
                Where-Object { $_.Name -match 'Hybrid' -or $_.DisplayName -match 'Hybrid' })
        } catch { $rows += [PSCustomObject]@{ Server = $s.Name; Type = 'Error'; Name = ''; Display = $_.Exception.Message; Status = ''; Version = '' } }
        $rows += @($svc | ForEach-Object { [PSCustomObject]@{ Server = $s.Name; Type = 'Service'; Name = $_.Name; Display = $_.DisplayName; Status = "$($_.Status)"; Version = '' } })
    }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $rows += Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match 'Hybrid' } | ForEach-Object { [PSCustomObject]@{ Server = $script:LocalServer; Type = 'Program'; Name = $_.DisplayName; Display = $_.Publisher; Status = $_.InstallDate; Version = $_.DisplayVersion } }
    }
    $script:HybridAgentRows = @($rows | Where-Object { $_.Type -eq 'Service' })
    Save-Csv $rows 'Hybrid-ModernHybridAgent'
}

Invoke-Section 'Hybrid-OrganizationConfig' {
    $o = @(Get-Safe 'Get-OrganizationConfig')
    Save-Text $o 'Hybrid-OrganizationConfig'
    Save-Csv $o 'Hybrid-OrganizationConfig'
}

# ===========================================================================
# 3. RECIPIENTS STILL ON-PREM
# ===========================================================================
$script:OnPremMailboxes = @()
Invoke-Section 'Recipients-Mailboxes' {
    $all = @(Get-Safe 'Get-Mailbox' @{ ResultSize = 'Unlimited' })
    foreach ($kind in 'Arbitration', 'AuditLog', 'AuxAuditLog', 'Monitoring', 'PublicFolder') {
        $all += @(Get-Safe 'Get-Mailbox' @{ ResultSize = 'Unlimited'; $kind = $true })
    }
    $all = @($all | Where-Object { $_ } | Sort-Object -Property DistinguishedName -Unique)
    $script:OnPremMailboxes = $all
    Write-Log "  $($all.Count) mailbox(es); reading statistics"

    # One statistics call per database; per-mailbox fallback for anything not returned
    $statMap = @{}
    foreach ($db in $script:Databases) {
        $dbId = $(if ($db.Guid) { "$($db.Guid)" } else { "$($db.Name)" })
        foreach ($st in @(Get-Safe 'Get-MailboxStatistics' @{ Database = $dbId })) {
            if ($st.MailboxGuid) { $statMap["$($st.MailboxGuid)"] = $st }
        }
    }
    $userMap = @{}
    foreach ($u in @(Get-Safe 'Get-User' @{ ResultSize = 'Unlimited'; RecipientTypeDetails = @('UserMailbox', 'SharedMailbox', 'RoomMailbox', 'EquipmentMailbox', 'LinkedMailbox', 'DiscoveryMailbox') })) {
        $userMap["$($u.DistinguishedName)"] = $u
    }
    $i = 0
    $rows = foreach ($m in $all) {
        $i++
        if ($i % 500 -eq 0) { Write-Log "  mailbox $i of $($all.Count)" }
        $dn = "$($m.DistinguishedName)"
        $stat = $null
        if ($m.ExchangeGuid -and $statMap.ContainsKey("$($m.ExchangeGuid)")) { $stat = $statMap["$($m.ExchangeGuid)"] }
        if (-not $stat) { try { $stat = Get-MailboxStatistics -Identity $dn -ErrorAction Stop } catch { } }
        $usr = $userMap[$dn]
        if (-not $usr) { try { $usr = Get-User -Identity $dn -ErrorAction Stop } catch { } }
        [PSCustomObject]@{
            DisplayName = $m.DisplayName; PrimarySmtpAddress = $m.PrimarySmtpAddress; Alias = $m.Alias
            RecipientTypeDetails = $m.RecipientTypeDetails; Database = $m.Database; ServerName = $m.ServerName
            TotalItemSize = $(if ($stat) { $stat.TotalItemSize } else { '' })
            ItemCount = $(if ($stat) { $stat.ItemCount } else { '' })
            LastLogonTime = $(if ($stat) { $stat.LastLogonTime } else { '' })
            LastLoggedOnUserAccount = $(if ($stat) { $stat.LastLoggedOnUserAccount } else { '' })
            AccountDisabled = (Get-AccountDisabled $usr)
            LitigationHoldEnabled = $m.LitigationHoldEnabled; LitigationHoldDate = $m.LitigationHoldDate
            InPlaceHolds = (@($m.InPlaceHolds) -join '; '); RetentionHoldEnabled = $m.RetentionHoldEnabled; RetentionPolicy = $m.RetentionPolicy
            ArchiveState = $m.ArchiveState; ArchiveDatabase = $m.ArchiveDatabase
            ForwardingAddress = $m.ForwardingAddress; ForwardingSmtpAddress = $m.ForwardingSmtpAddress; DeliverToMailboxAndForward = $m.DeliverToMailboxAndForward
            HiddenFromAddressListsEnabled = $m.HiddenFromAddressListsEnabled
            IsLinked = $m.IsLinked; LinkedMasterAccount = $m.LinkedMasterAccount; IsShared = $m.IsShared; IsResource = $m.IsResource
            EmailAddressPolicyEnabled = $m.EmailAddressPolicyEnabled; ExchangeGuid = $m.ExchangeGuid
            WhenCreated = $m.WhenCreated; WhenMailboxCreated = $m.WhenMailboxCreated
            OrganizationalUnit = $m.OrganizationalUnit; DistinguishedName = $m.DistinguishedName
        }
    }
    Save-Csv @($rows) 'Recipients-Mailboxes' | Out-Null
    Save-Csv @($rows | Group-Object RecipientTypeDetails | Select-Object @{ n = 'RecipientTypeDetails'; e = { $_.Name } }, Count) 'Recipients-Mailboxes-Summary' | Out-Null
    @($rows).Count
}

Invoke-Section 'Recipients-MailboxPermissions' {
    $rows = [System.Collections.Generic.List[object]]::new()
    $targets = @($script:OnPremMailboxes | Where-Object { "$($_.RecipientTypeDetails)" -notmatch 'Arbitration|Monitoring|AuditLog|Discovery|PublicFolder' })
    $i = 0
    foreach ($m in $targets) {
        $i++
        if ($i % 250 -eq 0) { Write-Log "  permissions $i of $($targets.Count)" }
        $dn = "$($m.DistinguishedName)"
        try {
            Get-MailboxPermission -Identity $dn -ErrorAction SilentlyContinue |
                Where-Object { -not $_.IsInherited -and "$($_.User)" -notmatch 'NT AUTHORITY\\SELF|S-1-5-' } |
                ForEach-Object { $rows.Add([PSCustomObject]@{ Mailbox = "$($m.PrimarySmtpAddress)"; Type = 'FullAccess'; Trustee = "$($_.User)"; Rights = (@($_.AccessRights) -join ';'); Deny = $_.Deny }) }
        } catch { }
        try {
            Get-ADPermission -Identity $dn -ErrorAction SilentlyContinue |
                Where-Object { "$($_.ExtendedRights)" -like '*Send-As*' -and -not $_.IsInherited -and "$($_.User)" -notmatch 'NT AUTHORITY\\SELF|S-1-5-' } |
                ForEach-Object { $rows.Add([PSCustomObject]@{ Mailbox = "$($m.PrimarySmtpAddress)"; Type = 'SendAs'; Trustee = "$($_.User)"; Rights = 'Send-As'; Deny = $_.Deny }) }
        } catch { }
        foreach ($t in @($m.GrantSendOnBehalfTo)) {
            if ($null -ne $t -and "$t") { $rows.Add([PSCustomObject]@{ Mailbox = "$($m.PrimarySmtpAddress)"; Type = 'SendOnBehalf'; Trustee = "$t"; Rights = 'SendOnBehalf'; Deny = $false }) }
        }
    }
    Save-Csv $rows.ToArray() 'Recipients-MailboxPermissions'
}

Invoke-Section 'Recipients-RemoteMailboxes' {
    $rm = @(Get-Safe 'Get-RemoteMailbox' @{ ResultSize = 'Unlimited' })
    $rows = foreach ($r in $rm) {
        [PSCustomObject]@{
            DisplayName = $r.DisplayName; PrimarySmtpAddress = $r.PrimarySmtpAddress; RecipientTypeDetails = $r.RecipientTypeDetails
            RemoteRoutingAddress = $r.RemoteRoutingAddress; ExchangeGuid = $r.ExchangeGuid; ArchiveGuid = $r.ArchiveGuid; ArchiveState = $r.ArchiveState
            EmailAddressPolicyEnabled = $r.EmailAddressPolicyEnabled
            HasOnMicrosoftProxy = (@($r.EmailAddresses | Where-Object { "$_" -match 'mail\.onmicrosoft\.com$' }).Count -gt 0)
            MissingExchangeGuid = ((-not $r.ExchangeGuid) -or ("$($r.ExchangeGuid)" -eq '00000000-0000-0000-0000-000000000000'))
            MissingRemoteRoutingAddress = (-not "$($r.RemoteRoutingAddress)")
            WhenCreated = $r.WhenCreated; OrganizationalUnit = $r.OrganizationalUnit
        }
    }
    Save-Csv @($rows) 'Recipients-RemoteMailboxes' | Out-Null
    Save-Csv @([PSCustomObject]@{
        TotalRemoteMailboxes = $rm.Count
        MissingExchangeGuid = @($rows | Where-Object { $_.MissingExchangeGuid }).Count
        MissingRemoteRoutingAddress = @($rows | Where-Object { $_.MissingRemoteRoutingAddress }).Count
        MissingOnMicrosoftProxy = @($rows | Where-Object { -not $_.HasOnMicrosoftProxy }).Count
        EmailAddressPolicyDisabled = @($rows | Where-Object { "$($_.EmailAddressPolicyEnabled)" -eq 'False' }).Count
    }) 'Recipients-RemoteMailboxes-Summary' | Out-Null
    $rm.Count
}

Invoke-Section 'Recipients-MailUsersAndContacts' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-MailUser' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress, RecipientTypeDetails, ExchangeGuid, WhenCreated, OrganizationalUnit) 'Recipients-MailUsers'
    $n += Save-Csv @(Get-Safe 'Get-MailContact' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress, RecipientTypeDetails, HiddenFromAddressListsEnabled, WhenCreated, OrganizationalUnit) 'Recipients-MailContacts'
    $n
}

Invoke-Section 'Recipients-Groups' {
    $dgs = @(Get-Safe 'Get-DistributionGroup' @{ ResultSize = 'Unlimited' })
    $rows = foreach ($g in $dgs) {
        $mc = ''
        try { $mc = @(Get-DistributionGroupMember -Identity "$($g.DistinguishedName)" -ResultSize Unlimited -ErrorAction SilentlyContinue).Count } catch { }
        [PSCustomObject]@{
            DisplayName = $g.DisplayName; PrimarySmtpAddress = $g.PrimarySmtpAddress; RecipientTypeDetails = $g.RecipientTypeDetails; GroupType = $g.GroupType
            MemberCount = $mc; ManagedBy = ((@($g.ManagedBy) | ForEach-Object { "$_" }) -join '; ')
            MemberJoinRestriction = $g.MemberJoinRestriction; MemberDepartRestriction = $g.MemberDepartRestriction
            ModerationEnabled = $g.ModerationEnabled; RequireSenderAuthenticationEnabled = $g.RequireSenderAuthenticationEnabled
            AcceptMessagesOnlyFromCount = @($g.AcceptMessagesOnlyFromSendersOrMembers).Count
            HiddenFromAddressListsEnabled = $g.HiddenFromAddressListsEnabled; EmailAddressPolicyEnabled = $g.EmailAddressPolicyEnabled
            ExpansionServer = $g.ExpansionServer; WhenCreated = $g.WhenCreated; OrganizationalUnit = $g.OrganizationalUnit
        }
    }
    Save-Csv @($rows) 'Recipients-DistributionGroups' | Out-Null
    Save-Csv @(Get-Safe 'Get-DynamicDistributionGroup' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, RecipientFilter, RecipientContainer, ManagedBy, WhenCreated) 'Recipients-DynamicDistributionGroups' | Out-Null
    Save-Csv @(Get-Safe 'Get-OrganizationConfig' | Select-Object DistributionGroupNamingPolicy, DistributionGroupDefaultOU, DistributionGroupNameBlockedWordsList) 'Recipients-GroupNamingPolicy' | Out-Null
    Save-Csv @($rows | Group-Object RecipientTypeDetails | Select-Object @{ n = 'RecipientTypeDetails'; e = { $_.Name } }, Count) 'Recipients-DistributionGroups-Summary' | Out-Null
    @($rows).Count
}

Invoke-Section 'Recipients-PublicFolders' {
    $o = Get-OrganizationConfig
    $pfCount = ''
    try { $pfCount = @(Get-PublicFolder -Recurse -ResultSize Unlimited -ErrorAction Stop).Count } catch { $pfCount = "ERR: $($_.Exception.Message)" }
    $mailPf = @(Get-Safe 'Get-MailPublicFolder' @{ ResultSize = 'Unlimited' })
    $pf = [PSCustomObject]@{
        PublicFoldersEnabled = $o.PublicFoldersEnabled
        PublicFoldersLockedForMigration = $o.PublicFoldersLockedForMigration
        PublicFolderMigrationComplete = $o.PublicFolderMigrationComplete
        PublicFolderMailboxesLockedForNewConnections = $o.PublicFolderMailboxesLockedForNewConnections
        PublicFolderMailboxesMigrationComplete = $o.PublicFolderMailboxesMigrationComplete
        RemotePublicFolderMailboxes = (@($o.RemotePublicFolderMailboxes) -join '; ')
        RootPublicFolderMailbox = $o.RootPublicFolderMailbox
        PublicFolderMailboxCount = @(Get-Safe 'Get-Mailbox' @{ PublicFolder = $true; ResultSize = 'Unlimited' }).Count
        MailEnabledPublicFolderCount = $mailPf.Count
        PublicFolderCount = $pfCount
    }
    Save-Csv @($pf) 'Recipients-PublicFolders' | Out-Null
    Save-Csv @($mailPf | Select-Object DisplayName, PrimarySmtpAddress, EntryId, WhenCreated) 'Recipients-MailPublicFolders' | Out-Null
    # Per-folder content and dates: tells "configured" apart from "in use"
    $stats = @(Get-Safe 'Get-PublicFolderStatistics' @{ ResultSize = 'Unlimited' })
    Save-Csv @($stats | Select-Object Name, FolderPath, ItemCount, TotalItemSize, CreationTime, LastModificationTime, LastUserAccessTime, LastUserModificationTime, ContentMailboxName) 'Recipients-PublicFolderStatistics' | Out-Null
    # Permissions other than the defaults (Default/Anonymous at None/Author/Reviewer are the out-of-box set)
    $perm = @()
    $folders = @()
    try { $folders = @(Get-PublicFolder -Recurse -ResultSize 5000 -ErrorAction Stop) } catch { }
    foreach ($fo in $folders) {
        foreach ($p in @(Get-Safe 'Get-PublicFolderClientPermission' @{ Identity = "$($fo.Identity)" })) {
            $user = "$($p.User)"; $rights = (@($p.AccessRights) | ForEach-Object { "$_" }) -join '; '
            if ($user -in 'Default', 'Anonymous' -and $rights -in 'None', 'Author', 'Reviewer') { continue }
            $perm += [PSCustomObject]@{ Folder = "$($fo.Identity)"; User = $user; AccessRights = $rights }
        }
    }
    Save-Csv $perm 'Recipients-PublicFolderPermissions' | Out-Null
    @($stats).Count
}

Invoke-Section 'Recipients-AddressPolicies' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-EmailAddressPolicy') 'Recipients-EmailAddressPolicies'
    $n += Save-Csv @(Get-Safe 'Get-AddressList' | Select-Object Name, RecipientFilter, RecipientFilterType, LastUpdatedRecipientFilter) 'Recipients-AddressLists'
    $n += Save-Csv @(Get-Safe 'Get-GlobalAddressList' | Select-Object Name, IsDefaultGlobalAddressList, RecipientFilter) 'Recipients-GlobalAddressLists'
    $n += Save-Csv @(Get-Safe 'Get-OfflineAddressBook' | Select-Object Name, IsDefault, GeneratingMailbox, AddressLists, VirtualDirectories, GlobalWebDistributionEnabled, LastTouchedTime) 'Recipients-OfflineAddressBooks'
    $n += Save-Csv @(Get-Safe 'Get-AddressBookPolicy') 'Recipients-AddressBookPolicies'
    $n
}

Invoke-Section 'Recipients-RBAC' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-RoleGroup' | Select-Object Name, Members, ManagedBy, RoleAssignments, WhenCreated) 'Recipients-RoleGroups'
    $n += Save-Csv @(Get-Safe 'Get-ManagementRole' | Where-Object { "$($_.IsRootRole)" -eq 'False' } | Select-Object Name, Parent, RoleType, WhenCreated) 'Recipients-CustomManagementRoles'
    $n += Save-Csv @(Get-Safe 'Get-ManagementRoleAssignment' | Where-Object { "$($_.RoleAssigneeType)" -ne 'RoleGroup' -or $_.CustomRecipientWriteScope -or $_.CustomConfigWriteScope } | Select-Object Name, Role, RoleAssigneeName, RoleAssigneeType, CustomRecipientWriteScope, CustomConfigWriteScope, RecipientWriteScope, Enabled, WhenCreated) 'Recipients-NonDefaultRoleAssignments'
    $n
}

# ===========================================================================
# 4. MAIL FLOW CONFIGURATION
# ===========================================================================
Invoke-Section 'MailFlow-Domains' {
    $n = 0
    $n += Save-Csv @($script:AcceptedDomains | Select-Object Name, DomainName, DomainType, Default, AddressBookEnabled, MatchSubDomains, WhenChanged) 'MailFlow-AcceptedDomains'
    $n += Save-Csv @(Get-Safe 'Get-RemoteDomain') 'MailFlow-RemoteDomains'
    $n
}

Invoke-Section 'MailFlow-SendConnectors' {
    $rows = foreach ($c in @(Get-Safe 'Get-SendConnector')) {
        [PSCustomObject]@{
            Name = $c.Name; Enabled = $c.Enabled
            AddressSpaces = ((@($c.AddressSpaces) | ForEach-Object { "$_" }) -join '; ')
            SmartHosts = ((@($c.SmartHosts) | ForEach-Object { "$_" }) -join '; ')
            DNSRoutingEnabled = $c.DNSRoutingEnabled
            SourceTransportServers = ((@($c.SourceTransportServers) | ForEach-Object { "$_" }) -join '; ')
            Fqdn = $c.Fqdn; TlsAuthLevel = $c.TlsAuthLevel; TlsDomain = $c.TlsDomain; TlsCertificateName = $c.TlsCertificateName
            RequireTLS = $c.RequireTLS; CloudServicesMailEnabled = $c.CloudServicesMailEnabled; SmartHostAuthMechanism = $c.SmartHostAuthMechanism
            Port = $c.Port; MaxMessageSize = $c.MaxMessageSize; IsScopedConnector = $c.IsScopedConnector; Comment = $c.Comment; WhenChanged = $c.WhenChanged
        }
    }
    Save-Csv @($rows) 'MailFlow-SendConnectors'
}

$script:ReceiveConnectors = @()
Invoke-Section 'MailFlow-ReceiveConnectors' {
    $script:ReceiveConnectors = @(Get-Safe 'Get-ReceiveConnector')
    $rows = foreach ($c in $script:ReceiveConnectors) {
        $anon = ''
        try {
            $perm = Get-ADPermission -Identity "$($c.DistinguishedName)" -ErrorAction SilentlyContinue | Where-Object { "$($_.ExtendedRights)" -like '*ms-Exch-SMTP-Accept-Any-Recipient*' -and -not $_.Deny }
            $anon = (@($perm | ForEach-Object { "$($_.User)" }) | Sort-Object -Unique) -join '; '
        } catch { $anon = "ERR: $($_.Exception.Message)" }
        [PSCustomObject]@{
            Server = $c.Server; Name = $c.Name; Identity = $c.Identity; Enabled = $c.Enabled; TransportRole = $c.TransportRole
            Bindings = ((@($c.Bindings) | ForEach-Object { "$_" }) -join '; ')
            RemoteIPRanges = ((@($c.RemoteIPRanges) | ForEach-Object { "$_" }) -join '; ')
            RemoteIPRangeCount = @($c.RemoteIPRanges).Count
            PermissionGroups = $c.PermissionGroups; AuthMechanism = $c.AuthMechanism
            AcceptAnyRecipientGrantedTo = $anon
            IsDefault = ("$($c.Name)" -match '^(Default |Client |Outbound Proxy )')
            ProtocolLoggingLevel = $c.ProtocolLoggingLevel; RequireTLS = $c.RequireTLS; TlsCertificateName = $c.TlsCertificateName
            TlsDomainCapabilities = ((@($c.TlsDomainCapabilities) | ForEach-Object { "$_" }) -join '; ')
            Fqdn = $c.Fqdn; MaxMessageSize = $c.MaxMessageSize; MessageRateLimit = $c.MessageRateLimit; Comment = $c.Comment; WhenChanged = $c.WhenChanged
        }
    }
    Save-Csv @($rows) 'MailFlow-ReceiveConnectors'
}

Invoke-Section 'MailFlow-Rules' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-TransportRule' | Select-Object Name, State, Priority, Mode, Description, WhenChanged) 'MailFlow-TransportRules'
    $n += Save-Csv @(Get-Safe 'Get-JournalRule') 'MailFlow-JournalRules'
    $n += Save-Csv @(Get-Safe 'Get-TransportConfig' | Select-Object JournalingReportNdrTo, MaxSendSize, MaxReceiveSize, MaxRecipientEnvelopeLimit, TLSSendDomainSecureList, TLSReceiveDomainSecureList, InternalSMTPServers, ExternalPostmasterAddress, SafetyNetHoldTime, ShadowRedundancyEnabled, AddressBookPolicyRoutingEnabled) 'MailFlow-TransportConfig'
    $n += Save-Csv @(Get-Safe 'Get-DlpPolicy') 'MailFlow-DlpPolicies'
    $n += Save-Csv @(Get-Safe 'Get-RetentionPolicy' | Select-Object Name, RetentionPolicyTagLinks, IsDefault, IsDefaultArbitrationMailbox) 'MailFlow-RetentionPolicies'
    $n += Save-Csv @(Get-Safe 'Get-RetentionPolicyTag' | Select-Object Name, Type, RetentionEnabled, AgeLimitForRetention, RetentionAction) 'MailFlow-RetentionPolicyTags'
    $n += Save-Csv @(Get-Safe 'Get-TransportAgent') 'MailFlow-TransportAgents'
    $n += Save-Csv @(Get-Safe 'Get-MalwareFilterPolicy') 'MailFlow-MalwareFilterPolicies'
    $n
}

Invoke-Section 'MailFlow-TransportServices' {
    $rows = foreach ($s in $script:Servers | Where-Object { -not $_.IsEdgeServer }) {
        $ts = $null; $fe = $null; $mt = $null
        try { $ts = Get-TransportService -Identity $s.Name -ErrorAction Stop } catch { }
        try { $fe = Get-FrontendTransportService -Identity $s.Name -ErrorAction Stop } catch { }
        try { $mt = Get-MailboxTransportService -Identity $s.Name -ErrorAction Stop } catch { }
        [PSCustomObject]@{
            Server = $s.Name
            MessageTrackingLogEnabled = $ts.MessageTrackingLogEnabled; MessageTrackingLogPath = $ts.MessageTrackingLogPath
            MessageTrackingLogMaxAge = $ts.MessageTrackingLogMaxAge; MessageTrackingLogMaxDirectorySize = $ts.MessageTrackingLogMaxDirectorySize; MessageTrackingLogMaxFileSize = $ts.MessageTrackingLogMaxFileSize
            Hub_ReceiveProtocolLogPath = $ts.ReceiveProtocolLogPath; Hub_ReceiveProtocolLogMaxAge = $ts.ReceiveProtocolLogMaxAge; Hub_ReceiveProtocolLogMaxDirectorySize = $ts.ReceiveProtocolLogMaxDirectorySize
            Hub_SendProtocolLogPath = $ts.SendProtocolLogPath
            FE_ReceiveProtocolLogPath = $fe.ReceiveProtocolLogPath; FE_ReceiveProtocolLogMaxAge = $fe.ReceiveProtocolLogMaxAge; FE_ReceiveProtocolLogMaxDirectorySize = $fe.ReceiveProtocolLogMaxDirectorySize
            FE_SendProtocolLogPath = $fe.SendProtocolLogPath
            MailboxTransport_ReceiveProtocolLogPath = $mt.ReceiveProtocolLogPath
            ConnectivityLogPath = $ts.ConnectivityLogPath; ConnectivityLogMaxAge = $ts.ConnectivityLogMaxAge
            ExternalDNSServers = ((@($ts.ExternalDNSServers) | ForEach-Object { "$_" }) -join '; ')
            InternalDNSServers = ((@($ts.InternalDNSServers) | ForEach-Object { "$_" }) -join '; ')
            ExternalIPAddress = $ts.ExternalIPAddress
            IntraOrgConnectorProtocolLoggingLevel = $ts.IntraOrgConnectorProtocolLoggingLevel
        }
    }
    Save-Csv @($rows) 'MailFlow-TransportServices'
}

Invoke-Section 'MailFlow-Queues' {
    $rows = foreach ($s in $script:Servers | Where-Object { ($_.IsHubTransportServer -or $_.IsMailboxServer) -and -not $_.IsEdgeServer }) {
        Get-Queue -Server $s.Name -ErrorAction SilentlyContinue | Select-Object @{ n = 'Server'; e = { $s.Name } }, Identity, DeliveryType, Status, MessageCount, NextHopDomain, NextHopConnector, LastError
    }
    Save-Csv @($rows) 'MailFlow-Queues'
}

$umSkip = $(if (-not (Get-Command Get-UMDialPlan -ErrorAction SilentlyContinue)) { 'UM cmdlets not present (Exchange 2019 or later)' } else { $null })
Invoke-Section 'MailFlow-UnifiedMessaging' -SkipReason $umSkip -Script {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-UMService' | Select-Object Name, Status, DialPlans, UMStartupMode, SipAccessService) 'MailFlow-UMService'
    $n += Save-Csv @(Get-Safe 'Get-UMDialPlan' | Select-Object Name, URIType, VoIPSecurity, NumberOfDigitsInExtension, UMServers, UMMailboxPolicies, UMIPGateway) 'MailFlow-UMDialPlans'
    $n += Save-Csv @(Get-Safe 'Get-UMIPGateway') 'MailFlow-UMIPGateways'
    $n += Save-Csv @(Get-Safe 'Get-UMMailboxPolicy' | Select-Object Name, UMDialPlan) 'MailFlow-UMMailboxPolicies'
    $n += Save-Csv @(Get-Safe 'Get-UMMailbox' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, UMDialPlan, UMEnabled, Extensions) 'MailFlow-UMMailboxes'
    $n
}

Invoke-Section 'MailFlow-PopImap' {
    $localPop = $null; $localImap = $null
    $rows = foreach ($s in $script:Servers | Where-Object { ($_.IsClientAccessServer -or $_.IsMailboxServer) -and -not $_.IsEdgeServer }) {
        $pop = $null; $imap = $null
        try { $pop = Get-PopSettings -Server $s.Name -ErrorAction Stop } catch { }
        try { $imap = Get-ImapSettings -Server $s.Name -ErrorAction Stop } catch { }
        if ($s.Name -eq $script:LocalServer) { $localPop = $pop; $localImap = $imap }
        $svc = @{}
        foreach ($n in 'MSExchangePOP3', 'MSExchangePOP3BE', 'MSExchangeIMAP4', 'MSExchangeIMAP4BE') {
            $x = $null
            try { $x = $(if ($s.Name -eq $script:LocalServer) { Get-Service -Name $n -ErrorAction SilentlyContinue } else { Get-Service -ComputerName $s.Name -Name $n -ErrorAction SilentlyContinue }) } catch { }
            $svc[$n] = $(if ($x) { "$($x.Status)/$($x.StartType)" } else { 'n/a' })
        }
        [PSCustomObject]@{
            Server = $s.Name
            POP3_Service = $svc['MSExchangePOP3']; POP3BE_Service = $svc['MSExchangePOP3BE']; IMAP4_Service = $svc['MSExchangeIMAP4']; IMAP4BE_Service = $svc['MSExchangeIMAP4BE']
            POP_LoginType = $pop.LoginType; POP_Bindings = ((@($pop.UnencryptedOrTLSBindings) + @($pop.SSLBindings) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) -join '; '); POP_ProtocolLogEnabled = $pop.ProtocolLogEnabled; POP_LogFileLocation = $pop.LogFileLocation
            IMAP_LoginType = $imap.LoginType; IMAP_Bindings = ((@($imap.UnencryptedOrTLSBindings) + @($imap.SSLBindings) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }) -join '; '); IMAP_ProtocolLogEnabled = $imap.ProtocolLogEnabled; IMAP_LogFileLocation = $imap.LogFileLocation
        }
    }
    Save-Csv @($rows) 'MailFlow-PopImap' | Out-Null
    # Client IPs from this server's POP3/IMAP4 protocol logs (only present if protocol logging was enabled)
    $logRows = @()
    $dirs = @(
        @('POP3', $(if ($localPop -and "$($localPop.LogFileLocation)") { "$($localPop.LogFileLocation)" } elseif ($script:ExchInstall) { Join-Path $script:ExchInstall 'Logging\Pop3' } else { '' })),
        @('IMAP4', $(if ($localImap -and "$($localImap.LogFileLocation)") { "$($localImap.LogFileLocation)" } elseif ($script:ExchInstall) { Join-Path $script:ExchInstall 'Logging\Imap4' } else { '' }))
    )
    foreach ($pair in $dirs) {
        $kind = $pair[0]; $dir = $pair[1]
        if (-not $dir -or -not (Test-Path -LiteralPath $dir)) { continue }
        $agg = @{}
        foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.log' -File -Recurse -ErrorAction SilentlyContinue)) {
            $sr = $null; $ipIdx = 4; $userIdx = 5
            try {
                $sr = Open-LogReader $f.FullName
                while ($null -ne ($line = $sr.ReadLine())) {
                    if ($line.StartsWith('#Fields:')) {
                        $fields = $line.Substring(8).Trim().Split(',')
                        $ipIdx = Find-FieldIndex $fields @('cIp', 'c-ip', 'clientIp', 'client-ip') $ipIdx
                        $userIdx = Find-FieldIndex $fields @('user', 'cs-username', 'userName') $userIdx
                        continue
                    }
                    if ($line.Length -eq 0 -or $line[0] -eq '#') { continue }
                    $c = $line.Split(',')
                    if ($c.Count -le $ipIdx) { continue }
                    $ip = Get-EndpointIp $c[$ipIdx]
                    $user = $(if ($c.Count -gt $userIdx) { $c[$userIdx] } else { '' })
                    $k = "$ip|$user"
                    if (-not $agg.ContainsKey($k)) { $agg[$k] = [PSCustomObject]@{ Protocol = $kind; ClientIp = $ip; User = $user; Lines = 0; Server = $script:LocalServer } }
                    $agg[$k].Lines++
                }
            } catch { Write-Log "  $kind log $($f.Name) failed: $($_.Exception.Message)" 'WARN' } finally { if ($sr) { $sr.Close() } }
        }
        $logRows += @($agg.Values)
    }
    Save-Csv @($logRows | Sort-Object Lines -Descending) 'MailFlow-PopImap-ClientIPs' | Out-Null
    @($rows).Count
}

# ===========================================================================
# 5. CLIENT ACCESS CONFIG
# ===========================================================================
Invoke-Section 'ClientAccess-VirtualDirectories' {
    $rows = @()
    $map = [ordered]@{
        'OWA' = 'Get-OwaVirtualDirectory'; 'ECP' = 'Get-EcpVirtualDirectory'; 'EWS' = 'Get-WebServicesVirtualDirectory'
        'ActiveSync' = 'Get-ActiveSyncVirtualDirectory'; 'OAB' = 'Get-OabVirtualDirectory'; 'MAPI' = 'Get-MapiVirtualDirectory'
        'Autodiscover' = 'Get-AutodiscoverVirtualDirectory'; 'PowerShell' = 'Get-PowerShellVirtualDirectory'
    }
    foreach ($k in $map.Keys) {
        $rows += Get-Safe $map[$k] @{ ADPropertiesOnly = $true } | ForEach-Object {
            [PSCustomObject]@{
                Type = $k; Server = $_.Server; Name = $_.Name; InternalUrl = $_.InternalUrl; ExternalUrl = $_.ExternalUrl
                InternalAuth = (@($_.InternalAuthenticationMethods) -join ';'); ExternalAuth = (@($_.ExternalAuthenticationMethods) -join ';')
                BasicAuth = $_.BasicAuthentication; WindowsAuth = $_.WindowsAuthentication; OAuth = $_.OAuthAuthentication; FormsAuth = $_.FormsAuthentication
                WhenChanged = $_.WhenChanged
            }
        }
    }
    $rows += Get-Safe 'Get-OutlookAnywhere' @{ ADPropertiesOnly = $true } | ForEach-Object {
        [PSCustomObject]@{ Type = 'OutlookAnywhere'; Server = $_.Server; Name = $_.Name; InternalUrl = $_.InternalHostname; ExternalUrl = $_.ExternalHostname; InternalAuth = $_.InternalClientAuthenticationMethod; ExternalAuth = $_.ExternalClientAuthenticationMethod; BasicAuth = ''; WindowsAuth = ''; OAuth = ''; FormsAuth = ''; WhenChanged = $_.WhenChanged }
    }
    $rows += Get-Safe 'Get-ClientAccessService' | ForEach-Object {
        [PSCustomObject]@{ Type = 'AutodiscoverSCP'; Server = $_.Name; Name = 'ClientAccessService'; InternalUrl = $_.AutoDiscoverServiceInternalUri; ExternalUrl = ''; InternalAuth = ''; ExternalAuth = ''; BasicAuth = ''; WindowsAuth = ''; OAuth = ''; FormsAuth = ''; WhenChanged = $_.WhenChanged }
    }
    Save-Csv @($rows) 'ClientAccess-VirtualDirectories'
}

Invoke-Section 'ClientAccess-MobileDevices' {
    $rows = foreach ($d in @(Get-Safe 'Get-MobileDevice' @{ ResultSize = 'Unlimited' })) {
        [PSCustomObject]@{ UserDisplayName = $d.UserDisplayName; DeviceType = $d.DeviceType; DeviceModel = $d.DeviceModel; DeviceOS = $d.DeviceOS; DeviceUserAgent = $d.DeviceUserAgent; DeviceAccessState = $d.DeviceAccessState; FirstSyncTime = $d.FirstSyncTime; WhenChanged = $d.WhenChanged }
    }
    Save-Csv @($rows) 'ClientAccess-MobileDevices'
}

Invoke-Section 'ClientAccess-Certificates' {
    $rows = foreach ($s in $script:Servers | Where-Object { -not $_.IsEdgeServer }) {
        Get-ExchangeCertificate -Server $s.Name -ErrorAction SilentlyContinue | ForEach-Object {
            [PSCustomObject]@{
                Server = $s.Name; Thumbprint = $_.Thumbprint; Subject = $_.Subject; Issuer = $_.Issuer
                CertificateDomains = (@($_.CertificateDomains) -join '; '); NotBefore = $_.NotBefore; NotAfter = $_.NotAfter
                Services = $_.Services; IsSelfSigned = $_.IsSelfSigned; Status = $_.Status; RootCAType = $_.RootCAType; HasPrivateKey = $_.HasPrivateKey; FriendlyName = $_.FriendlyName
            }
        }
    }
    Save-Csv @($rows) 'ClientAccess-Certificates'
}

# ===========================================================================
# 6. EVIDENCE - MESSAGE TRACKING
# ===========================================================================
$script:RelayOutcome = @()
$trackSkip = $(if ($SkipTrackingLogs) { 'SkipTrackingLogs specified' } else { $null })
Invoke-Section 'Evidence-MessageTracking' -SkipReason $trackSkip -Script {
    $servers = @(Get-LogServers)
    $depth = foreach ($s in $servers) {
        $ts = $null
        try { $ts = Get-TransportService -Identity $s.Name -ErrorAction Stop } catch { }
        $lp = "$($ts.MessageTrackingLogPath)"
        $p = $(if ($s.Name -eq $script:LocalServer) { $lp } else { ConvertTo-UncPath $s.Name $lp })
        $st = Get-DirStats -Path $p -Filter 'MSGTRK*.LOG'
        [PSCustomObject]@{ Server = $s.Name; Path = $p; Exists = $st.Exists; Files = $st.Files; SizeMB = $st.SizeMB; OldestLog = $st.Oldest; NewestLog = $st.Newest; DaysAvailable = (Get-DaysAvailable $st.Oldest); ConfiguredMaxAge = $ts.MessageTrackingLogMaxAge; ConfiguredMaxDirSize = $ts.MessageTrackingLogMaxDirectorySize; TrackingEnabled = $ts.MessageTrackingLogEnabled }
    }
    Save-Csv @($depth) 'Evidence-MessageTracking-Depth' | Out-Null

    $end = Get-Date
    $oldest = @($depth | Where-Object { $_.OldestLog -is [datetime] } | ForEach-Object { $_.OldestLog } | Sort-Object)
    $start = $(if ($TrackingDays -gt 0) { $end.AddDays(-$TrackingDays) } elseif ($oldest.Count) { $oldest[0].AddDays(-1) } else { $end.AddDays(-30) })
    Write-Log ('  Tracking log window: {0:yyyy-MM-dd HH:mm} -> {1:yyyy-MM-dd HH:mm} across {2} server(s)' -f $start, $end, $servers.Count)

    $recv = @{}; $send = @{}; $deliver = @{}; $daily = @{}; $fail = @{}
    # Outcome per message: first SMTP receive from a non-Exchange address is the origin;
    # DELIVER / SEND (not intra-org) / FAIL events for the same MessageId are its outcome.
    $origin = @{}; $outcome = @{}
    $chunkDays = 3
    foreach ($s in $servers) {
        $cur = $start
        while ($cur -lt $end) {
            $next = $cur.AddDays($chunkDays); if ($next -gt $end) { $next = $end }
            Write-Host ('  {0} {1:yyyy-MM-dd} .. {2:yyyy-MM-dd}' -f $s.Name, $cur, $next)
            try {
                Get-MessageTrackingLog -Server $s.Name -Start $cur -End $next -ResultSize Unlimited -ErrorAction SilentlyContinue | ForEach-Object {
                    $e = $_
                    $day = $e.Timestamp.ToString('yyyy-MM-dd')
                    $eid = "$($e.EventId)"
                    $dk = "$day|$eid"
                    if (-not $daily.ContainsKey($dk)) { $daily[$dk] = 0 }
                    $daily[$dk]++
                    $mid = "$($e.MessageId)"
                    if ($mid -and $eid -in 'DELIVER', 'SEND', 'FAIL') {
                        if (-not $outcome.ContainsKey($mid)) { $outcome[$mid] = @{ Delivered = 0; Sent = 0; Failed = 0; FailRcpt = @(); Reason = '' } }
                        $o = $outcome[$mid]
                        if ($eid -eq 'DELIVER') { $o.Delivered += @($e.Recipients).Count }
                        elseif ($eid -eq 'SEND' -and "$($e.ConnectorId)" -notmatch '(?i)Intra-Organization') { $o.Sent += @($e.Recipients).Count }
                        elseif ($eid -eq 'FAIL') {
                            $o.Failed += @($e.Recipients).Count
                            if ($o.FailRcpt.Count -lt 5) { $o.FailRcpt += @($e.Recipients | ForEach-Object { "$_".ToLower() }) }
                            if (-not $o.Reason) { $o.Reason = ((@($e.RecipientStatus) -join ' ') -replace '^\[?\{LED=', '' -replace '\};.*$', '') }
                        }
                    }
                    switch ($eid) {
                        'RECEIVE' {
                            if ("$($e.Source)" -ne 'SMTP') { break }
                            $ip = "$($e.ClientIp)"; $oip = "$($e.OriginalClientIp)"
                            $key = "$($s.Name)|$ip|$oip|$($e.ClientHostname)|$($e.ConnectorId)"
                            if (-not $recv.ContainsKey($key)) { $recv[$key] = @{ Server = $s.Name; ClientIp = $ip; OriginalClientIp = $oip; ClientHostname = "$($e.ClientHostname)"; ConnectorId = "$($e.ConnectorId)"; Count = 0; First = $e.Timestamp; Last = $e.Timestamp; Senders = @{}; InternalRcpt = 0; ExternalRcpt = 0; Days = @{}; SampleSubject = ''; TotalBytes = [int64]0 } }
                            $r = $recv[$key]; $r.Count++
                            if ($e.Timestamp -lt $r.First) { $r.First = $e.Timestamp }
                            if ($e.Timestamp -gt $r.Last) { $r.Last = $e.Timestamp }
                            if ($e.Sender -and $r.Senders.Count -lt 25) { $r.Senders["$($e.Sender)".ToLower()] = 1 }
                            foreach ($rcpt in @($e.Recipients)) { if (Test-InternalRecipient "$rcpt") { $r.InternalRcpt++ } else { $r.ExternalRcpt++ } }
                            $r.Days[$day] = 1
                            if ($IncludeSubjects -and -not $r.SampleSubject -and $e.MessageSubject) { $subj = "$($e.MessageSubject)"; $r.SampleSubject = $subj.Substring(0, [math]::Min(60, $subj.Length)) }
                            $r.TotalBytes += [int64]$e.TotalBytes
                            $src = $(if ($oip -and (Get-SourceClass $oip) -eq 'Client') { $oip } elseif ((Get-SourceClass $ip) -eq 'Client') { $ip } else { '' })
                            if ($src -and $mid -and (-not $origin.ContainsKey($mid) -or $e.Timestamp -lt $origin[$mid].Time)) {
                                $origin[$mid] = @{ Ip = $src; Host = "$($e.ClientHostname)"; Connector = "$($e.ConnectorId)"; Sender = "$($e.Sender)".ToLower(); Time = $e.Timestamp }
                            }
                        }
                        'SEND' {
                            $nhIp = "$($e.ServerIp)"
                            $key = "$($s.Name)|$($e.ConnectorId)|$($e.ServerHostname)"
                            if (-not $send.ContainsKey($key)) { $send[$key] = @{ Server = $s.Name; ConnectorId = "$($e.ConnectorId)"; NextHop = "$($e.ServerHostname)"; NextHopIp = $nhIp; Count = 0; First = $e.Timestamp; Last = $e.Timestamp; RcptDomains = @{}; Days = @{} } }
                            $r = $send[$key]; $r.Count++
                            if ($e.Timestamp -lt $r.First) { $r.First = $e.Timestamp }
                            if ($e.Timestamp -gt $r.Last) { $r.Last = $e.Timestamp }
                            foreach ($rcpt in @($e.Recipients)) { if ("$rcpt" -match '@') { $d = "$rcpt".Split('@')[-1].ToLower(); if (-not $r.RcptDomains.ContainsKey($d)) { $r.RcptDomains[$d] = 0 }; $r.RcptDomains[$d]++ } }
                            $r.Days[$day] = 1
                        }
                        'DELIVER' {
                            foreach ($rcpt in @($e.Recipients)) {
                                if ("$rcpt" -match '^(HealthMailbox|SystemMailbox|Migration\.|FederatedEmail|DiscoverySearchMailbox)') { continue }
                                $key = "$rcpt".ToLower()
                                if (-not $deliver.ContainsKey($key)) { $deliver[$key] = [ordered]@{ Recipient = $key; Server = $s.Name; Count = 0; First = $e.Timestamp; Last = $e.Timestamp; LastSender = ''; LastSubject = '' } }
                                $r = $deliver[$key]; $r.Count++
                                if ($e.Timestamp -lt $r.First) { $r.First = $e.Timestamp }
                                if ($e.Timestamp -ge $r.Last) {
                                    $r.Last = $e.Timestamp; $r.LastSender = "$($e.Sender)"
                                    if ($IncludeSubjects -and $e.MessageSubject) { $subj = "$($e.MessageSubject)"; $r.LastSubject = $subj.Substring(0, [math]::Min(60, $subj.Length)) }
                                }
                            }
                        }
                        'FAIL' {
                            $key = "$($e.Source)|$(@($e.RecipientStatus) -join ';')"
                            if ($key.Length -gt 200) { $key = $key.Substring(0, 200) }
                            if (-not $fail.ContainsKey($key)) { $fail[$key] = 0 }
                            $fail[$key]++
                        }
                    }
                }
            } catch { Write-Log "  Tracking chunk failed on $($s.Name) $cur : $($_.Exception.Message)" 'WARN' }
            $cur = $next
        }
    }

    $recvRows = @($recv.Values | ForEach-Object {
        [PSCustomObject]@{
            Server = $_.Server; ClientIp = $_.ClientIp; OriginalClientIp = $_.OriginalClientIp; ClientHostname = $_.ClientHostname; ConnectorId = $_.ConnectorId
            IsMicrosoftIP = (Test-MicrosoftIP $_.ClientIp); OriginalIsMicrosoftIP = (Test-MicrosoftIP $_.OriginalClientIp)
            IsDefaultConnector = ($_.ConnectorId -match '\\(Default|Client|Outbound Proxy) ')
            MessageCount = $_.Count; FirstSeen = $_.First; LastSeen = $_.Last
            ActiveDays = $_.Days.Count; SpanDays = [math]::Round(($_.Last - $_.First).TotalDays, 1)
            MsgsPerActiveDay = $(if ($_.Days.Count) { [math]::Round($_.Count / $_.Days.Count, 1) } else { '' })
            InternalRecipients = $_.InternalRcpt; ExternalRecipients = $_.ExternalRcpt
            TotalMB = [math]::Round($_.TotalBytes / 1MB, 2)
            SampleSenders = ($_.Senders.Keys -join '; '); SampleSubject = $_.SampleSubject
        }
    } | Sort-Object MessageCount -Descending)
    Save-Csv $recvRows 'Evidence-MessageTracking-ReceiveBySource' | Out-Null

    $sendRows = @($send.Values | ForEach-Object {
        $top = $_.RcptDomains.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 15 | ForEach-Object { "$($_.Key)=$($_.Value)" }
        [PSCustomObject]@{ Server = $_.Server; ConnectorId = $_.ConnectorId; NextHop = $_.NextHop; NextHopIp = $_.NextHopIp; IsMicrosoftIP = (Test-MicrosoftIP $_.NextHopIp); MessageCount = $_.Count; FirstSeen = $_.First; LastSeen = $_.Last; ActiveDays = $_.Days.Count; TopRecipientDomains = ($top -join '; ') }
    } | Sort-Object MessageCount -Descending)
    Save-Csv $sendRows 'Evidence-MessageTracking-SendByConnector' | Out-Null

    Save-Csv @($deliver.Values | ForEach-Object { [PSCustomObject]$_ } | Sort-Object Count -Descending) 'Evidence-MessageTracking-LocalDeliveries' | Out-Null
    Save-Csv @($daily.GetEnumerator() | ForEach-Object { $p = $_.Key.Split('|'); [PSCustomObject]@{ Day = $p[0]; EventId = $p[1]; Count = $_.Value } } | Sort-Object Day, EventId) 'Evidence-MessageTracking-DailyHistogram' | Out-Null
    Save-Csv @($fail.GetEnumerator() | ForEach-Object { $p = $_.Key.Split('|', 2); [PSCustomObject]@{ Source = $p[0]; RecipientStatus = $p[1]; Count = $_.Value } } | Sort-Object Count -Descending) 'Evidence-MessageTracking-Failures' | Out-Null

    # Did mail from each original client address actually get anywhere?
    $bySrc = @{}
    foreach ($kv in $origin.GetEnumerator()) {
        $og = $kv.Value
        $k = "$($og.Ip)"
        if (-not $bySrc.ContainsKey($k)) { $bySrc[$k] = @{ Ip = $og.Ip; Hosts = @{}; Connectors = @{}; Senders = @{}; Messages = 0; Delivered = 0; Sent = 0; Failed = 0; NoOutcome = 0; MsgFailedOnly = 0; FailRcpt = @{}; Reasons = @{}; First = $og.Time; Last = $og.Time } }
        $b = $bySrc[$k]; $b.Messages++
        if ($og.Host -and $b.Hosts.Count -lt 5) { $b.Hosts[$og.Host] = 1 }
        if ($og.Connector -and $b.Connectors.Count -lt 5) { $b.Connectors[$og.Connector] = 1 }
        if ($og.Sender -and $b.Senders.Count -lt 10) { $b.Senders[$og.Sender] = 1 }
        if ($og.Time -lt $b.First) { $b.First = $og.Time }
        if ($og.Time -gt $b.Last) { $b.Last = $og.Time }
        $o = $outcome[$kv.Key]
        if (-not $o) { $b.NoOutcome++; continue }
        $b.Delivered += $o.Delivered; $b.Sent += $o.Sent; $b.Failed += $o.Failed
        if ($o.Failed -gt 0 -and ($o.Delivered + $o.Sent) -eq 0) { $b.MsgFailedOnly++ }
        foreach ($fr in $o.FailRcpt) { if (-not $b.FailRcpt.ContainsKey($fr)) { $b.FailRcpt[$fr] = 0 }; $b.FailRcpt[$fr]++ }
        if ($o.Reason) { $rk = $(if ($o.Reason.Length -gt 120) { $o.Reason.Substring(0, 120) } else { $o.Reason }); if (-not $b.Reasons.ContainsKey($rk)) { $b.Reasons[$rk] = 0 }; $b.Reasons[$rk]++ }
    }
    $outRows = @($bySrc.Values | ForEach-Object {
        $topFail = @($_.FailRcpt.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; '
        $topReason = "$(@($_.Reasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1 | ForEach-Object { $_.Key }))"
        $verdict = $(if ($_.Messages -eq $_.MsgFailedOnly) { 'All messages failed' } elseif ($_.MsgFailedOnly -gt 0) { 'Some messages failed' } elseif (($_.Delivered + $_.Sent) -gt 0) { 'Delivered' } else { 'No outcome logged' })
        [PSCustomObject]@{
            OriginalClientIp = $_.Ip; Hostnames = ($_.Hosts.Keys -join '; '); Connectors = ($_.Connectors.Keys -join '; '); SampleSenders = ($_.Senders.Keys -join '; ')
            Messages = $_.Messages; RecipientsDelivered = $_.Delivered; RecipientsSentOn = $_.Sent; RecipientsFailed = $_.Failed
            MessagesFailedEntirely = $_.MsgFailedOnly; MessagesWithoutOutcome = $_.NoOutcome; Verdict = $verdict
            TopFailedRecipients = $topFail; TopFailReason = $topReason; FirstSeen = $_.First; LastSeen = $_.Last
        }
    } | Sort-Object Messages -Descending)
    $script:RelayOutcome = $outRows
    Save-Csv $outRows 'Evidence-MessageTracking-OutcomeBySource' | Out-Null
    $recvRows.Count
}

# ===========================================================================
# 7. EVIDENCE - SMTP RECEIVE PROTOCOL LOGS
# ===========================================================================
$protoSkip = $(if ($SkipProtocolLogs) { 'SkipProtocolLogs specified' } else { $null })
Invoke-Section 'Evidence-SmtpReceiveProtocolLogs' -SkipReason $protoSkip -Script {
    $servers = @(Get-LogServers)
    $agg = @{}; $depthRows = @(); $conn = @{}
    foreach ($s in $servers) {
        $ts = $null; $fe = $null
        try { $ts = Get-TransportService -Identity $s.Name -ErrorAction Stop } catch { }
        try { $fe = Get-FrontendTransportService -Identity $s.Name -ErrorAction Stop } catch { }
        foreach ($pair in @(@('Hub', "$($ts.ReceiveProtocolLogPath)"), @('FrontEnd', "$($fe.ReceiveProtocolLogPath)"))) {
            $role = $pair[0]; $lp = $pair[1]
            if (-not $lp) { continue }
            $p = $(if ($s.Name -eq $script:LocalServer) { $lp } else { ConvertTo-UncPath $s.Name $lp })
            $st = Get-DirStats -Path $p -Filter '*.LOG'
            $depthRows += [PSCustomObject]@{ Server = $s.Name; Role = $role; Path = $p; Exists = $st.Exists; Files = $st.Files; SizeMB = $st.SizeMB; Oldest = $st.Oldest; Newest = $st.Newest; DaysAvailable = (Get-DaysAvailable $st.Oldest) }
            if (-not $st.Exists -or $st.Files -eq 0) { continue }
            $files = Get-ChildItem -LiteralPath $p -Filter '*.LOG' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime
            foreach ($f in $files) {
                $sessions = @{}
                $sr = $null
                try {
                    $sr = Open-LogReader $f.FullName
                    while ($null -ne ($line = $sr.ReadLine())) {
                        if ($line.Length -eq 0 -or $line[0] -eq '#') { continue }
                        # date-time,connector-id,session-id,sequence-number,local-endpoint,remote-endpoint,event,data,context
                        $c = $line.Split(',', 9)
                        if ($c.Count -lt 8) { continue }
                        $ts2 = $c[0]; $cid = $c[1]; $sid = $c[2]; $remote = Get-EndpointIp $c[5]; $ev = $c[6]; $data = $c[7].Trim('"')
                        $ctx = $(if ($c.Count -ge 9) { $c[8].Trim('"') } else { '' })
                        $sk = "$cid|$sid"
                        if (-not $sessions.ContainsKey($sk)) { $sessions[$sk] = @{ Ip = $remote; Conn = $cid; Ehlo = ''; Auth = ''; AuthUser = ''; Tls = $false; Time = $ts2; Mail = 0; Rcpt = 0; Queued = 0; Rejected = 0 } }
                        $ss = $sessions[$sk]
                        if ($ev -eq '<') {
                            $u = $data.ToUpper()
                            if ($u.StartsWith('EHLO') -or $u.StartsWith('HELO')) { $ss.Ehlo = ($data -replace '^(?i)(EHLO|HELO)\s*', '') }
                            elseif ($u.StartsWith('AUTH')) { $parts = $data.Split(' '); if ($parts.Count -gt 1) { $ss.Auth = $parts[1] } }
                            elseif ($u.StartsWith('STARTTLS') -or $u.StartsWith('X-ANONYMOUSTLS')) { $ss.Tls = $true }
                            elseif ($u.StartsWith('MAIL FROM')) { $ss.Mail++ }
                            elseif ($u.StartsWith('RCPT TO')) { $ss.Rcpt++ }
                        }
                        elseif ($ev -eq '>') {
                            # 250 2.6.0 = message queued; 5xx = rejected (relay denied, unknown recipient, ...)
                            if ($data.StartsWith('250 2.6.0')) { $ss.Queued++ }
                            elseif ($data -match '^5\d\d[ -]') { $ss.Rejected++ }
                        }
                        elseif ($ev -eq '*') {
                            # Successful authentication is logged as: *,DOMAIN\user,authenticated
                            if ($ctx -match '(?i)^authenticated') { if (-not $ss.Auth) { $ss.Auth = 'Yes' }; if ($data) { $ss.AuthUser = $data } }
                            elseif ($data -match '(?i)authenticated as (.+)$') { if (-not $ss.Auth) { $ss.Auth = 'Yes' }; $ss.AuthUser = $Matches[1] }
                            if ("$data $ctx" -match '(?i)\btls\b') { $ss.Tls = $true }
                        }
                    }
                } catch { Write-Log "  Protocol log $($f.Name) failed: $($_.Exception.Message)" 'WARN' } finally { if ($sr) { $sr.Close() } }
                foreach ($ss in $sessions.Values) {
                    $k = "$($s.Name)|$role|$($ss.Ip)|$($ss.Conn)"
                    if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Server = $s.Name; Role = $role; ClientIp = $ss.Ip; ConnectorId = $ss.Conn; Sessions = 0; MailCmds = 0; Rcpts = 0; Queued = 0; Rejected = 0; Probe = 0; Ehlo = @{}; AuthMech = @{}; AuthUsers = @{}; TlsSessions = 0; First = $ss.Time; Last = $ss.Time } }
                    $a = $agg[$k]; $a.Sessions++; $a.MailCmds += $ss.Mail; $a.Rcpts += $ss.Rcpt; $a.Queued += $ss.Queued; $a.Rejected += $ss.Rejected
                    $cls = Get-SourceClass $ss.Ip $ss.Ehlo
                    if ($cls -in 'HealthProbe', 'Loopback') { $a.Probe++ }
                    # Per connector, health probes and loopback excluded
                    if (-not $conn.ContainsKey($ss.Conn)) { $conn[$ss.Conn] = @{ Sessions = 0; Client = 0; ExchangeServer = 0; WithMail = 0; Queued = 0; Rejected = 0; Sources = @{}; First = ''; Last = '' } }
                    $cu = $conn[$ss.Conn]; $cu.Sessions++
                    if ($cls -notin 'HealthProbe', 'Loopback') {
                        if ($cls -like 'ExchangeServer:*' -or $cls -eq 'LinkLocal') { $cu.ExchangeServer++ } else { $cu.Client++ }
                        if ($ss.Mail -gt 0) { $cu.WithMail++ }
                        $cu.Queued += $ss.Queued; $cu.Rejected += $ss.Rejected
                        $sk2 = $(if ($ss.Ehlo) { "$($ss.Ip) ($($ss.Ehlo))" } else { "$($ss.Ip)" })
                        if ($cu.Sources.ContainsKey($sk2)) { $cu.Sources[$sk2]++ } elseif ($cu.Sources.Count -lt 50) { $cu.Sources[$sk2] = 1 }
                        if (-not $cu.First -or $ss.Time -lt $cu.First) { $cu.First = $ss.Time }
                        if (-not $cu.Last -or $ss.Time -gt $cu.Last) { $cu.Last = $ss.Time }
                    }
                    if ($ss.Ehlo -and $a.Ehlo.Count -lt 5) { $a.Ehlo[$ss.Ehlo] = 1 }
                    if ($ss.Auth) { $a.AuthMech[$ss.Auth] = 1 }
                    if ($ss.AuthUser -and $a.AuthUsers.Count -lt 5) { $a.AuthUsers[$ss.AuthUser] = 1 }
                    if ($ss.Tls) { $a.TlsSessions++ }
                    if ($ss.Time -lt $a.First) { $a.First = $ss.Time }
                    if ($ss.Time -gt $a.Last) { $a.Last = $ss.Time }
                }
            }
        }
    }
    Save-Csv @($depthRows) 'Evidence-SmtpReceiveProtocolLogs-Depth' | Out-Null
    $rows = @($agg.Values | ForEach-Object {
        [PSCustomObject]@{
            Server = $_.Server; Role = $_.Role; ClientIp = $_.ClientIp; IsMicrosoftIP = (Test-MicrosoftIP $_.ClientIp); ConnectorId = $_.ConnectorId
            SourceClass = (Get-SourceClass $_.ClientIp ($_.Ehlo.Keys | Select-Object -First 1))
            Sessions = $_.Sessions; MailFromCommands = $_.MailCmds; RcptToCommands = $_.Rcpts; QueuedMessages = $_.Queued; Rejected5xx = $_.Rejected
            TlsSessions = $_.TlsSessions; TlsPct = $(if ($_.Sessions) { [math]::Round(100 * $_.TlsSessions / $_.Sessions, 0) } else { '' })
            EhloNames = ($_.Ehlo.Keys -join '; '); AuthMechanisms = ($_.AuthMech.Keys -join '; '); AuthUsers = ($_.AuthUsers.Keys -join '; ')
            FirstSeen = $_.First; LastSeen = $_.Last
        }
    } | Sort-Object MailFromCommands -Descending)
    Save-Csv $rows 'Evidence-SmtpReceiveProtocolLogs-BySource' | Out-Null
    $script:ProtoConnUsage = $conn
    $script:ProtoLogDays = @($depthRows | Where-Object { $_.DaysAvailable -ne '' } | ForEach-Object { [double]$_.DaysAvailable } | Sort-Object | Select-Object -First 1)
    $rows.Count
}

# Every receive connector, including those nobody used: the list that decides which relay
# dependencies are real. Health probes (smtp.availability.contoso.com) and loopback are excluded.
$script:RecvUsage = @()
Invoke-Section 'Evidence-ReceiveConnectorUsage' -SkipReason $protoSkip -Script {
    $window = $(if (@($script:ProtoLogDays).Count) { [math]::Round(@($script:ProtoLogDays)[0], 1) } else { '' })
    $rows = foreach ($c in $script:ReceiveConnectors) {
        $id = "$($c.Identity)"
        $u = $(if ($script:ProtoConnUsage -and $script:ProtoConnUsage.ContainsKey($id)) { $script:ProtoConnUsage[$id] } else { $null })
        $isDefault = ("$($c.Name)" -match '^(Default |Client |Outbound Proxy )')
        $client = $(if ($u) { $u.Client } else { 0 }); $withMail = $(if ($u) { $u.WithMail } else { 0 }); $queued = $(if ($u) { $u.Queued } else { 0 })
        $verdict = $(if ("$($c.ProtocolLoggingLevel)" -ne 'Verbose') { 'Unknown: protocol logging is off' }
            elseif (-not $c.Enabled) { 'Disabled' }
            elseif (-not $u -or ($client + $u.ExchangeServer) -eq 0) { 'No sessions in window' }
            elseif ($withMail -eq 0) { 'Sessions but no mail' }
            elseif ($queued -eq 0) { 'Mail attempted, none accepted' }
            else { 'In use' })
        $top = $(if ($u) { @($u.Sources.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' } else { '' })
        [PSCustomObject]@{
            Server = "$($c.Server)"; Name = "$($c.Name)"; Identity = $id; Enabled = $c.Enabled; IsDefault = $isDefault
            Bindings = ((@($c.Bindings) | ForEach-Object { "$_" }) -join '; '); RemoteIPRangeCount = @($c.RemoteIPRanges).Count
            ProtocolLoggingLevel = "$($c.ProtocolLoggingLevel)"; LogWindowDays = $window
            ClientSessions = $client; ExchangeServerSessions = $(if ($u) { $u.ExchangeServer } else { 0 })
            SessionsWithMail = $withMail; QueuedMessages = $queued; Rejected5xx = $(if ($u) { $u.Rejected } else { 0 })
            TopSources = $top; FirstSeen = $(if ($u) { $u.First } else { '' }); LastSeen = $(if ($u) { $u.Last } else { '' }); Verdict = $verdict
        }
    }
    $script:RecvUsage = @($rows)
    Save-Csv @($rows | Sort-Object IsDefault, Verdict, Identity) 'Evidence-ReceiveConnectorUsage'
}

# ===========================================================================
# 8. EVIDENCE - IIS LOGS
# ===========================================================================
$iisSkip = $(if ($SkipIisLogs) { 'SkipIisLogs specified' } else { $null })
Invoke-Section 'Evidence-IisLogs' -SkipReason $iisSkip -Script {
    $cut = (Get-Date).AddDays(-$IisDays)
    $agg = @{}; $depthRows = @()
    # Managed Availability probes only; everything else (including EWS Managed API and Microsoft 365 traffic) is kept
    $noiseUa = '^(AMProbe|MSEXCHMON|ACTIVEMONITORING|MSExchangeMonitoring)'
    $servers = @($script:Servers | Where-Object { ($_.IsClientAccessServer -or $_.IsMailboxServer) -and -not $_.IsEdgeServer })
    if ($SkipRemoteServers) { $servers = @($servers | Where-Object { $_.Name -eq $script:LocalServer }) }
    foreach ($s in $servers) {
        $sites = @()
        try { $sites = @(Get-IisSiteInfo -Server $s.Name) } catch { Write-Log "  IIS configuration unreadable on $($s.Name): $($_.Exception.Message)" 'WARN' }
        if ($sites.Count -eq 0) { Write-Log "  No IIS site information for $($s.Name); IIS logs not read there" 'WARN'; continue }
        foreach ($site in $sites) {
            if ($site.Name -eq 'Exchange Back End' -and -not $IncludeBackEndIisLogs) { continue }
            $logDir = [System.Environment]::ExpandEnvironmentVariables($site.LogDir)
            $siteDir = Join-Path $logDir ('W3SVC{0}' -f $site.Id)
            $p = $(if ($s.Name -eq $script:LocalServer) { $siteDir } else { ConvertTo-UncPath $s.Name $siteDir })
            $st = Get-DirStats -Path $p -Filter '*.log'
            $depthRows += [PSCustomObject]@{ Server = $s.Name; Site = $site.Name; Path = $p; Exists = $st.Exists; Files = $st.Files; SizeMB = $st.SizeMB; Oldest = $st.Oldest; Newest = $st.Newest; DaysAvailable = (Get-DaysAvailable $st.Oldest) }
            if (-not $st.Exists) { continue }
            $files = Get-ChildItem -LiteralPath $p -Filter '*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cut } | Sort-Object LastWriteTime
            foreach ($f in $files) {
                $sr = $null; $idx = $null
                try {
                    $sr = Open-LogReader $f.FullName
                    while ($null -ne ($line = $sr.ReadLine())) {
                        if ($line.StartsWith('#Fields:')) {
                            $fields = $line.Substring(8).Trim().Split(' ')
                            $idx = @{}; for ($i = 0; $i -lt $fields.Count; $i++) { $idx[$fields[$i]] = $i }
                            continue
                        }
                        if ($line.Length -eq 0 -or $line[0] -eq '#' -or $null -eq $idx) { continue }
                        $c = $line.Split(' ')
                        $uri = $(if ($idx.ContainsKey('cs-uri-stem') -and $c.Count -gt $idx['cs-uri-stem']) { $c[$idx['cs-uri-stem']] } else { '' })
                        $vdir = $(if ($uri -match '^/([^/]+)') { $Matches[1].ToLower() } else { '/' })
                        $ip = $(if ($idx.ContainsKey('c-ip') -and $c.Count -gt $idx['c-ip']) { $c[$idx['c-ip']] } else { '' })
                        $ua = $(if ($idx.ContainsKey('cs(User-Agent)') -and $c.Count -gt $idx['cs(User-Agent)']) { $c[$idx['cs(User-Agent)']] } else { '' })
                        $user = $(if ($idx.ContainsKey('cs-username') -and $c.Count -gt $idx['cs-username']) { $c[$idx['cs-username']] } else { '' })
                        $status = $(if ($idx.ContainsKey('sc-status') -and $c.Count -gt $idx['sc-status']) { $c[$idx['sc-status']] } else { '' })
                        $dt = $(if ($idx.ContainsKey('date') -and $c.Count -gt $idx['date']) { $c[$idx['date']] } else { $f.LastWriteTime.ToString('yyyy-MM-dd') })
                        if ($ua -match $noiseUa -or $user -match 'HealthMailbox') { continue }
                        $uaShort = $(if ($ua.Length -gt 80) { $ua.Substring(0, 80) } else { $ua })
                        $k = "$($s.Name)|$($site.Name)|$vdir|$ip|$uaShort|$user"
                        if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Server = $s.Name; Site = $site.Name; VDir = $vdir; ClientIp = $ip; UserAgent = $uaShort; User = $user; Hits = 0; First = $dt; Last = $dt; Days = @{}; Ok = 0; Auth401 = 0; Err5xx = 0 } }
                        $a = $agg[$k]; $a.Hits++; $a.Days[$dt] = 1
                        if ($dt -lt $a.First) { $a.First = $dt }
                        if ($dt -gt $a.Last) { $a.Last = $dt }
                        if ($status -like '2*') { $a.Ok++ } elseif ($status -eq '401') { $a.Auth401++ } elseif ($status -like '5*') { $a.Err5xx++ }
                    }
                } catch { Write-Log "  IIS log $($f.FullName) failed: $($_.Exception.Message)" 'WARN' } finally { if ($sr) { $sr.Close() } }
            }
        }
    }
    Save-Csv @($depthRows) 'Evidence-IisLogs-Depth' | Out-Null
    $rows = @($agg.Values | ForEach-Object {
        [PSCustomObject]@{ Server = $_.Server; Site = $_.Site; VDir = $_.VDir; ClientIp = $_.ClientIp; IsMicrosoftIP = (Test-MicrosoftIP $_.ClientIp); User = $_.User; UserAgent = $_.UserAgent; Hits = $_.Hits; Http2xx = $_.Ok; Http401 = $_.Auth401; Http5xx = $_.Err5xx; ActiveDays = $_.Days.Count; FirstSeen = $_.First; LastSeen = $_.Last }
    } | Sort-Object Hits -Descending)
    Save-Csv $rows 'Evidence-IisLogs-ByClient' | Out-Null
    $byVdir = @($rows | Group-Object Server, Site, VDir | ForEach-Object {
        [PSCustomObject]@{ Group = $_.Name; Hits = ($_.Group | Measure-Object Hits -Sum).Sum; DistinctClientIPs = @($_.Group | Select-Object -ExpandProperty ClientIp -Unique).Count; DistinctUsers = @($_.Group | Where-Object { $_.User -and $_.User -ne '-' } | Select-Object -ExpandProperty User -Unique).Count; NonMicrosoftHits = [int]($_.Group | Where-Object { $_.IsMicrosoftIP -ne 'True' } | Measure-Object Hits -Sum).Sum }
    } | Sort-Object Hits -Descending)
    Save-Csv $byVdir 'Evidence-IisLogs-ByVDir' | Out-Null
    $rows.Count
}

Invoke-Section 'Evidence-AdminAuditLog' {
    $cfg = Get-Safe 'Get-AdminAuditLogConfig'
    Save-Csv @($cfg | Select-Object AdminAuditLogEnabled, AdminAuditLogAgeLimit, AdminAuditLogCmdlets, AdminAuditLogParameters, AdminAuditLogExcludedCmdlets, LogLevel, UnifiedAuditLogIngestionEnabled) 'Evidence-AdminAuditLogConfig' | Out-Null
    $start = (Get-Date).AddDays(-$AuditDays)
    $entries = @(Get-Safe 'Search-AdminAuditLog' @{ StartDate = $start; EndDate = (Get-Date); ResultSize = 250000 })
    $rows = @($entries | Where-Object { "$($_.CmdletName)" -notmatch '^(Get-|Search-|Test-)' } | Group-Object Caller, CmdletName | ForEach-Object {
        $sorted = @($_.Group | Sort-Object RunDate)
        [PSCustomObject]@{ Caller = $_.Group[0].Caller; Cmdlet = $_.Group[0].CmdletName; Count = $_.Count; First = $sorted[0].RunDate; Last = $sorted[-1].RunDate; ObjectSample = (($sorted | Select-Object -Last 3 | ForEach-Object { "$($_.ObjectModified)" }) -join '; ') }
    } | Sort-Object Count -Descending)
    Save-Csv $rows 'Evidence-AdminAuditLog-ByCallerCmdlet' | Out-Null
    $sortedAll = @($entries | Sort-Object RunDate)
    Save-Csv @([PSCustomObject]@{ Entries = $entries.Count; Oldest = $(if ($sortedAll.Count) { $sortedAll[0].RunDate } else { '' }); Newest = $(if ($sortedAll.Count) { $sortedAll[-1].RunDate } else { '' }); WindowStart = $start }) 'Evidence-AdminAuditLog-Depth' | Out-Null
    $rows.Count
}

# HttpProxy logs name the mailbox behind each request (AnchorMailbox, and mailboxId= for MAPI).
# That separates "user opens own cloud mailbox via redirect" from "user opens an on-prem
# mailbox" - for example the public-folder mailbox when Exchange Online has
# PublicFoldersEnabled = Remote, or a delegate/shared mailbox still on-prem.
$script:ProxyByTarget = @()
$hpSkip = $(if ($SkipHttpProxyLogs) { 'SkipHttpProxyLogs specified' } else { $null })
Invoke-Section 'Evidence-HttpProxyLogs' -SkipReason $hpSkip -Script {
    if (-not $script:ExchInstall) { throw 'Exchange install path unknown' }
    $localRoot = Join-Path $script:ExchInstall 'Logging\HttpProxy'
    $cut = (Get-Date).AddDays(-$IisDays)
    $parsed = 'Autodiscover', 'Mapi', 'Ews', 'RpcHttp', 'Eas'
    $byGuid = @{}; $bySmtp = @{}
    foreach ($m in $script:OnPremMailboxes) {
        $ref = @{ Smtp = "$($m.PrimarySmtpAddress)".ToLower(); Type = "$($m.RecipientTypeDetails)" }
        if ($m.ExchangeGuid) { $byGuid["$($m.ExchangeGuid)".ToLower()] = $ref }
        foreach ($a in @($m.EmailAddresses)) { if ("$a" -match '^(?i)smtp:(.+)$') { $bySmtp[$Matches[1].ToLower()] = $ref } }
    }
    $servers = @($script:Servers | Where-Object { ($_.IsClientAccessServer -or $_.IsMailboxServer) -and -not $_.IsEdgeServer })
    if ($SkipRemoteServers) { $servers = @($servers | Where-Object { $_.Name -eq $script:LocalServer }) }
    $depth = @(); $agg = @{}
    foreach ($s in $servers) {
        $root = $(if ($s.Name -eq $script:LocalServer) { $localRoot } else { ConvertTo-UncPath $s.Name $localRoot })
        foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
            $st = Get-DirStats -Path $d.FullName -Filter '*.LOG'
            $depth += [PSCustomObject]@{ Server = $s.Name; Protocol = $d.Name; Files = $st.Files; SizeMB = $st.SizeMB; Oldest = $st.Oldest; Newest = $st.Newest; DaysAvailable = (Get-DaysAvailable $st.Oldest) }
            if ($parsed -notcontains $d.Name) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -Filter '*.LOG' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cut })) {
                $sr = $null; $iU = -1
                try {
                    $sr = Open-LogReader $f.FullName
                    while ($null -ne ($line = $sr.ReadLine())) {
                        if ($line.StartsWith('#Fields:')) {
                            $fl = @($line.Substring(8).Trim().Split(',') | ForEach-Object { $_.Trim() })
                            $iU = [array]::IndexOf($fl, 'AuthenticatedUser'); $iA = [array]::IndexOf($fl, 'UserAgent'); $iM = [array]::IndexOf($fl, 'AnchorMailbox')
                            $iQ = [array]::IndexOf($fl, 'UrlQuery'); $iS = [array]::IndexOf($fl, 'HttpStatus'); $iC = [array]::IndexOf($fl, 'ClientIpAddress'); $iT = [array]::IndexOf($fl, 'DateTime')
                            continue
                        }
                        if ($line.Length -eq 0 -or $line[0] -eq '#' -or $iU -lt 0) { continue }
                        $c = Split-CsvLine $line
                        $n = $c.Count
                        $user = $(if ($iU -lt $n) { $c[$iU] } else { '' }); $ua = $(if ($iA -ge 0 -and $iA -lt $n) { $c[$iA] } else { '' })
                        if ($user -match 'HealthMailbox' -or $ua -match '^(AMProbe|MSEXCHMON|ACTIVEMONITORING|MSExchangeMonitoring)') { continue }
                        $anchor = $(if ($iM -ge 0 -and $iM -lt $n) { $c[$iM] } else { '' }); $query = $(if ($iQ -ge 0 -and $iQ -lt $n) { $c[$iQ] } else { '' })
                        $status = $(if ($iS -ge 0 -and $iS -lt $n) { $c[$iS] } else { '' }); $when = $(if ($iT -ge 0 -and $iT -lt $n) { $c[$iT] } else { '' })
                        $ip = $(if ($iC -ge 0 -and $iC -lt $n) { Get-EndpointIp $c[$iC] } else { '' })
                        # Target mailbox: MAPI mailboxId=<guid>@domain, else AnchorMailbox (Smtp~a@b, MailboxGuid~g@b, ...)
                        $guid = ''; $smtp = ''
                        if ($query -match '(?i)mailboxId=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $guid = $Matches[1].ToLower() }
                        elseif ($anchor -match '(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $guid = $Matches[1].ToLower() }
                        if ($anchor -match '(?i)^smtp~(.+)$') { $smtp = $Matches[1].ToLower() }
                        $ref = $(if ($guid -and $byGuid.ContainsKey($guid)) { $byGuid[$guid] } elseif ($smtp -and $bySmtp.ContainsKey($smtp)) { $bySmtp[$smtp] } else { $null })
                        $target = $(if ($ref) { $ref.Smtp } elseif ($smtp) { $smtp } elseif ($guid) { $guid } else { $anchor })
                        $ttype = $(if ($ref) { $ref.Type } elseif ($target) { 'NotOnPrem' } else { '' })
                        $k = "$($s.Name)|$($d.Name)|$user|$target"
                        if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Server = $s.Name; Protocol = $d.Name; User = $user; Target = $target; TargetType = $ttype; Hits = 0; Ok = 0; Ips = @{}; First = $when; Last = $when } }
                        $a = $agg[$k]; $a.Hits++
                        if ($status -like '2*') { $a.Ok++ }
                        if ($ip -and $a.Ips.Count -lt 5) { $a.Ips[$ip] = 1 }
                        if ($when -and $when -lt $a.First) { $a.First = $when }
                        if ($when -gt $a.Last) { $a.Last = $when }
                    }
                } catch { Write-Log "  HttpProxy log $($f.FullName) failed: $($_.Exception.Message)" 'WARN' } finally { if ($sr) { $sr.Close() } }
            }
        }
    }
    Save-Csv @($depth) 'Evidence-HttpProxyLogs-Depth' | Out-Null
    $rows = @($agg.Values | ForEach-Object {
        [PSCustomObject]@{ Server = $_.Server; Protocol = $_.Protocol; User = $_.User; Target = $_.Target; TargetType = $_.TargetType; Hits = $_.Hits; Http2xx = $_.Ok; ClientIps = ($_.Ips.Keys -join '; '); FirstSeen = $_.First; LastSeen = $_.Last }
    } | Sort-Object Hits -Descending)
    Save-Csv $rows 'Evidence-HttpProxy-ByUserTarget' | Out-Null
    $byTarget = @($rows | Group-Object Protocol, Target | ForEach-Object {
        $g = $_.Group
        [PSCustomObject]@{
            Protocol = $g[0].Protocol; Target = $g[0].Target; TargetType = $g[0].TargetType
            DistinctUsers = @($g | Where-Object { $_.User } | Select-Object -ExpandProperty User -Unique).Count
            Hits = ($g | Measure-Object Hits -Sum).Sum; Http2xx = ($g | Measure-Object Http2xx -Sum).Sum
            Servers = (@($g | Select-Object -ExpandProperty Server -Unique) -join '; ')
            FirstSeen = ($g | Sort-Object FirstSeen | Select-Object -First 1).FirstSeen; LastSeen = ($g | Sort-Object LastSeen -Descending | Select-Object -First 1).LastSeen
        }
    } | Sort-Object Hits -Descending)
    $script:ProxyByTarget = $byTarget
    Save-Csv $byTarget 'Evidence-HttpProxy-ByTarget' | Out-Null
    $rows.Count
}

# ===========================================================================
# 9. SERVER-LOCAL DEPENDENCIES (this server only)
# ===========================================================================
Invoke-Section 'Local-OS' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $hf = Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending | Select-Object -First 1
    Save-Csv @([PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME; Domain = $cs.Domain; OS = $os.Caption; Version = $os.Version; BuildNumber = $os.BuildNumber
        LastBootUpTime = $os.LastBootUpTime; InstallDate = $os.InstallDate; TotalMemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        Processors = $cs.NumberOfLogicalProcessors; Manufacturer = $cs.Manufacturer; Model = $cs.Model
        LatestHotfix = $(if ($hf) { "$($hf.HotFixID) $($hf.InstalledOn)" } else { '' })
        PSVersion = $PSVersionTable.PSVersion.ToString()
        DotNetRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
        ExchangeInstallPath = $script:ExchInstall; ExchangeCmdletMode = $script:ExchMode
        Disks = ((Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object { "$($_.DeviceID) $([math]::Round($_.FreeSpace / 1GB, 1))/$([math]::Round($_.Size / 1GB, 1)) GB free" }) -join '; ')
        IPAddresses = ((Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { $_.IPAddress }) -join '; ')
        DnsServers = ((Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses }) -join '; ')
    }) 'Local-OS'
}

Invoke-Section 'Local-InstalledPrograms' {
    $rows = @()
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $hive = $k.Split('\')[0]
        $rows += Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, @{ n = 'Hive'; e = { $hive } }, @{ n = 'SystemComponent'; e = { $_.SystemComponent } }
    }
    Save-Csv @($rows | Sort-Object DisplayName -Unique) 'Local-InstalledPrograms'
}

Invoke-Section 'Local-Services' {
    $rows = foreach ($s in Get-CimInstance Win32_Service) {
        $flag = $(if ("$($s.PathName)" -match '\\Windows\\|\\Microsoft\\Exchange Server\\|svchost|MsMpEng') { 'Windows/Exchange' } else { 'Other' })
        [PSCustomObject]@{ Name = $s.Name; DisplayName = $s.DisplayName; State = $s.State; StartMode = $s.StartMode; StartName = $s.StartName; PathName = $s.PathName; Class = $flag }
    }
    Save-Csv @($rows | Sort-Object Class, Name) 'Local-Services'
}

Invoke-Section 'Local-ScheduledTasks' {
    $rows = foreach ($t in @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft\*' })) {
        $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            TaskPath = $t.TaskPath; TaskName = $t.TaskName; State = $t.State; Author = $t.Author; RunAs = $t.Principal.UserId
            Actions = (($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' || ')
            Triggers = (($t.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task', '' }) -join '; ')
            LastRunTime = $info.LastRunTime; LastTaskResult = $info.LastTaskResult; NextRunTime = $info.NextRunTime
        }
    }
    Save-Csv @($rows) 'Local-ScheduledTasks'
}

Invoke-Section 'Local-IIS' {
    $cfg = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
    if (-not (Test-Path -LiteralPath $cfg)) { throw "applicationHost.config not found at $cfg" }
    $x = New-Object System.Xml.XmlDocument
    $x.LoadXml((Get-Content -LiteralPath $cfg -Raw -ErrorAction Stop))
    $rows = @()
    foreach ($s in @($x.SelectNodes('/configuration/system.applicationHost/sites/site'))) {
        $siteName = $s.GetAttribute('name')
        $bind = @($s.SelectNodes('bindings/binding') | ForEach-Object { '{0} {1}' -f $_.GetAttribute('protocol'), $_.GetAttribute('bindingInformation') }) -join '; '
        $rows += [PSCustomObject]@{ Type = 'Site'; Name = $siteName; Id = $s.GetAttribute('id'); PhysicalPath = ''; Bindings = $bind; AppPool = '' }
        foreach ($a in @($s.SelectNodes('application'))) {
            $vd = $a.SelectSingleNode("virtualDirectory[@path='/']")
            $rows += [PSCustomObject]@{ Type = 'App'; Name = "$siteName$($a.GetAttribute('path'))"; Id = ''; PhysicalPath = $(if ($vd) { $vd.GetAttribute('physicalPath') } else { '' }); Bindings = ''; AppPool = $a.GetAttribute('applicationPool') }
        }
    }
    foreach ($ap in @($x.SelectNodes('/configuration/system.applicationHost/applicationPools/add'))) {
        $pm = $ap.SelectSingleNode('processModel')
        $rows += [PSCustomObject]@{ Type = 'AppPool'; Name = $ap.GetAttribute('name'); Id = ''; PhysicalPath = ''; Bindings = ''; AppPool = $(if ($pm) { ('identityType={0} userName={1}' -f $pm.GetAttribute('identityType'), $pm.GetAttribute('userName')) } else { '' }) }
    }
    foreach ($m in @($x.SelectNodes('/configuration/system.webServer/globalModules/add'))) {
        $img = $m.GetAttribute('image')
        if ($img -notmatch '(?i)\\Windows\\|%windir%|%SystemRoot%|\\Microsoft\\Exchange Server\\|ExchangeInstall|\\V15\\|\\Microsoft\.NET\\') {
            $rows += [PSCustomObject]@{ Type = 'NonDefaultGlobalModule'; Name = $m.GetAttribute('name'); Id = ''; PhysicalPath = $img; Bindings = ''; AppPool = '' }
        }
    }
    Save-Csv @($rows) 'Local-IIS'
}

Invoke-Section 'Local-Network' {
    $procs = @{}; Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)
    Save-Csv @($listen | Select-Object LocalAddress, LocalPort, OwningProcess, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } } | Sort-Object LocalPort -Unique) 'Local-ListeningPorts' | Out-Null
    $listenPorts = @($listen | Select-Object -ExpandProperty LocalPort -Unique)
    $est = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $listenPorts -contains $_.LocalPort -and $_.RemoteAddress -notmatch '^127\.|^::1' })
    $erows = @($est | Group-Object RemoteAddress, LocalPort | ForEach-Object {
        [PSCustomObject]@{ RemoteAddress = $_.Group[0].RemoteAddress; IsMicrosoftIP = (Test-MicrosoftIP $_.Group[0].RemoteAddress); LocalPort = $_.Group[0].LocalPort; Process = $procs[[int]$_.Group[0].OwningProcess]; Connections = $_.Count }
    } | Sort-Object LocalPort, Connections -Descending)
    Save-Csv $erows 'Local-InboundEstablishedConnections' | Out-Null
    $fw = @(Get-NetFirewallRule -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | Where-Object { "$($_.Group)" -notmatch '@' -and $_.DisplayName -notmatch '^(Core Networking|File and Printer|Remote|Windows|Network Discovery|Delivery|Cast)' } |
        Select-Object DisplayName, Profile, Action, @{ n = 'Ports'; e = { (($_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue).LocalPort) -join ';' } }, @{ n = 'Program'; e = { ($_ | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program } })
    Save-Csv $fw 'Local-CustomFirewallRules' | Out-Null
    $erows.Count
}

Invoke-Section 'Local-Agents' {
    $pattern = 'backup|veeam|commvault|netbackup|arcserve|acronis|veritas|unitrends|datto|rubrik|cohesity|avamar|networker|dpm|defender|crowdstrike|sentinel|carbon|cylance|sophos|mcafee|trellix|symantec|trend|kaspersky|eset|splunk|forwarder|nxlog|winlogbeat|elastic|datadog|solarwinds|prtg|nagios|zabbix|scom|momagent|zix|proofpoint|mimecast|barracuda|ironport|cisco|archiv|journal|enterprise vault|mailstore|fax|rightfax|zetafax|nuance|kofax|hyland|onbase|epic|cerner|meditech|qualys|tenable|nessus|rapid7'
    $rows = @()
    $rows += Get-CimInstance Win32_Service | Where-Object { "$($_.DisplayName)" -match $pattern -or "$($_.PathName)" -match $pattern } | ForEach-Object { [PSCustomObject]@{ Type = 'Service'; Name = $_.DisplayName; Detail = $_.PathName; State = $_.State } }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        $rows += Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { "$($_.DisplayName)" -match $pattern } | ForEach-Object { [PSCustomObject]@{ Type = 'Program'; Name = $_.DisplayName; Detail = $_.DisplayVersion; State = $_.Publisher } }
    }
    $vss = @()
    try { $vss = @(& vssadmin list writers 2>$null | Select-String 'Writer name' | ForEach-Object { ($_.Line -replace "Writer name:\s*'", '' -replace "'$", '').Trim() }) } catch { }
    $rows += [PSCustomObject]@{ Type = 'VSSWriters'; Name = ($vss -join '; '); Detail = ''; State = '' }
    Save-Csv @($rows) 'Local-Agents'
}

Invoke-Section 'Local-EventLogErrors' {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2, 3; StartTime = (Get-Date).AddDays(-30) } -ErrorAction SilentlyContinue)
    $rows = @($ev | Group-Object ProviderName, Id | ForEach-Object {
        $first = ("$($_.Group[0].Message)" -split "`n")[0]
        [PSCustomObject]@{ Provider = $_.Group[0].ProviderName; EventId = $_.Group[0].Id; Level = $_.Group[0].LevelDisplayName; Count = $_.Count; Last = ($_.Group | Sort-Object TimeCreated | Select-Object -Last 1).TimeCreated; SampleMessage = $first.Substring(0, [math]::Min(200, $first.Length)) }
    } | Sort-Object Count -Descending | Select-Object -First 300)
    Save-Csv $rows 'Local-EventLogErrors'
}

# ===========================================================================
# 10. DNS - internal and public view for every accepted domain
# ===========================================================================
function Resolve-Rec {
    param($View, $Server, $Name, $Type)
    try {
        $a = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
        if ($Server) { $a.Server = $Server }
        $res = Resolve-DnsName @a
        $out = foreach ($r in $res) {
            if ("$($r.Type)" -ne $Type) { continue }
            $val = switch ("$($r.Type)") {
                'MX'    { "$($r.Preference) $($r.NameExchange)" }
                'TXT'   { (@($r.Strings) -join '') }
                'CNAME' { $r.NameHost }
                'SRV'   { "$($r.Priority) $($r.Weight) $($r.Port) $($r.NameTarget)" }
                'PTR'   { $r.NameHost }
                'A'     { $r.IPAddress }
                'AAAA'  { $r.IPAddress }
                default { "$r" }
            }
            [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = $val; TTL = $r.TTL; Status = 'OK' }
        }
        if (-not $out) { [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = ''; TTL = ''; Status = 'NoRecord' } } else { $out }
    } catch { [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = ''; TTL = ''; Status = $_.Exception.Message } }
}

Invoke-Section 'DNS-Records' {
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { throw 'Resolve-DnsName not available on this system' }
    $domains = @($script:AcceptedDomainNames)
    $pub = $null
    foreach ($ps in @(@($PublicDnsServer, '1.1.1.1') | Select-Object -Unique)) { try { $null = Resolve-DnsName -Name 'microsoft.com' -Type A -Server $ps -DnsOnly -ErrorAction Stop; $pub = $ps; break } catch { } }
    if (-not $pub) { Write-Log '  No public resolver reachable; public DNS view will be empty.' 'WARN' }
    $views = @(, @('Internal', $null)); if ($pub) { $views += , @("Public($pub)", $pub) }
    $rows = @()
    foreach ($d in $domains) {
        foreach ($v in $views) {
            $rows += Resolve-Rec $v[0] $v[1] $d 'MX'
            $rows += Resolve-Rec $v[0] $v[1] $d 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "_dmarc.$d" 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "selector1._domainkey.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "selector2._domainkey.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "autodiscover.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "autodiscover.$d" 'A'
            $rows += Resolve-Rec $v[0] $v[1] "_autodiscover._tcp.$d" 'SRV'
            $rows += Resolve-Rec $v[0] $v[1] "_mta-sts.$d" 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "_smtp._tls.$d" 'TXT'
            foreach ($h in 'mail', 'smtp', 'webmail', 'owa', 'exchange', 'autodiscover-s', 'lyncdiscover', 'sip') { $rows += Resolve-Rec $v[0] $v[1] "$h.$d" 'A' }
            $rows += Resolve-Rec $v[0] $v[1] ('{0}.mail.protection.outlook.com' -f ($d -replace '\.', '-')) 'A'
            foreach ($mx in @($rows | Where-Object { $_.View -eq $v[0] -and $_.Name -eq $d -and $_.Type -eq 'MX' -and $_.Value })) {
                $rows += Resolve-Rec $v[0] $v[1] (($mx.Value -split ' ')[-1]) 'A'
            }
        }
    }
    $extra = @()
    $extra += @(Get-Safe 'Get-SendConnector' | ForEach-Object { "$($_.Fqdn)"; @($_.SmartHosts) | ForEach-Object { "$_" } })
    $extra += @(Get-Safe 'Get-ReceiveConnector' | ForEach-Object { "$($_.Fqdn)" })
    $extra += @(Get-Safe 'Get-OwaVirtualDirectory' @{ ADPropertiesOnly = $true } | ForEach-Object { if ($_.ExternalUrl) { ([uri]"$($_.ExternalUrl)").Host }; if ($_.InternalUrl) { ([uri]"$($_.InternalUrl)").Host } })
    $extra += @(Get-Safe 'Get-WebServicesVirtualDirectory' @{ ADPropertiesOnly = $true } | ForEach-Object { if ($_.ExternalUrl) { ([uri]"$($_.ExternalUrl)").Host }; if ($_.InternalUrl) { ([uri]"$($_.InternalUrl)").Host } })
    $extra += @(Get-Safe 'Get-OutlookAnywhere' @{ ADPropertiesOnly = $true } | ForEach-Object { "$($_.ExternalHostname)"; "$($_.InternalHostname)" })
    try { $extra += ("$((Get-Safe 'Get-HybridConfiguration').TlsCertificateName)" -replace '.*CN=([^,]+).*', '$1') } catch { }
    $extra = @($extra | Where-Object { $_ -and $_ -match '\.' -and $_ -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^\[' -and $_ -notmatch '[<>]' } | ForEach-Object { "$_".ToLower() } | Sort-Object -Unique)
    foreach ($h in $extra) { foreach ($v in $views) { $rows += Resolve-Rec $v[0] $v[1] $h 'A' } }
    $script:NamespaceHosts = $extra; $script:PublicResolver = $pub
    if ($pub) {
        $ips = @()
        $ips += @($rows | Where-Object { $_.Type -eq 'TXT' -and $_.Value -match 'v=spf1' } | ForEach-Object { [regex]::Matches($_.Value, 'ip4:(\d+\.\d+\.\d+\.\d+)') | ForEach-Object { $_.Groups[1].Value } })
        $ips += @($rows | Where-Object { $_.View -like 'Public*' -and $_.Type -eq 'A' -and $_.Value } | ForEach-Object { $_.Value })
        $ts = $null
        try { $ts = Get-TransportService -Identity $script:LocalServer -ErrorAction Stop } catch { }
        if ($ts -and $ts.ExternalIPAddress) { $ips += "$($ts.ExternalIPAddress)" }
        foreach ($ip in @($ips | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' -and $_ -notmatch '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)' } | Sort-Object -Unique)) {
            $o = $ip.Split('.'); $rows += Resolve-Rec "Public($pub)" $pub "$($o[3]).$($o[2]).$($o[1]).$($o[0]).in-addr.arpa" 'PTR'
        }
    }
    Save-Csv @($rows) 'DNS-Records' | Out-Null
    $viewPrefix = $(if ($pub) { 'Public*' } else { 'Internal' })
    $viewRows = @($rows | Where-Object { $_.View -like $viewPrefix })
    $assess = foreach ($d in $domains) {
        $spf = "$(($viewRows | Where-Object { $_.Name -eq $d -and $_.Type -eq 'TXT' -and $_.Value -match '^v=spf1' } | Select-Object -First 1).Value)"
        $mx = (@($viewRows | Where-Object { $_.Name -eq $d -and $_.Type -eq 'MX' -and $_.Value } | ForEach-Object { $_.Value }) -join '; ')
        $auto = (@($viewRows | Where-Object { $_.Name -eq "autodiscover.$d" -and $_.Value } | ForEach-Object { $_.Value }) -join '; ')
        [PSCustomObject]@{
            Domain = $d; View = $viewPrefix.TrimEnd('*'); MX = $mx; MXPointsToEOP = ($mx -match 'mail\.protection\.outlook\.com')
            SPF = $spf; SPFIncludesEOP = ($spf -match 'spf\.protection\.outlook\.com'); SPFHasIp4OrA = ($spf -match 'ip4:|\sa[\s:]|\smx')
            SPFIncludes = (@([regex]::Matches($spf, 'include:(\S+)') | ForEach-Object { $_.Groups[1].Value }) -join '; ')
            DKIM_selector1 = "$(($viewRows | Where-Object { $_.Name -eq "selector1._domainkey.$d" -and $_.Value } | Select-Object -First 1).Value)"
            DMARC = "$(($viewRows | Where-Object { $_.Name -eq "_dmarc.$d" -and $_.Value } | Select-Object -First 1).Value)"
            AutodiscoverPublic = $auto; AutodiscoverPointsToEXO = ($auto -match 'autodiscover\.outlook\.com')
        }
    }
    Save-Csv @($assess) 'DNS-Assessment' | Out-Null
    @($rows).Count
}

# Every Exchange host name (vdir URLs, SCPs, connector FQDNs, HCW certificate name, autodiscover.<domain>)
# with what it resolves to. A name on the DAG cluster IP disappears when the DAG is removed; a
# public record for a name no internet client uses is exposure that can be removed early.
$script:NamespaceRows = @()
Invoke-Section 'Topology-NamespaceCheck' {
    $sources = @{}
    $addSrc = { param($h, $src) $h = "$h".ToLower().TrimEnd('.'); if (-not $h -or $h -notmatch '\.' -or $h -match '^\d+\.\d+\.\d+\.\d+$') { return }; if (-not $sources.ContainsKey($h)) { $sources[$h] = @{} }; $sources[$h][$src] = 1 }
    foreach ($h in @($script:NamespaceHosts)) { & $addSrc $h 'Vdir/Connector/Hybrid' }
    foreach ($scp in @($script:Scps)) { foreach ($u in @("$($scp.ServiceBindingInformation)" -split '; ')) { try { & $addSrc ([uri]$u).Host 'SCP' } catch { } } }
    foreach ($d in $script:AcceptedDomainNames) { if ($d -notmatch 'onmicrosoft\.com$') { & $addSrc "autodiscover.$d" 'Autodiscover'; & $addSrc "mail.$d" 'mail.<domain>' } }
    foreach ($s in $script:Servers) { & $addSrc "$($s.Fqdn)" 'ExchangeServer' }
    $dagIps = @{}
    foreach ($dag in @(Get-Safe 'Get-DatabaseAvailabilityGroup')) {
        foreach ($ip in @($dag.DatabaseAvailabilityGroupIpv4Addresses) + @($dag.DatabaseAvailabilityGroupIpAddresses)) { if ("$ip" -match '^\d+\.\d+\.\d+\.\d+$') { $dagIps["$ip"] = "$($dag.Name)" } }
    }
    # Public wildcard per parent zone: a random label that resolves means *.zone exists
    $wild = @{}
    $pub = $script:PublicResolver
    $rows = foreach ($h in @($sources.Keys | Sort-Object)) {
        $int = @(Resolve-Rec 'Internal' $null $h 'A' | Where-Object { $_.Value } | ForEach-Object { "$($_.Value)" })
        $pubA = @(); $isWild = $false
        if ($pub) {
            $pubA = @(Resolve-Rec 'Public' $pub $h 'A' | Where-Object { $_.Value } | ForEach-Object { "$($_.Value)" })
            $zone = ($h -split '\.', 2)[1]
            if ($zone -and -not $wild.ContainsKey($zone)) { $wild[$zone] = @(Resolve-Rec 'Public' $pub ('decomcheck-{0}.{1}' -f (Get-Random -Minimum 100000 -Maximum 999999), $zone) 'A' | Where-Object { $_.Value } | ForEach-Object { "$($_.Value)" }) }
            if ($pubA.Count -and $wild[$zone].Count -and -not @($pubA | Where-Object { $wild[$zone] -notcontains $_ }).Count) { $isWild = $true }
        }
        $targets = @(foreach ($ip in $int) {
            if ($dagIps.ContainsKey($ip)) { "DAG cluster IP ($($dagIps[$ip]))" }
            elseif ($script:ExchangeServerIps.ContainsKey($ip)) { "Exchange server $($script:ExchangeServerIps[$ip])" }
            else { "Other ($ip)" }
        })
        [PSCustomObject]@{
            Name = $h; Sources = ($sources[$h].Keys -join '; ')
            InternalIPs = ($int -join '; '); InternalTarget = (($targets | Sort-Object -Unique) -join '; ')
            OnDagClusterIP = [bool]@($int | Where-Object { $dagIps.ContainsKey($_) }).Count
            PublicIPs = ($pubA -join '; '); PublicIsWildcard = $isWild
            PubliclyResolvable = ($pubA.Count -gt 0 -and -not $isWild)
        }
    }
    $script:NamespaceRows = @($rows)
    Save-Csv @($rows) 'Topology-NamespaceCheck'
}

# ===========================================================================
# 11. FINDINGS - what the evidence above says, as rules a reviewer can check
# ===========================================================================
Invoke-Section 'Findings' {
    $f = @()
    $add = { param($sev, $area, $finding, $evidence, $file) [PSCustomObject]@{ Severity = $sev; Area = $area; Finding = $finding; Evidence = $evidence; File = $file } }

    # Receive connectors nobody used
    $custom = @($script:RecvUsage | Where-Object { -not $_.IsDefault })
    $unused = @($custom | Where-Object { $_.Verdict -in 'No sessions in window', 'Sessions but no mail' })
    if ($custom.Count) {
        $f += & $add 'Info' 'Relay' ('{0} of {1} custom receive connectors received no mail in the {2}-day protocol-log window' -f $unused.Count, $custom.Count, $custom[0].LogWindowDays) (($unused | ForEach-Object { $_.Identity }) -join '; ') 'Evidence-ReceiveConnectorUsage.csv'
    }
    foreach ($c in @($custom | Where-Object { $_.Verdict -eq 'Mail attempted, none accepted' })) {
        $f += & $add 'Medium' 'Relay' "Connector $($c.Identity): clients tried to send mail but none was accepted" $c.TopSources 'Evidence-ReceiveConnectorUsage.csv'
    }
    foreach ($c in @($custom | Where-Object { $_.Verdict -like 'Unknown*' })) {
        $f += & $add 'Medium' 'Relay' "Connector $($c.Identity): protocol logging is off, so its use cannot be measured" "ProtocolLoggingLevel=$($c.ProtocolLoggingLevel)" 'Evidence-ReceiveConnectorUsage.csv'
    }
    # Relay sources whose mail went nowhere
    foreach ($r in @($script:RelayOutcome | Where-Object { $_.Verdict -eq 'All messages failed' })) {
        $f += & $add 'High' 'Relay' "All $($r.Messages) message(s) from $($r.OriginalClientIp) failed; mail from this source is not being delivered today" "Senders: $($r.SampleSenders). Reason: $($r.TopFailReason). Recipients: $($r.TopFailedRecipients)" 'Evidence-MessageTracking-OutcomeBySource.csv'
    }
    # Namespaces on the DAG cluster IP / publicly resolvable
    foreach ($n in @($script:NamespaceRows | Where-Object { $_.OnDagClusterIP })) {
        $f += & $add 'High' 'Namespace' "$($n.Name) resolves internally to the DAG cluster IP; removing the DAG removes this name" "$($n.InternalIPs) ($($n.InternalTarget)); used by: $($n.Sources)" 'Topology-NamespaceCheck.csv'
    }
    $pubNames = @($script:NamespaceRows | Where-Object { $_.PubliclyResolvable -and $_.Sources -match 'Vdir|SCP|ExchangeServer' })
    if ($pubNames.Count) {
        $f += & $add 'Medium' 'Exposure' "$($pubNames.Count) Exchange host name(s) resolve publicly; compare with internet clients in the IIS evidence before keeping them published" (($pubNames | ForEach-Object { "$($_.Name)=$($_.PublicIPs)" }) -join '; ') 'Topology-NamespaceCheck.csv'
    }
    # Other forests: Exchange organizations, SCPs, SCP pointers
    foreach ($p in @($script:ForestPresence | Where-Object { -not $_.IsLocalForest })) {
        if (-not $p.Reachable) { $f += & $add 'Medium' 'Forests' "Forest $($p.Forest) could not be read; SCPs and Exchange objects there are unknown (use -ForestCredential)" $p.Error 'Topology-ForestExchangePresence.csv'; continue }
        if ([int]$p.ExchangeServerCount -gt 0 -or $p.ExchangeOrganizations) { $f += & $add 'High' 'Forests' "Forest $($p.Forest) contains its own Exchange organization ($($p.ExchangeOrganizations)) with $($p.ExchangeServerCount) server object(s)" $p.ExchangeServers 'Topology-ForestExchangePresence.csv' }
        if ([int]$p.AutodiscoverSCPs -gt 0 -or [int]$p.SCPPointers -gt 0) { $f += & $add 'High' 'Autodiscover' "Forest $($p.Forest) has $($p.AutodiscoverSCPs) Autodiscover SCP(s) and $($p.SCPPointers) SCP pointer(s); domain-joined Outlook there follows them" 'See Topology-ForestSCPs.csv' 'Topology-ForestSCPs.csv' }
    }
    # Tenants
    $tenants = @($script:ForestPresence | ForEach-Object { "$($_.EntraConnectTenants)" -split '; ' } | Where-Object { $_ } | Sort-Object -Unique)
    $iocTenants = @(Get-Safe 'Get-IntraOrganizationConnector' | ForEach-Object { @($_.TargetAddressDomains) } | ForEach-Object { "$_".ToLower() } | Where-Object { $_ -match '\.mail\.onmicrosoft\.com$' } | ForEach-Object { $_ -replace '\.mail\.onmicrosoft\.com$', '.onmicrosoft.com' } | Sort-Object -Unique)
    $allTenants = @(@($tenants) + @($iocTenants) | Sort-Object -Unique)
    if ($allTenants.Count -gt 1) {
        $f += & $add 'High' 'Tenants' "This environment is tied to $($allTenants.Count) Microsoft 365 tenants; hybrid teardown has to cover each one" "Entra Connect accounts: $($tenants -join ', '). Hybrid IOC targets: $($iocTenants -join ', ')" 'Topology-ForestExchangePresence.csv; Hybrid-IntraOrganizationConnector.csv'
    }
    # Hybrid Agent
    foreach ($h in @($script:HybridAgentRows)) { $f += & $add 'Info' 'Hybrid' "Hybrid Agent service found on $($h.Server) ($($h.Status)); uninstall it and remove its Entra application proxy connector at teardown" "$($h.Name) / $($h.Display)" 'Hybrid-ModernHybridAgent.csv' }
    # System mailboxes on dismounted databases
    $down = @($script:Databases | Where-Object { "$($_.Mounted)" -eq 'False' } | ForEach-Object { "$($_.Name)" })
    foreach ($db in $down) {
        $sys = @($script:OnPremMailboxes | Where-Object { "$($_.Database)" -eq $db -and "$($_.RecipientTypeDetails)" -match 'Arbitration|AuditLog|PublicFolder|Discovery' })
        if ($sys.Count) { $f += & $add 'High' 'Databases' "Database $db is dismounted and holds $($sys.Count) system mailbox(es); it must be mounted (or the mailboxes rehomed) before decommission" (($sys | ForEach-Object { "$($_.RecipientTypeDetails): $($_.Name)" }) -join '; ') 'Recipients-Mailboxes.csv; Topology-MailboxDatabases.csv' }
    }
    # On-prem mailboxes opened by many users (remote public folders, shared or delegate access)
    foreach ($t in @($script:ProxyByTarget | Where-Object { $_.Protocol -in 'Mapi', 'RpcHttp', 'Ews' -and $_.TargetType -and $_.TargetType -ne 'NotOnPrem' -and $_.DistinctUsers -ge 2 })) {
        $why = $(if ($t.TargetType -eq 'PublicFolderMailbox') { 'public-folder mailbox; with Exchange Online PublicFoldersEnabled=Remote every Outlook profile opens it' } else { 'on-prem mailbox opened by several accounts (shared or delegate access)' })
        $f += & $add 'High' 'Client access' "$($t.DistinctUsers) users opened $($t.Target) over $($t.Protocol) ($why)" "$($t.Hits) requests, $($t.FirstSeen) to $($t.LastSeen), servers $($t.Servers)" 'Evidence-HttpProxy-ByTarget.csv'
    }
    $sev = @{ High = 0; Medium = 1; Info = 2 }
    Save-Csv @($f | Sort-Object { $sev[$_.Severity] }, Area) 'Findings'
}

# ===========================================================================
# 12. PREREQUISITE SUMMARY
# ===========================================================================
Invoke-Section 'Prerequisites-Summary' {
    $rows = @()
    function Import-Out { param($n) $p = Join-Path $script:Out "$n.csv"; if ((Test-Path $p) -and (Get-Item $p).Length -gt 3) { @(Import-Csv $p) } else { @() } }
    function ConvertTo-Days { param($v) $x = 0.0; if ([double]::TryParse("$v", [ref]$x)) { $x } else { 0.0 } }
    $unreadable = 'Not readable - check the admin share or run on that server'
    foreach ($r in (Import-Out 'Evidence-MessageTracking-Depth')) {
        $d = ConvertTo-Days $r.DaysAvailable
        $rows += [PSCustomObject]@{ Check = "Message tracking depth ($($r.Server))"; Value = "$($r.DaysAvailable) days, $($r.SizeMB) MB, cfg $($r.ConfiguredMaxAge)/$($r.ConfiguredMaxDirSize)"; Target = '90 days'; Status = $(if ($r.Exists -ne 'True') { $unreadable } elseif ($d -ge 90) { 'OK' } elseif ($d -ge 30) { 'Marginal' } else { 'Short' }) }
    }
    foreach ($r in (Import-Out 'MailFlow-ReceiveConnectors' | Where-Object { $_.IsDefault -eq 'False' })) {
        $rows += [PSCustomObject]@{ Check = "Protocol logging on $($r.Identity)"; Value = $r.ProtocolLoggingLevel; Target = 'Verbose, >=30 days'; Status = $(if ($r.ProtocolLoggingLevel -eq 'Verbose') { 'OK' } else { 'Off' }) }
    }
    foreach ($r in (Import-Out 'Evidence-SmtpReceiveProtocolLogs-Depth')) {
        $d = ConvertTo-Days $r.DaysAvailable
        $rows += [PSCustomObject]@{ Check = "SMTP receive protocol log depth ($($r.Server)/$($r.Role))"; Value = "$($r.DaysAvailable) days, $($r.Files) files"; Target = '30 days'; Status = $(if ($r.Exists -ne 'True') { $unreadable } elseif ($d -ge 30) { 'OK' } elseif ([int]$r.Files -gt 0) { 'Short' } else { 'None' }) }
    }
    foreach ($r in (Import-Out 'Evidence-IisLogs-Depth')) {
        $d = ConvertTo-Days $r.DaysAvailable
        $rows += [PSCustomObject]@{ Check = "IIS log depth ($($r.Server)/$($r.Site))"; Value = "$($r.DaysAvailable) days, $($r.SizeMB) MB"; Target = '30-90 days'; Status = $(if ($r.Exists -ne 'True') { $unreadable } elseif ($d -ge 90) { 'OK' } elseif ($d -ge 30) { 'Marginal' } else { 'Short' }) }
    }
    $ad = Import-Out 'Evidence-AdminAuditLog-Depth' | Select-Object -First 1
    if ($ad) { $rows += [PSCustomObject]@{ Check = 'Admin audit log'; Value = "$($ad.Entries) entries, oldest $($ad.Oldest)"; Target = '90 days'; Status = $(if ([int]$ad.Entries -gt 0) { 'OK' } else { 'Empty' }) } }
    $rows += [PSCustomObject]@{ Check = 'Microsoft 365 IP list downloaded'; Value = $script:MsCidrs.Count; Target = '>0'; Status = $(if ($script:MsCidrs.Count) { 'OK' } else { 'No internet - IsMicrosoftIP blank' }) }
    $rows += [PSCustomObject]@{ Check = 'Elevated'; Value = $isAdmin; Target = 'True'; Status = $(if ($isAdmin) { 'OK' } else { 'Not elevated' }) }
    $rows += [PSCustomObject]@{ Check = 'Exchange cmdlet mode'; Value = $script:ExchMode; Target = ''; Status = 'Info' }
    Save-Csv $rows 'Prerequisites-Summary'
}

# ===========================================================================
# Finish
# ===========================================================================
$script:Manifest | Export-Csv -Path (Join-Path $script:Out 'Manifest.csv') -NoTypeInformation -Encoding UTF8
$meta = [PSCustomObject]@{
    ScriptVersion = $script:ScriptVersion; Script = 'OnPrem'; RunOn = $env:COMPUTERNAME; RunBy = "$env:USERDOMAIN\$env:USERNAME"
    Started = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'); Finished = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Elevated = $isAdmin; ExchangeCmdletMode = $script:ExchMode; PSVersion = $PSVersionTable.PSVersion.ToString()
    Parameters = (($PSBoundParameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
    Sections = $script:Manifest.Count
    Collected = @($script:Manifest | Where-Object { $_.Status -eq 'Collected' }).Count
    Failed = @($script:Manifest | Where-Object { $_.Status -eq 'Failed' }).Count
    Skipped = @($script:Manifest | Where-Object { $_.Status -eq 'Skipped' }).Count
}
Save-Json $meta 'RunInfo'
Write-Log ('Finished. Sections: {0} collected, {1} failed, {2} skipped.' -f $meta.Collected, $meta.Failed, $meta.Skipped)
Stop-RunTranscript

if (-not $NoZip) {
    $zip = "$OutputRoot.zip"
    try {
        Compress-Archive -Path (Join-Path $OutputRoot '*') -DestinationPath $zip -Force -ErrorAction Stop
        Write-Log "ZIP written: $zip"
        Write-Host "`nReturn this file for analysis:`n  $zip`n" -ForegroundColor Green
    } catch { Write-Log "Zip failed: $($_.Exception.Message). Return the folder $OutputRoot instead." 'WARN' }
} else { Write-Host "`nOutput folder: $OutputRoot`n" -ForegroundColor Green }
