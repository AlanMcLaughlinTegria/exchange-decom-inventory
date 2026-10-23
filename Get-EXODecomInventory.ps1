#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only discovery inventory of the Exchange Online side of a hybrid
    organisation, collected ahead of on-prem Exchange decommissioning.

.DESCRIPTION
    Run from any Windows machine with internet access and the
    ExchangeOnlineManagement module 3.x. Microsoft.Graph.Authentication is
    optional (licensing and directory sync status).

    Roles: Exchange Administrator, or Global Reader for a read-only account.
    The audit log section needs View-Only Audit Logs; the compliance section
    needs read access in Microsoft Purview (for example Compliance Administrator).

    If an Exchange Online session is already connected in this window it is
    reused; otherwise the script signs in interactively.

    The script makes NO configuration changes; it only calls Get-*/Search-*
    cmdlets. Nothing is emailed or uploaded: all output is saved locally.

    Output: folder of CSV/JSON/TXT + Manifest.csv, RunLog.txt, Transcript.txt,
    zipped. Return the ZIP.

.PARAMETER OutputRoot
    Folder to write into. Default: timestamped folder next to the script;
    falls back to C:\DecomInventory, then %TEMP%, if that is not writable.
.PARAMETER UserPrincipalName
    Admin UPN to pre-fill the sign-in prompt.
.PARAMETER SkipGraph
    Skip Microsoft Graph sections (licensing, directory sync status).
.PARAMETER SkipMessageTrace
    Skip the message trace.
.PARAMETER MessageTraceDays
    Days of message trace to collect, 1-90. Default 90. More than 10 days needs
    Get-MessageTraceV2 (current ExchangeOnlineManagement); with the older
    Get-MessageTrace the window is capped at 10 days. A busy tenant can take
    hours at 90 days; use 30 or less to shorten the run.
.PARAMETER SkipAuditLog
    Skip the unified audit log search.
.PARAMETER SkipCompliance
    Skip the Security & Compliance (Purview retention) session.
.PARAMETER AuditDays
    Days of unified audit log to summarise. Default 90.
.PARAMETER PublicDnsServer
    Resolver for public DNS. Default 8.8.8.8, falls back to 1.1.1.1.
.PARAMETER NoZip
    Leave the output folder unzipped.

.EXAMPLE
    .\Get-EXODecomInventory.ps1 -UserPrincipalName admin@contoso.com

.NOTES
    Version 1.2
      - Message trace covers up to 90 days (default) through Get-MessageTraceV2, saved locally,
        with automatic waits when Microsoft throttles the queries. -MessageTraceDays sets the window.
    Version 1.1
      Fixed
      - The Exchange Online sign-in was commented out, so every section failed unless a session was
        already open. The script now reuses a live session or signs in.
      - WhenSoftDeleted was always blank for inactive mailboxes (property was not requested).
      - A cmdlet missing from the module or tenant no longer aborts the whole section.
      - Connect-MgGraph -NoWelcome and Connect-IPPSSession -ShowBanner are only passed when supported.
      - Wildcard accepted domains no longer produce invalid DNS lookups.
      Changed
      - The Purview (compliance) section runs last. Sessions are only disconnected at the end if
        this script opened them.
      - Dates in CSV files are written as yyyy-MM-dd HH:mm:ss.
      Removed
      - The 90-day historical message trace requests (Start-HistoricalSearch). A submitted search
        makes Microsoft send a notification email; the script now only saves reports locally.
        Historical searches that already exist are still listed (read-only).
      Added
      - Transcript.txt, output folder fallback; the DNS assessment uses the internal view when no
        public resolver is reachable.
#>
[CmdletBinding()]
param(
    [string]$OutputRoot,
    [string]$UserPrincipalName,
    [switch]$SkipGraph,
    [switch]$SkipMessageTrace,
    [ValidateRange(1, 90)][int]$MessageTraceDays = 90,
    [switch]$SkipAuditLog,
    [switch]$SkipCompliance,
    [int]$AuditDays = 90,
    [string]$PublicDnsServer = '8.8.8.8',
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

$leaf = 'DecomInventory_EXO_{0}' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
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
function Save-Text { param([object[]]$Data, [string]$Name) $Data | Format-List * | Out-String -Width 4096 | Set-Content -Path (Join-Path $script:Out "$Name.txt") -Encoding UTF8 }
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

# Runs a Get-* command only if it exists; a missing command, an unsupported
# parameter or a terminating error is logged and returns nothing instead of
# aborting the calling section.
function Get-Safe {
    param([Parameter(Mandatory = $true)][string]$Command, [hashtable]$Params = @{})
    if (-not (Get-Command -Name $Command -ErrorAction SilentlyContinue)) { Write-Log "  $Command is not available; skipped" 'WARN'; return }
    $ev = $null
    try { & $Command @Params -ErrorAction SilentlyContinue -ErrorVariable ev }
    catch { Write-Log "  $Command failed: $($_.Exception.Message)" 'WARN'; return }
    if ($ev) { Write-Log ('  {0}: {1} error(s), first: {2}' -f $Command, @($ev).Count, "$(@($ev)[0])") 'WARN' }
}

# Runs one message trace query; when Microsoft throttles it, waits and retries.
function Invoke-TraceQuery {
    param([string]$Label, [scriptblock]$Query)
    $waits = @(60, 120, 240, 300, 300)
    for ($i = 0; ; $i++) {
        try { return @(& $Query) }
        catch {
            if ($i -ge $waits.Count -or $_.Exception.Message -notmatch 'throttl|\b429\b|too many requests|rate limit') { throw }
            Write-Log ('  {0} throttled; waiting {1}s (retry {2} of {3})' -f $Label, $waits[$i], ($i + 1), $waits.Count) 'WARN'
            Start-Sleep -Seconds $waits[$i]
        }
    }
}

function Get-ExoConnection {
    try {
        @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
            "$($_.State)" -eq 'Connected' -and "$($_.IsEopSession)" -ne 'True' -and ("$($_.TokenStatus)" -eq '' -or "$($_.TokenStatus)" -eq 'Active')
        }) | Select-Object -First 1
    } catch { $null }
}

# ---------------------------------------------------------------------------
# Connect
# ---------------------------------------------------------------------------
Write-Log "EXO decom inventory v$($script:ScriptVersion) starting (PowerShell $($PSVersionTable.PSVersion))"
Write-Log "Output: $OutputRoot"

$exoMod = Get-Module -ListAvailable ExchangeOnlineManagement | Sort-Object Version -Descending | Select-Object -First 1
if (-not $exoMod) {
    Write-Log 'ExchangeOnlineManagement module not found. Install with: Install-Module ExchangeOnlineManagement -Scope CurrentUser' 'ERROR'
    Stop-RunTranscript; return
}
if ($exoMod.Version.Major -lt 3) {
    Write-Log "ExchangeOnlineManagement $($exoMod.Version) found; version 3.x or later is required. Update with: Update-Module ExchangeOnlineManagement" 'ERROR'
    Stop-RunTranscript; return
}
Write-Log "ExchangeOnlineManagement $($exoMod.Version)"
try { Import-Module ExchangeOnlineManagement -ErrorAction Stop } catch { Write-Log "Import-Module ExchangeOnlineManagement failed: $($_.Exception.Message)" 'ERROR'; Stop-RunTranscript; return }

$connectArgs = @{ ShowBanner = $false; ErrorAction = 'Stop' }
if ($UserPrincipalName) { $connectArgs.UserPrincipalName = $UserPrincipalName }
$script:WeConnectedExo = $false
$ci = Get-ExoConnection
if ($ci) {
    Write-Log "Reusing the existing Exchange Online session ($($ci.UserPrincipalName))"
    if ($UserPrincipalName -and "$($ci.UserPrincipalName)" -ne $UserPrincipalName) { Write-Log "Existing session is for $($ci.UserPrincipalName), not $UserPrincipalName. Run Disconnect-ExchangeOnline first to use a different account." 'WARN' }
} else {
    Write-Log 'Signing in to Exchange Online'
    try { Connect-ExchangeOnline @connectArgs; $script:WeConnectedExo = $true }
    catch { Write-Log "Connect-ExchangeOnline failed: $($_.Exception.Message)" 'ERROR'; Stop-RunTranscript; return }
    $ci = Get-ExoConnection
}
if (-not $ci -or -not (Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue)) { Write-Log 'No usable Exchange Online session after sign-in.' 'ERROR'; Stop-RunTranscript; return }
Write-Log "Connected to tenant $($ci.TenantID) as $($ci.UserPrincipalName)"

$script:GraphOk = $false
$script:WeConnectedGraph = $false
if (-not $SkipGraph) {
    if (Get-Module -ListAvailable Microsoft.Graph.Authentication) {
        try {
            Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
            $mgArgs = @{ Scopes = @('Organization.Read.All', 'Directory.Read.All', 'User.Read.All'); ErrorAction = 'Stop' }
            if ((Get-Command Connect-MgGraph).Parameters.ContainsKey('NoWelcome')) { $mgArgs.NoWelcome = $true }
            Connect-MgGraph @mgArgs | Out-Null
            $script:GraphOk = $true; $script:WeConnectedGraph = $true
            Write-Log 'Connected to Microsoft Graph'
        } catch { Write-Log "Graph sign-in failed; Graph sections skipped. $($_.Exception.Message) (For an assembly or 'method not found' error, run the script in PowerShell 7, or use -SkipGraph.)" 'WARN' }
    } else { Write-Log 'Microsoft.Graph.Authentication not installed; Graph sections skipped. Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' 'WARN' }
}

$script:AcceptedDomains = @(Get-Safe 'Get-AcceptedDomain')
$script:AcceptedDomainNames = @($script:AcceptedDomains | ForEach-Object { ("$($_.DomainName)".ToLower()) -replace '^\*\.', '' } | Where-Object { $_ } | Sort-Object -Unique)

# ===========================================================================
# 1. ORG / HYBRID
# ===========================================================================
Invoke-Section 'Org-OrganizationConfig' {
    $o = Get-OrganizationConfig -ErrorAction Stop
    Save-Text @($o) 'Org-OrganizationConfig'
    Save-Csv @($o | Select-Object Name, DisplayName, IsDehydrated, OAuth2ClientProfileEnabled, PublicFoldersEnabled, PublicFolderMigrationComplete, PublicFolderMailboxesLockedForNewConnections, PublicFolderMailboxesMigrationComplete, RemotePublicFolderMailboxes, MailTipsExternalRecipientsTipsEnabled, AuditDisabled, SmtpActionableMessagesEnabled, SendFromAliasEnabled, DefaultAuthenticationPolicy, WhenCreated) 'Org-OrganizationConfig' | Out-Null
    1
}

Invoke-Section 'Org-OnPremisesOrganization' { Save-Csv @(Get-Safe 'Get-OnPremisesOrganization') 'Org-OnPremisesOrganization' }

Invoke-Section 'Org-Hybrid' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-IntraOrganizationConnector') 'Org-IntraOrganizationConnector'
    $n += Save-Csv @(Get-Safe 'Get-IntraOrganizationConfiguration') 'Org-IntraOrganizationConfiguration'
    $n += Save-Csv @(Get-Safe 'Get-OrganizationRelationship') 'Org-OrganizationRelationship'
    $n += Save-Csv @(Get-Safe 'Get-FederationTrust') 'Org-FederationTrust'
    $n += Save-Csv @(Get-Safe 'Get-FederatedOrganizationIdentifier') 'Org-FederatedOrganizationIdentifier'
    $n += Save-Csv @(Get-Safe 'Get-AvailabilityAddressSpace') 'Org-AvailabilityAddressSpace'
    $n += Save-Csv @(Get-Safe 'Get-SharingPolicy') 'Org-SharingPolicy'
    $n += Save-Csv @(Get-Safe 'Get-HybridMailflowDatacenterIPs') 'Org-HybridMailflowDatacenterIPs'
    $n
}

Invoke-Section 'Org-Migration' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-MigrationEndpoint') 'Org-MigrationEndpoint'
    $n += Save-Csv @(Get-Safe 'Get-MigrationBatch') 'Org-MigrationBatch'
    $n += Save-Csv @(Get-Safe 'Get-MoveRequest' @{ ResultSize = 'Unlimited' }) 'Org-MoveRequest'
    $n += Save-Csv @(Get-Safe 'Get-MigrationConfig') 'Org-MigrationConfig'
    $n
}

$graphSkip = $(if (-not $script:GraphOk) { 'Graph not connected' } else { $null })
Invoke-Section 'Org-DirectorySync' -SkipReason $graphSkip -Script {
    $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime,verifiedDomains,tenantType' -ErrorAction Stop
    $o = $org.value[0]
    $row = [PSCustomObject]@{
        TenantId = $o.id; DisplayName = $o.displayName; TenantType = $o.tenantType
        OnPremisesSyncEnabled = $o.onPremisesSyncEnabled; OnPremisesLastSyncDateTime = $o.onPremisesLastSyncDateTime; OnPremisesLastPasswordSyncDateTime = $o.onPremisesLastPasswordSyncDateTime
        VerifiedDomains = (($o.verifiedDomains | ForEach-Object { "$($_.name)[$($_.type)$(if ($_.isDefault) { ',default' })$(if ($_.isInitial) { ',initial' })]" }) -join '; ')
    }
    Save-Csv @($row) 'Org-DirectorySync' | Out-Null
    try {
        $sp = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/directory/onPremisesSynchronization' -ErrorAction Stop
        Save-Json $sp 'Org-OnPremisesSynchronization'
    } catch { Write-Log "  onPremisesSynchronization not readable: $($_.Exception.Message)" 'WARN' }
    try {
        $synced = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users/$count?$filter=onPremisesSyncEnabled eq true' -Headers @{ ConsistencyLevel = 'eventual' } -OutputType PSObject -ErrorAction Stop
        $total = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users/$count' -Headers @{ ConsistencyLevel = 'eventual' } -OutputType PSObject -ErrorAction Stop
        Save-Csv @([PSCustomObject]@{ TotalUsers = "$total"; SyncedUsers = "$synced"; CloudOnlyUsers = ([int]"$total" - [int]"$synced") }) 'Org-UserSyncCounts' | Out-Null
    } catch { Write-Log "  User count query failed: $($_.Exception.Message)" 'WARN' }
    1
}

Invoke-Section 'Org-Licensing' -SkipReason $graphSkip -Script {
    $skus = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -ErrorAction Stop
    $rows = foreach ($s in $skus.value) {
        $exo = @($s.servicePlans | Where-Object { $_.servicePlanName -match 'EXCHANGE' } | ForEach-Object { "$($_.servicePlanName):$($_.provisioningStatus)" })
        [PSCustomObject]@{ SkuPartNumber = $s.skuPartNumber; SkuId = $s.skuId; Enabled = $s.prepaidUnits.enabled; Consumed = $s.consumedUnits; Suspended = $s.prepaidUnits.suspended; Warning = $s.prepaidUnits.warning; CapabilityStatus = $s.capabilityStatus; ExchangePlans = ($exo -join '; ') }
    }
    Save-Csv @($rows) 'Org-Licensing'
}

# ===========================================================================
# 2. MAIL FLOW CONFIG
# ===========================================================================
Invoke-Section 'MailFlow-Domains' {
    $n = 0
    $n += Save-Csv @($script:AcceptedDomains | Select-Object Name, DomainName, DomainType, Default, InitialDomain, MatchSubDomains, OutboundOnly, AuthenticationType, WhenChanged) 'MailFlow-AcceptedDomains'
    $n += Save-Csv @(Get-Safe 'Get-RemoteDomain') 'MailFlow-RemoteDomains'
    $n
}

Invoke-Section 'MailFlow-Connectors' {
    $inb = @(Get-Safe 'Get-InboundConnector')
    $rows = foreach ($c in $inb) {
        [PSCustomObject]@{
            Name = $c.Name; Enabled = $c.Enabled; ConnectorType = $c.ConnectorType; ConnectorSource = $c.ConnectorSource
            SenderDomains = (@($c.SenderDomains) -join '; '); SenderIPAddresses = (@($c.SenderIPAddresses) -join '; ')
            TlsSenderCertificateName = $c.TlsSenderCertificateName; RequireTls = $c.RequireTls; RestrictDomainsToIPAddresses = $c.RestrictDomainsToIPAddresses; RestrictDomainsToCertificate = $c.RestrictDomainsToCertificate
            CloudServicesMailEnabled = $c.CloudServicesMailEnabled; TreatMessagesAsInternal = $c.TreatMessagesAsInternal; EFSkipLastIP = $c.EFSkipLastIP; EFSkipIPs = (@($c.EFSkipIPs) -join '; ')
            Comment = $c.Comment; WhenChanged = $c.WhenChanged
        }
    }
    Save-Csv @($rows) 'MailFlow-InboundConnectors' | Out-Null
    $outb = @(Get-Safe 'Get-OutboundConnector' @{ IncludeTestModeConnectors = $true })
    if ($outb.Count -eq 0) { $outb = @(Get-Safe 'Get-OutboundConnector') }
    $orows = foreach ($c in $outb) {
        [PSCustomObject]@{
            Name = $c.Name; Enabled = $c.Enabled; ConnectorType = $c.ConnectorType; ConnectorSource = $c.ConnectorSource
            RecipientDomains = (@($c.RecipientDomains) -join '; '); SmartHosts = (@($c.SmartHosts) -join '; ')
            UseMXRecord = $c.UseMXRecord; TlsSettings = $c.TlsSettings; TlsDomain = $c.TlsDomain
            RouteAllMessagesViaOnPremises = $c.RouteAllMessagesViaOnPremises; CloudServicesMailEnabled = $c.CloudServicesMailEnabled; AllAcceptedDomains = $c.AllAcceptedDomains
            IsTransportRuleScoped = $c.IsTransportRuleScoped; TestMode = $c.TestMode; Comment = $c.Comment; WhenChanged = $c.WhenChanged
        }
    }
    Save-Csv @($orows) 'MailFlow-OutboundConnectors' | Out-Null
    $cmt = @($orows | Where-Object { "$($_.RouteAllMessagesViaOnPremises)" -eq 'True' })
    Save-Csv @([PSCustomObject]@{ CentralizedMailTransportEnabled = ($cmt.Count -gt 0); ConnectorsWithRouteAllViaOnPrem = (($cmt | ForEach-Object { $_.Name }) -join '; '); InboundOnPremConnectors = @($rows | Where-Object { "$($_.ConnectorType)" -eq 'OnPremises' }).Count; OutboundOnPremConnectors = @($orows | Where-Object { "$($_.ConnectorType)" -eq 'OnPremises' }).Count }) 'MailFlow-Connectors-Summary' | Out-Null
    @($rows).Count + @($orows).Count
}

Invoke-Section 'MailFlow-Rules' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-TransportRule' @{ ResultSize = 'Unlimited' } | Select-Object Name, State, Priority, Mode, Description, RouteMessageOutboundConnector, WhenChanged) 'MailFlow-TransportRules'
    $n += Save-Csv @(Get-Safe 'Get-JournalRule') 'MailFlow-JournalRules'
    $n += Save-Csv @(Get-Safe 'Get-TransportConfig' | Select-Object JournalingReportNdrTo, MaxSendSize, MaxReceiveSize, MaxRecipientEnvelopeLimit, ExternalPostmasterAddress, SmtpClientAuthenticationDisabled, AllowLegacyTLSClients, HeaderPromotionModeSetting) 'MailFlow-TransportConfig'
    $n += Save-Csv @(Get-Safe 'Get-DkimSigningConfig' | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME, SelectorBeforeRotateOnDate, SelectorAfterRotateOnDate, LastChecked, WhenChanged) 'MailFlow-DkimSigningConfig'
    $n += Save-Csv @(Get-Safe 'Get-HostedConnectionFilterPolicy' | Select-Object Name, IPAllowList, IPBlockList, EnableSafeList, IsDefault) 'MailFlow-ConnectionFilterPolicy'
    $n += Save-Csv @(Get-Safe 'Get-HostedOutboundSpamFilterPolicy' | Select-Object Name, IsDefault, RecipientLimitExternalPerHour, RecipientLimitInternalPerHour, RecipientLimitPerDay, ActionWhenThresholdReached, AutoForwardingMode) 'MailFlow-OutboundSpamPolicy'
    $n += Save-Csv @(Get-Safe 'Get-HostedContentFilterPolicy' | Select-Object Name, IsDefault, AllowedSenderDomains, AllowedSenders, BlockedSenderDomains, SpamAction, HighConfidenceSpamAction, PhishSpamAction) 'MailFlow-ContentFilterPolicy'
    $n += Save-Csv @(Get-Safe 'Get-EOPProtectionPolicyRule') 'MailFlow-EOPProtectionPolicyRules'
    $n += Save-Csv @(Get-Safe 'Get-TenantAllowBlockListItems' @{ ListType = 'Sender' }) 'MailFlow-TenantAllowBlockList-Sender'
    $n
}

Invoke-Section 'MailFlow-Auth' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-AuthenticationPolicy') 'MailFlow-AuthenticationPolicies'
    $n += Save-Csv @(Get-Safe 'Get-CASMailboxPlan' | Select-Object DisplayName, SmtpClientAuthenticationDisabled, PopEnabled, ImapEnabled, ActiveSyncEnabled, IsDefault) 'MailFlow-CASMailboxPlans'
    $n += Save-Csv @(Get-Safe 'Get-CASMailbox' @{ ResultSize = 'Unlimited'; Filter = 'SmtpClientAuthenticationDisabled -eq $false' } | Select-Object DisplayName, PrimarySmtpAddress, SmtpClientAuthenticationDisabled, PopEnabled, ImapEnabled) 'MailFlow-SmtpAuthEnabledMailboxes'
    $n
}

# ===========================================================================
# 3. RECIPIENTS
# ===========================================================================
Invoke-Section 'Recipients-Summary' {
    $rows = @(Get-Safe 'Get-Recipient' @{ ResultSize = 'Unlimited' } | Group-Object RecipientTypeDetails | ForEach-Object { [PSCustomObject]@{ RecipientTypeDetails = $_.Name; Count = $_.Count } })
    Save-Csv @($rows) 'Recipients-Summary'
}

Invoke-Section 'Recipients-Mailboxes' {
    $mbx = @(Get-Safe 'Get-EXOMailbox' @{ ResultSize = 'Unlimited'; PropertySets = @('Minimum', 'Hold', 'Archive', 'Delivery'); Properties = @('RecipientTypeDetails', 'IsDirSynced', 'WhenMailboxCreated', 'LitigationHoldEnabled', 'LitigationHoldDate', 'InPlaceHolds', 'RetentionHoldEnabled', 'ArchiveStatus', 'ArchiveGuid', 'ForwardingAddress', 'ForwardingSmtpAddress', 'DeliverToMailboxAndForward', 'HiddenFromAddressListsEnabled', 'EmailAddressPolicyEnabled', 'ExchangeGuid', 'WhenCreated') })
    $rows = foreach ($m in $mbx) {
        [PSCustomObject]@{
            DisplayName = $m.DisplayName; PrimarySmtpAddress = $m.PrimarySmtpAddress; RecipientTypeDetails = $m.RecipientTypeDetails
            IsDirSynced = $m.IsDirSynced; ExchangeGuid = $m.ExchangeGuid
            LitigationHoldEnabled = $m.LitigationHoldEnabled; LitigationHoldDate = $m.LitigationHoldDate; InPlaceHolds = (@($m.InPlaceHolds) -join '; '); RetentionHoldEnabled = $m.RetentionHoldEnabled
            ArchiveStatus = $m.ArchiveStatus; ArchiveGuid = $m.ArchiveGuid
            ForwardingAddress = $m.ForwardingAddress; ForwardingSmtpAddress = $m.ForwardingSmtpAddress; DeliverToMailboxAndForward = $m.DeliverToMailboxAndForward
            HiddenFromAddressListsEnabled = $m.HiddenFromAddressListsEnabled; EmailAddressPolicyEnabled = $m.EmailAddressPolicyEnabled
            WhenMailboxCreated = $m.WhenMailboxCreated; WhenCreated = $m.WhenCreated
        }
    }
    Save-Csv @($rows) 'Recipients-Mailboxes' | Out-Null
    Save-Csv @($rows | Group-Object RecipientTypeDetails, IsDirSynced | ForEach-Object { [PSCustomObject]@{ Group = $_.Name; Count = $_.Count } }) 'Recipients-Mailboxes-Summary' | Out-Null
    @($rows).Count
}

Invoke-Section 'Recipients-MailUsers' {
    # MailUsers in EXO are usually on-prem mailboxes not yet migrated (or external/linked accounts)
    Save-Csv @(Get-Safe 'Get-MailUser' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress, RecipientTypeDetails, IsDirSynced, ExchangeGuid, ArchiveGuid, WhenCreated) 'Recipients-MailUsers'
}

Invoke-Section 'Recipients-InactiveMailboxes' {
    Save-Csv @(Get-Safe 'Get-EXOMailbox' @{ InactiveMailboxOnly = $true; ResultSize = 'Unlimited'; PropertySets = @('Minimum', 'Hold'); Properties = @('WhenSoftDeleted') } | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, WhenSoftDeleted, LitigationHoldEnabled, InPlaceHolds) 'Recipients-InactiveMailboxes'
}

Invoke-Section 'Recipients-Groups' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-DistributionGroup' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, RecipientTypeDetails, GroupType, IsDirSynced, ManagedBy, RequireSenderAuthenticationEnabled, HiddenFromAddressListsEnabled, WhenCreated) 'Recipients-DistributionGroups'
    $n += Save-Csv @(Get-Safe 'Get-DynamicDistributionGroup' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, RecipientFilter, WhenCreated) 'Recipients-DynamicDistributionGroups'
    $n += Save-Csv @(Get-Safe 'Get-UnifiedGroup' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, AccessType, ResourceProvisioningOptions, HiddenFromExchangeClientsEnabled, WhenCreated) 'Recipients-UnifiedGroups'
    $n += Save-Csv @(Get-Safe 'Get-MailContact' @{ ResultSize = 'Unlimited' } | Select-Object DisplayName, PrimarySmtpAddress, ExternalEmailAddress, IsDirSynced, WhenCreated) 'Recipients-MailContacts'
    $n
}

Invoke-Section 'Recipients-PublicFolders' {
    $o = Get-OrganizationConfig -ErrorAction Stop
    Save-Csv @([PSCustomObject]@{
        PublicFoldersEnabled = $o.PublicFoldersEnabled; PublicFolderMigrationComplete = $o.PublicFolderMigrationComplete
        PublicFolderMailboxesLockedForNewConnections = $o.PublicFolderMailboxesLockedForNewConnections; PublicFolderMailboxesMigrationComplete = $o.PublicFolderMailboxesMigrationComplete
        RemotePublicFolderMailboxes = (@($o.RemotePublicFolderMailboxes) -join '; '); RootPublicFolderMailbox = $o.RootPublicFolderMailbox
        PublicFolderMailboxCount = @(Get-Safe 'Get-Mailbox' @{ PublicFolder = $true; ResultSize = 'Unlimited' }).Count
        MailEnabledPublicFolderCount = @(Get-Safe 'Get-MailPublicFolder' @{ ResultSize = 'Unlimited' }).Count
    }) 'Recipients-PublicFolders' | Out-Null
    Save-Csv @(Get-Safe 'Get-PublicFolderMigrationRequest') 'Recipients-PublicFolderMigrationRequests' | Out-Null
    1
}

Invoke-Section 'Recipients-Policies' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-EmailAddressPolicy') 'Recipients-EmailAddressPolicies'
    $n += Save-Csv @(Get-Safe 'Get-AddressBookPolicy') 'Recipients-AddressBookPolicies'
    $n += Save-Csv @(Get-Safe 'Get-RetentionPolicy' | Select-Object Name, RetentionPolicyTagLinks, IsDefault) 'Recipients-RetentionPolicies'
    $n += Save-Csv @(Get-Safe 'Get-OrganizationConfig' | Select-Object DistributionGroupNamingPolicy, DistributionGroupDefaultOU) 'Recipients-GroupNamingPolicy'
    $n
}

Invoke-Section 'Recipients-RBAC' {
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-RoleGroup' | Select-Object Name, Members, ManagedBy, WhenCreated) 'Recipients-RoleGroups'
    $n += Save-Csv @(Get-Safe 'Get-ManagementRoleAssignment' | Where-Object { "$($_.RoleAssigneeType)" -ne 'RoleGroup' -or $_.CustomRecipientWriteScope } | Select-Object Name, Role, RoleAssigneeName, RoleAssigneeType, CustomRecipientWriteScope, Enabled, WhenCreated) 'Recipients-NonDefaultRoleAssignments'
    $n += Save-Csv @(Get-Safe 'Get-ServicePrincipal' | Select-Object DisplayName, AppId, ObjectId) 'Recipients-ExchangeServicePrincipals'
    $n
}

# ===========================================================================
# 4. EVIDENCE - MESSAGE TRACE (last 10 days)
# ===========================================================================
$mtSkip = $(if ($SkipMessageTrace) { 'SkipMessageTrace specified' } else { $null })
Invoke-Section 'Evidence-MessageTrace' -SkipReason $mtSkip -Script {
    $end = Get-Date
    $onPremInbound = @(Get-Safe 'Get-InboundConnector' | Where-Object { "$($_.ConnectorType)" -eq 'OnPremises' })
    $onPremIPs = @($onPremInbound | ForEach-Object { @($_.SenderIPAddresses) } | Where-Object { $_ } | ForEach-Object { "$_" })
    $onPremCerts = @($onPremInbound | ForEach-Object { "$($_.TlsSenderCertificateName)" } | Where-Object { $_ })

    $agg = @{}; $daily = @{}; $total = 0
    $useV2 = [bool](Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)
    if (-not $useV2 -and -not (Get-Command Get-MessageTrace -ErrorAction SilentlyContinue)) { throw 'Neither Get-MessageTraceV2 nor Get-MessageTrace is available' }
    $days = $MessageTraceDays
    if (-not $useV2 -and $days -gt 10) { Write-Log '  Get-MessageTraceV2 not available (update ExchangeOnlineManagement); message trace limited to 10 days' 'WARN'; $days = 10 }
    $start = $end.AddDays(-$days)
    if ($days -ge 90) { $start = $start.AddHours(1) }   # stay inside the 90-day limit
    Write-Log ('  Message trace via {0}, {1:yyyy-MM-dd} .. {2:yyyy-MM-dd}' -f $(if ($useV2) { 'Get-MessageTraceV2' } else { 'Get-MessageTrace' }), $start, $end)

    # Walk in 1-day windows to stay under result caps
    $cur = $start
    while ($cur -lt $end) {
        $next = $cur.AddDays(1); if ($next -gt $end) { $next = $end }
        $page = 1; $batch = @()
        do {
            try {
                if ($useV2) {
                    if ($page -eq 1) { $batch = @(Invoke-TraceQuery "Trace $($cur.ToString('yyyy-MM-dd')) page $page" { Get-MessageTraceV2 -StartDate $cur -EndDate $next -ResultSize 5000 -ErrorAction Stop }) }
                    else {
                        $last = $batch[-1]
                        $batch = @(Invoke-TraceQuery "Trace $($cur.ToString('yyyy-MM-dd')) page $page" { Get-MessageTraceV2 -StartDate $cur -EndDate $last.Received -ResultSize 5000 -StartingRecipientAddress $last.RecipientAddress -ErrorAction Stop })
                    }
                } else {
                    $batch = @(Invoke-TraceQuery "Trace $($cur.ToString('yyyy-MM-dd')) page $page" { Get-MessageTrace -StartDate $cur -EndDate $next -PageSize 5000 -Page $page -ErrorAction Stop })
                }
            } catch { Write-Log "  Message trace page $page failed for $cur : $($_.Exception.Message)" 'WARN'; $batch = @() }
            foreach ($m in $batch) {
                $total++
                $day = ([datetime]$m.Received).ToString('yyyy-MM-dd')
                $fromInternal = ($script:AcceptedDomainNames -contains "$($m.SenderAddress)".Split('@')[-1].ToLower())
                $toInternal = ($script:AcceptedDomainNames -contains "$($m.RecipientAddress)".Split('@')[-1].ToLower())
                $dir = $(if ($fromInternal -and $toInternal) { 'Internal' } elseif ($fromInternal) { 'Outbound' } elseif ($toInternal) { 'Inbound' } else { 'Other' })
                $fromIp = "$($m.FromIP)"; $toIp = "$($m.ToIP)"
                $viaOnPrem = $(if ($onPremIPs -contains $fromIp) { 'FromOnPremIP' } else { '' })
                $k = "$dir|$fromIp|$toIp|$($m.Status)"
                if (-not $agg.ContainsKey($k)) { $agg[$k] = @{ Direction = $dir; FromIP = $fromIp; ToIP = $toIp; Status = "$($m.Status)"; Count = 0; SenderDomains = @{}; RecipientDomains = @{}; First = $m.Received; Last = $m.Received; ViaOnPrem = $viaOnPrem } }
                $a = $agg[$k]; $a.Count++
                $sd = "$($m.SenderAddress)".Split('@')[-1].ToLower(); if ($sd -and $a.SenderDomains.Count -lt 20) { $a.SenderDomains[$sd] = 1 }
                $rd = "$($m.RecipientAddress)".Split('@')[-1].ToLower(); if ($rd -and $a.RecipientDomains.Count -lt 20) { $a.RecipientDomains[$rd] = 1 }
                if ($m.Received -lt $a.First) { $a.First = $m.Received }
                if ($m.Received -gt $a.Last) { $a.Last = $m.Received }
                $dk = "$day|$dir"; if (-not $daily.ContainsKey($dk)) { $daily[$dk] = 0 }; $daily[$dk]++
            }
            $page++
        } while ($batch.Count -ge 5000 -and $page -le 200)
        Write-Host ('  trace {0:yyyy-MM-dd} done ({1} messages so far)' -f $cur, $total)
        $cur = $next
    }
    $rows = @($agg.Values | ForEach-Object {
        [PSCustomObject]@{ Direction = $_.Direction; FromIP = $_.FromIP; ToIP = $_.ToIP; ViaOnPrem = $_.ViaOnPrem; Status = $_.Status; Count = $_.Count; FirstSeen = $_.First; LastSeen = $_.Last; SenderDomains = ($_.SenderDomains.Keys -join '; '); RecipientDomains = ($_.RecipientDomains.Keys -join '; ') }
    } | Sort-Object Count -Descending)
    Save-Csv $rows 'Evidence-MessageTrace-ByPath' | Out-Null
    Save-Csv @($daily.GetEnumerator() | ForEach-Object { $p = $_.Key.Split('|'); [PSCustomObject]@{ Day = $p[0]; Direction = $p[1]; Count = $_.Value } } | Sort-Object Day, Direction) 'Evidence-MessageTrace-Daily' | Out-Null
    Save-Csv @([PSCustomObject]@{ Window = ('{0:yyyy-MM-dd HH:mm} .. {1:yyyy-MM-dd HH:mm}' -f $start, $end); Cmdlet = $(if ($useV2) { 'Get-MessageTraceV2' } else { 'Get-MessageTrace' }); Days = $days; TotalMessages = $total; OnPremConnectorIPs = ($onPremIPs -join '; '); OnPremConnectorCerts = ($onPremCerts -join '; ') }) 'Evidence-MessageTrace-Summary' | Out-Null
    $rows.Count
}

Invoke-Section 'Evidence-HistoricalSearch-Existing' {
    # Read-only list of historical searches that already exist in the tenant. No new searches are submitted:
    # a submitted search makes Microsoft send a notification email, and this script only saves reports locally.
    Save-Csv @(Get-Safe 'Get-HistoricalSearch' | Select-Object JobId, ReportTitle, ReportType, Status, SubmitDate, StartDate, EndDate, Rows, FileUrl) 'Evidence-HistoricalSearch-Existing'
}

# ===========================================================================
# 5. EVIDENCE - UNIFIED AUDIT LOG (where recipient management happens)
# ===========================================================================
$auSkip = $(if ($SkipAuditLog) { 'SkipAuditLog specified' } else { $null })
Invoke-Section 'Evidence-UnifiedAuditLog' -SkipReason $auSkip -Script {
    if (-not (Get-Command Search-UnifiedAuditLog -ErrorAction SilentlyContinue)) { throw 'Search-UnifiedAuditLog not available to this account' }
    $end = Get-Date; $start = $end.AddDays(-$AuditDays)
    $all = [System.Collections.Generic.List[object]]::new()
    $sessionId = "DecomInv-$(Get-Date -Format yyyyMMddHHmmss)"
    $ops = 'New-Mailbox', 'Set-Mailbox', 'Remove-Mailbox', 'Enable-Mailbox', 'Disable-Mailbox', 'New-RemoteMailbox', 'Set-RemoteMailbox', 'New-DistributionGroup', 'Set-DistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'New-MailContact', 'Set-MailContact', 'Set-User', 'Set-CASMailbox', 'Add-MailboxPermission', 'Add-RecipientPermission', 'Set-MailboxAutoReplyConfiguration', 'New-InboundConnector', 'Set-InboundConnector', 'New-OutboundConnector', 'Set-OutboundConnector', 'New-TransportRule', 'Set-TransportRule', 'Set-AcceptedDomain', 'New-AcceptedDomain', 'Set-OrganizationConfig', 'Set-HybridConfiguration'
    $page = 0
    do {
        $page++
        $batch = @()
        try { $batch = @(Search-UnifiedAuditLog -StartDate $start -EndDate $end -RecordType ExchangeAdmin -Operations $ops -SessionId $sessionId -SessionCommand ReturnLargeSet -ResultSize 5000 -ErrorAction Stop) }
        catch { Write-Log "  Audit page $page failed: $($_.Exception.Message)" 'WARN' }
        foreach ($b in $batch) { $all.Add($b) }
        Write-Host "  audit page $page : $($batch.Count) (total $($all.Count))"
    } while ($batch.Count -eq 5000 -and $page -lt 40)
    $rows = @($all | Group-Object UserIds, Operations | ForEach-Object {
        $sorted = @($_.Group | Sort-Object CreationDate)
        $sample = ''
        try { $sample = ((ConvertFrom-Json $sorted[-1].AuditData).ObjectId) } catch { }
        [PSCustomObject]@{ User = $_.Group[0].UserIds; Operation = $_.Group[0].Operations; Count = $_.Count; First = $sorted[0].CreationDate; Last = $sorted[-1].CreationDate; LastObject = $sample }
    } | Sort-Object Count -Descending)
    Save-Csv $rows 'Evidence-UnifiedAuditLog-ByUserOperation' | Out-Null
    Save-Csv @([PSCustomObject]@{ WindowStart = $start; WindowEnd = $end; Entries = $all.Count; Note = 'Changes made in the on-prem Exchange Management Shell do not appear here; compare with the on-prem admin audit log' }) 'Evidence-UnifiedAuditLog-Depth' | Out-Null
    $rows.Count
}

# ===========================================================================
# 6. DNS (public view of every accepted domain, for comparison with the on-prem run)
# ===========================================================================
function Resolve-Rec {
    param($View, $Server, $Name, $Type)
    try {
        $a = @{ Name = $Name; Type = $Type; DnsOnly = $true; ErrorAction = 'Stop' }
        if ($Server) { $a.Server = $Server }
        $out = foreach ($r in (Resolve-DnsName @a)) {
            if ("$($r.Type)" -ne $Type) { continue }
            $val = switch ("$($r.Type)") { 'MX' { "$($r.Preference) $($r.NameExchange)" } 'TXT' { (@($r.Strings) -join '') } 'CNAME' { $r.NameHost } 'SRV' { "$($r.Priority) $($r.Weight) $($r.Port) $($r.NameTarget)" } 'PTR' { $r.NameHost } 'A' { $r.IPAddress } default { "$r" } }
            [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = $val; TTL = $r.TTL; Status = 'OK' }
        }
        if (-not $out) { [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = ''; TTL = ''; Status = 'NoRecord' } } else { $out }
    } catch { [PSCustomObject]@{ View = $View; Name = $Name; Type = $Type; Value = ''; TTL = ''; Status = $_.Exception.Message } }
}

Invoke-Section 'DNS-Records' {
    if (-not (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue)) { throw 'Resolve-DnsName not available on this system (Windows only)' }
    $pub = $null
    foreach ($ps in @(@($PublicDnsServer, '1.1.1.1') | Select-Object -Unique)) { try { $null = Resolve-DnsName -Name 'microsoft.com' -Type A -Server $ps -DnsOnly -ErrorAction Stop; $pub = $ps; break } catch { } }
    if (-not $pub) { Write-Log '  No public resolver reachable; only the internal DNS view is collected.' 'WARN' }
    $views = @(, @('Internal', $null)); if ($pub) { $views += , @("Public($pub)", $pub) }
    $rows = @()
    $dkim = @{}
    Get-Safe 'Get-DkimSigningConfig' | ForEach-Object { $dkim["$($_.Domain)".ToLower()] = $_ }
    $domains = @($script:AcceptedDomainNames | Where-Object { $_ -notmatch '\.onmicrosoft\.com$' })
    foreach ($d in $domains) {
        foreach ($v in $views) {
            $rows += Resolve-Rec $v[0] $v[1] $d 'MX'
            $rows += Resolve-Rec $v[0] $v[1] $d 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "_dmarc.$d" 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "selector1._domainkey.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "selector2._domainkey.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "autodiscover.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "autodiscover.$d" 'A'
            $rows += Resolve-Rec $v[0] $v[1] "_mta-sts.$d" 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "_smtp._tls.$d" 'TXT'
            $rows += Resolve-Rec $v[0] $v[1] "enterpriseregistration.$d" 'CNAME'
            $rows += Resolve-Rec $v[0] $v[1] "enterpriseenrollment.$d" 'CNAME'
            foreach ($h in 'mail', 'smtp', 'webmail', 'owa') { $rows += Resolve-Rec $v[0] $v[1] "$h.$d" 'A' }
        }
    }
    Save-Csv @($rows) 'DNS-Records' | Out-Null
    $viewPrefix = $(if ($pub) { 'Public*' } else { 'Internal' })
    $pr = @($rows | Where-Object { $_.View -like $viewPrefix })
    $assess = foreach ($d in $domains) {
        $spf = "$(($pr | Where-Object { $_.Name -eq $d -and $_.Type -eq 'TXT' -and $_.Value -match '^v=spf1' } | Select-Object -First 1).Value)"
        $mx = (@($pr | Where-Object { $_.Name -eq $d -and $_.Type -eq 'MX' -and $_.Value } | ForEach-Object { $_.Value }) -join '; ')
        $s1 = "$(($pr | Where-Object { $_.Name -eq "selector1._domainkey.$d" -and $_.Value } | Select-Object -First 1).Value)"
        $dk = $dkim[$d]
        [PSCustomObject]@{
            Domain = $d; View = $viewPrefix.TrimEnd('*'); MX = $mx; MXPointsToEOP = ($mx -match 'mail\.protection\.outlook\.com'); SPF = $spf; SPFIncludesEOP = ($spf -match 'spf\.protection\.outlook\.com'); SPFHasIp4OrA = ($spf -match 'ip4:|\sa[\s:]|\smx')
            DKIM_PublishedSelector1 = $s1; DKIM_ExpectedSelector1 = $(if ($dk) { "$($dk.Selector1CNAME)" } else { '' }); DKIM_EnabledInEXO = $(if ($dk) { $dk.Enabled } else { 'NoConfig' })
            DKIM_Match = $(if ($dk -and $s1) { ($s1.TrimEnd('.') -eq "$($dk.Selector1CNAME)".TrimEnd('.')) } else { '' })
            DMARC = "$(($pr | Where-Object { $_.Name -eq "_dmarc.$d" -and $_.Value } | Select-Object -First 1).Value)"
            AutodiscoverPublic = (@($pr | Where-Object { $_.Name -eq "autodiscover.$d" -and $_.Value } | ForEach-Object { $_.Value }) -join '; ')
        }
    }
    Save-Csv @($assess) 'DNS-Assessment' | Out-Null
    @($rows).Count
}

# ===========================================================================
# 7. COMPLIANCE (Purview retention / holds) - runs last because it opens a second session
# ===========================================================================
$ccSkip = $(if ($SkipCompliance) { 'SkipCompliance specified' } else { $null })
Invoke-Section 'Compliance-Retention' -SkipReason $ccSkip -Script {
    $cc = Get-Command Connect-IPPSSession -ErrorAction Stop
    $cargs = @{ ErrorAction = 'Stop' }
    if ($cc.Parameters.ContainsKey('ShowBanner')) { $cargs.ShowBanner = $false }
    $upn = $(if ($UserPrincipalName) { $UserPrincipalName } else { "$($ci.UserPrincipalName)" })
    if ($upn -and $cc.Parameters.ContainsKey('UserPrincipalName')) { $cargs.UserPrincipalName = $upn }
    Connect-IPPSSession @cargs
    $n = 0
    $n += Save-Csv @(Get-Safe 'Get-RetentionCompliancePolicy' @{ DistributionDetail = $true } | Select-Object Name, Enabled, Mode, Workload, ExchangeLocation, ExchangeLocationException, DistributionStatus, WhenChanged) 'Compliance-RetentionPolicies'
    $n += Save-Csv @(Get-Safe 'Get-RetentionComplianceRule' | Select-Object Name, Policy, RetentionDuration, RetentionComplianceAction, ExpirationDateOption) 'Compliance-RetentionRules'
    $n += Save-Csv @(Get-Safe 'Get-ComplianceCase' | Select-Object Name, CaseType, Status, CreatedDateTime) 'Compliance-Cases'
    $n += Save-Csv @(Get-Safe 'Get-CaseHoldPolicy' | Select-Object Name, Enabled, ExchangeLocation, WhenChanged) 'Compliance-CaseHoldPolicies'
    $n
}

# ===========================================================================
# Finish
# ===========================================================================
$script:Manifest | Export-Csv -Path (Join-Path $script:Out 'Manifest.csv') -NoTypeInformation -Encoding UTF8
$meta = [PSCustomObject]@{
    ScriptVersion = $script:ScriptVersion; Script = 'EXO'; Tenant = "$($ci.TenantID)"; RunBy = "$($ci.UserPrincipalName)"; RunOn = $env:COMPUTERNAME
    Started = $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'); Finished = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    ExoModuleVersion = "$($exoMod.Version)"; ReusedExoSession = (-not $script:WeConnectedExo); GraphConnected = $script:GraphOk; PSVersion = $PSVersionTable.PSVersion.ToString()
    Parameters = (($PSBoundParameters.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
    Sections = $script:Manifest.Count
    Collected = @($script:Manifest | Where-Object { $_.Status -eq 'Collected' }).Count
    Failed = @($script:Manifest | Where-Object { $_.Status -eq 'Failed' }).Count
    Skipped = @($script:Manifest | Where-Object { $_.Status -eq 'Skipped' }).Count
}
Save-Json $meta 'RunInfo'
Write-Log ('Finished. Sections: {0} collected, {1} failed, {2} skipped.' -f $meta.Collected, $meta.Failed, $meta.Skipped)
if ($script:WeConnectedExo) { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null } catch { } }
if ($script:WeConnectedGraph) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { } }
Stop-RunTranscript

if (-not $NoZip) {
    $zip = "$OutputRoot.zip"
    try { Compress-Archive -Path (Join-Path $OutputRoot '*') -DestinationPath $zip -Force -ErrorAction Stop; Write-Log "ZIP written: $zip"; Write-Host "`nReturn this file for analysis:`n  $zip`n" -ForegroundColor Green }
    catch { Write-Log "Zip failed: $($_.Exception.Message). Return the folder $OutputRoot instead." 'WARN' }
} else { Write-Host "`nOutput folder: $OutputRoot`n" -ForegroundColor Green }
