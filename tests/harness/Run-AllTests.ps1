<#
.SYNOPSIS
    Runs the three inventory scripts end to end against stubbed Exchange / Graph / ADSync / Windows
    commands and a generated fake Exchange server file system, then the helper unit tests.

.DESCRIPTION
    Needs PowerShell 7 in FullLanguage mode (it builds stubs with [scriptblock]::Create and .NET types).
    Written for Linux/macOS pwsh, where none of the real Exchange or Windows cmdlets exist, so every
    one of them is replaced by a stub. On Windows the real Get-CimInstance, Get-Service, [ADSI], ...
    would be used instead and results would differ.

    Nothing is contacted: no Exchange, no Microsoft 365, no DNS, no endpoints.office.com.
    All data is fictitious (contoso.com, RFC 5737 addresses).

    Exit code = number of failed checks.

.PARAMETER WorkDir
    Where fake modules, the fake server and the run outputs go. Default: a new temp folder.
.PARAMETER Only
    Run only scenarios whose name matches this wildcard (e.g. 'exo-*').

.EXAMPLE
    pwsh -NoProfile -File tests/harness/Run-AllTests.ps1
#>
[CmdletBinding()]
param(
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) ("decom-tests-{0:yyyyMMdd_HHmmss}" -f (Get-Date))),
    [string]$Only = '*'
)
$ErrorActionPreference = 'Stop'
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { throw "FullLanguage required (current: $($ExecutionContext.SessionState.LanguageMode))" }
$here = $PSScriptRoot
$repo = Split-Path (Split-Path $here -Parent) -Parent
$sep = [IO.Path]::PathSeparator
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null
$out = Join-Path $WorkDir 'out'; New-Item -ItemType Directory -Path $out -Force | Out-Null
Write-Host "Work folder: $WorkDir" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Fake modules (Get-Module -ListAvailable / Import-Module only need a manifest)
# ---------------------------------------------------------------------------
function New-FakeModule([string]$Root, [string]$Name, [string]$Version) {
    $d = Join-Path $Root "$Name/$Version"; New-Item -ItemType Directory -Path $d -Force | Out-Null
    Set-Content -Path (Join-Path $d "$Name.psm1") -Value '# fake'
    Set-Content -Path (Join-Path $d "$Name.psd1") -Value "@{ ModuleVersion = '$Version'; RootModule = '$Name.psm1'; GUID = '$([guid]::NewGuid())'; FunctionsToExport = @() }"
}
$mods = Join-Path $WorkDir 'fakemods'; $modsOld = Join-Path $WorkDir 'fakemods-old'
New-FakeModule $mods 'ExchangeOnlineManagement' '3.7.1'
New-FakeModule $mods 'Microsoft.Graph.Authentication' '2.25.0'
New-FakeModule $mods 'ADSync' '1.0.0'
New-FakeModule $modsOld 'ExchangeOnlineManagement' '2.0.5'
$basePsModulePath = $env:PSModulePath

# ---------------------------------------------------------------------------
# Fake Exchange server file system (logs, applicationHost.config)
# ---------------------------------------------------------------------------
$fe = Join-Path $WorkDir 'fakeenv'
$x = Join-Path $fe 'ExchangeServer/V15'
function Write-Fake([string]$Rel, [string]$Text, [double]$AgeDays = 0) {
    $p = Join-Path $fe $Rel
    New-Item -ItemType Directory -Path (Split-Path $p -Parent) -Force | Out-Null
    [IO.File]::WriteAllText($p, ($Text -replace "`r?`n", "`r`n"))
    (Get-Item $p).LastWriteTime = (Get-Date).AddDays(-$AgeDays)
}
$xr = 'ExchangeServer/V15'
Write-Fake "$xr/Bin/ExSetup.exe" 'MZ'
foreach ($d in 50, 30, 10, 1) { Write-Fake ("$xr/TransportRoles/Logs/MessageTracking/MSGTRK{0:yyyyMMdd}-1.LOG" -f (Get-Date).AddDays(-$d)) '#Fields: x' $d }
Write-Fake "$xr/Logging/Update-HybridConfiguration/HybridConfiguration_10_1_2026.log" 'Hybrid Configuration Wizard - HCW Version 17.0.5494.0'
Write-Fake "$xr/Logging/HttpProxy/Owa/HttpProxy_2026102300-1.LOG" 'x'

$c = 'EX01\Default Frontend EX01'; $r = 'EX01\Relay Apps'
$smtp = @"
#Software: Microsoft Exchange Server
#Version: 15.0.0.0
#Log-type: SMTP Receive Protocol Log
#Date: 2026-10-23T00:00:01.000Z
#Fields: date-time,connector-id,session-id,sequence-number,local-endpoint,remote-endpoint,event,data,context
2026-10-23T00:00:01.123Z,$c,08DCF1A2B3C4D5E6,0,10.0.0.10:25,10.0.0.50:51234,+,,
2026-10-23T00:00:01.124Z,$c,08DCF1A2B3C4D5E6,1,10.0.0.10:25,10.0.0.50:51234,*,SMTPSubmit SMTPAcceptAnyRecipient SMTPAcceptAnySender,Set Session Permissions
2026-10-23T00:00:01.125Z,$c,08DCF1A2B3C4D5E6,2,10.0.0.10:25,10.0.0.50:51234,>,"220 EX01.contoso.com Microsoft ESMTP MAIL Service ready at Thu, 23 Oct 2026 00:00:01 +0000",
2026-10-23T00:00:01.126Z,$c,08DCF1A2B3C4D5E6,3,10.0.0.10:25,10.0.0.50:51234,<,EHLO app01.contoso.com,
2026-10-23T00:00:01.127Z,$c,08DCF1A2B3C4D5E6,4,10.0.0.10:25,10.0.0.50:51234,<,STARTTLS,
2026-10-23T00:00:01.128Z,$c,08DCF1A2B3C4D5E6,5,10.0.0.10:25,10.0.0.50:51234,*,,"TLS protocol SP_PROT_TLS1_2_SERVER negotiated succeeded using bulk encryption algorithm CALG_AES_256 with strength 256 bits, MAC hash algorithm CALG_SHA_384 with strength 0 bits and key exchange algorithm CALG_ECDH_EPHEM with strength 384 bits"
2026-10-23T00:00:01.129Z,$c,08DCF1A2B3C4D5E6,6,10.0.0.10:25,10.0.0.50:51234,<,AUTH LOGIN,
2026-10-23T00:00:01.130Z,$c,08DCF1A2B3C4D5E6,7,10.0.0.10:25,10.0.0.50:51234,*,CONTOSO\svc-scanner,authenticated
2026-10-23T00:00:01.131Z,$c,08DCF1A2B3C4D5E6,8,10.0.0.10:25,10.0.0.50:51234,<,MAIL FROM:<scanner@contoso.com> SIZE=1234,
2026-10-23T00:00:01.132Z,$c,08DCF1A2B3C4D5E6,9,10.0.0.10:25,10.0.0.50:51234,<,RCPT TO:<user1@contoso.com>,
2026-10-23T00:00:01.133Z,$c,08DCF1A2B3C4D5E6,10,10.0.0.10:25,10.0.0.50:51234,-,,Local
2026-10-23T00:05:00.000Z,$r,08DCF1A2B3C4D5E7,0,10.0.0.10:25,192.168.1.20:40000,+,,
2026-10-23T00:05:00.001Z,$r,08DCF1A2B3C4D5E7,1,10.0.0.10:25,192.168.1.20:40000,<,HELO printer-3f,
2026-10-23T00:05:00.002Z,$r,08DCF1A2B3C4D5E7,2,10.0.0.10:25,192.168.1.20:40000,<,MAIL FROM:<printer@contoso.com>,
2026-10-23T00:05:00.003Z,$r,08DCF1A2B3C4D5E7,3,10.0.0.10:25,192.168.1.20:40000,<,MAIL FROM:<printer@contoso.com>,
2026-10-23T00:06:00.000Z,$c,08DCF1A2B3C4D5E8,0,[fe80::10]:25,[fe80::99]:50001,+,,
2026-10-23T00:06:00.001Z,$c,08DCF1A2B3C4D5E8,1,[fe80::10]:25,[fe80::99]:50001,<,EHLO v6host,
2026-10-23T00:07:00.000Z,$c,08DCF1A2B3C4D5E9,0,10.0.0.10:25,40.92.5.5:50001,+,,
2026-10-23T00:07:00.001Z,$c,08DCF1A2B3C4D5E9,1,10.0.0.10:25,40.92.5.5:50001,<,EHLO NAM12-BN8-obe.outbound.protection.outlook.com,
2026-10-23T00:07:00.002Z,$c,08DCF1A2B3C4D5E9,2,10.0.0.10:25,40.92.5.5:50001,<,X-ANONYMOUSTLS,
2026-10-23T00:07:00.003Z,$c,08DCF1A2B3C4D5E9,3,10.0.0.10:25,40.92.5.5:50001,<,MAIL FROM:<user@contoso.com> SIZE=10,
"@
Write-Fake "$xr/TransportRoles/Logs/FrontEnd/ProtocolLog/SmtpReceive/RECV2026102300-1.LOG" $smtp 20
Write-Fake "$xr/TransportRoles/Logs/Hub/ProtocolLog/SmtpReceive/RECV2026102300-1.LOG" $smtp 0

Write-Fake "$xr/Logging/Pop3/POP3BE20261023-1.log" @'
#Software: Microsoft Exchange Server
#Log-type: POP3 Protocol Log
#Fields: dateTime,sessionId,seqNumber,sIp,cIp,user,duration,rqsize,rpsize,command,parameters,context
2026-10-23T00:00:00.000Z,1,0,10.0.0.10:995,10.0.0.77:50000,CONTOSO\bob,0,0,0,USER,,R=ok
2026-10-23T00:00:01.000Z,1,1,10.0.0.10:995,10.0.0.77:50000,CONTOSO\bob,0,0,0,RETR,1,R=ok
2026-10-23T00:00:02.000Z,2,0,10.0.0.10:995,10.0.0.78:50001,,0,0,0,CAPA,,
'@
# no #Fields header: the default column positions are used
Write-Fake "$xr/Logging/Imap4/IMAP4BE20261023-1.log" '2026-10-23T00:00:00.000Z,1,0,10.0.0.10:993,10.0.0.88:50000,CONTOSO\carol,0,0,0,LOGIN,,R=ok'

$hpHdr = '#Fields: DateTime,RequestId,MajorVersion,MinorVersion,BuildVersion,RevisionVersion,ClientRequestId,Protocol,UrlHost,UrlStem,ProtocolAction,AuthenticationType,IsAuthenticated,AuthenticatedUser,Organization,AnchorMailbox,UserAgent,ServerHostName,HttpStatus,BackEndStatus,ClientIpAddress,UrlQuery'
Write-Fake "$xr/Logging/HttpProxy/Mapi/HttpProxy_2026102301-1.LOG" @"
#Software: Microsoft Exchange Server
#Log-type: HttpProxy Logs
$hpHdr
2026-10-23T01:00:00.000Z,r1,15,2,1544,4,,Mapi,mail.contoso.com,/mapi/emsmdb/,,Negotiate,true,CONTOSO\alice,,MailboxGuid~e0000001-0000-0000-0000-000000000000@contoso.com,"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)",EX01.contoso.com,200,200,10.0.0.71,?mailboxId=e0000001-0000-0000-0000-000000000000@contoso.com
2026-10-23T01:05:00.000Z,r2,15,2,1544,4,,Mapi,mail.contoso.com,/mapi/emsmdb/,,Negotiate,true,CONTOSO\alice,,,"Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)",EX01.contoso.com,200,200,10.0.0.71,?mailboxId=e0000004-0000-0000-0000-000000000000@contoso.com
2026-10-23T01:06:00.000Z,r3,15,2,1544,4,,Mapi,mail.contoso.com,/mapi/emsmdb/,,Negotiate,true,CONTOSO\HealthMailbox1a2b,,,AMProbe/Local,EX01.contoso.com,200,200,10.0.0.10,
"@
Write-Fake "$xr/Logging/HttpProxy/Ews/HttpProxy_2026102302-1.LOG" @"
$hpHdr
2026-10-23T02:00:00.000Z,r4,15,2,1544,4,,Ews,mail.contoso.com,/EWS/Exchange.asmx,,Basic,true,CONTOSO\svc-crm,,Smtp~shared@contoso.com,ExchangeServicesClient/15.00.0913.015,EX01.contoso.com,200,200,10.0.0.60,
2026-10-23T02:01:00.000Z,r5,15,2,1544,4,,Ews,mail.contoso.com,/EWS/Exchange.asmx,,Basic,true,CONTOSO\svc-crm,,Smtp~cloud1@contoso.com,ExchangeServicesClient/15.00.0913.015,EX01.contoso.com,302,,10.0.0.60,
"@
Write-Fake "$xr/Logging/HttpProxy/Autodiscover/HttpProxy_2026102303-1.LOG" @"
$hpHdr
2026-10-23T03:00:00.000Z,r6,15,2,1544,4,,Autodiscover,autodiscover.contoso.com,/autodiscover/autodiscover.xml,,Basic,true,user3@contoso.com,,Smtp~user3@contoso.com,"Microsoft Office/16.0, quoted, commas",EX01.contoso.com,200,200,"[2001:db8::5]:443",
"@

$iis = @'
#Software: Microsoft Internet Information Services 10.0
#Version: 1.0
#Date: 2026-10-23 00:00:00
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken
2026-10-23 00:00:01 10.0.0.10 POST /EWS/Exchange.asmx - 443 CONTOSO\svc-crm 10.0.0.60 ExchangeServicesClient/15.00.0913.015 - 200 0 0 15
2026-10-23 00:00:02 10.0.0.10 POST /EWS/Exchange.asmx - 443 CONTOSO\svc-crm 10.0.0.60 ExchangeServicesClient/15.00.0913.015 - 200 0 0 15
2026-10-22 00:00:02 10.0.0.10 GET /owa/ - 443 - 10.0.0.70 Mozilla/5.0+(Windows+NT+10.0) - 302 0 0 1
2026-10-23 00:00:03 10.0.0.10 POST /Microsoft-Server-ActiveSync/default.eas Cmd=Sync 443 CONTOSO\bob 203.0.113.99 Apple-iPhone14C2/2101.123 - 200 0 0 100
2026-10-23 00:00:04 127.0.0.1 GET /owa/healthcheck.htm - 443 - 127.0.0.1 AMProbe/Local/ClientAccess - 200 0 0 1
2026-10-23 00:00:05 10.0.0.10 POST /EWS/Exchange.asmx - 443 - 52.100.1.2 Microsoft+Office/16.0 - 401 0 0 1
2026-10-23 00:00:06 10.0.0.10 POST /mapi/emsmdb/ - 443 CONTOSO\HealthMailbox123 10.0.0.10 MSRPC - 200 0 0 1
2026-10-23 00:00:07 10.0.0.10 POST /rpc/rpcproxy.dll - 443 CONTOSO\alice 10.0.0.71 MSRPC - 500 0 0 1
'@
Write-Fake 'inetpub/logs/LogFiles/W3SVC1/u_ex261023.log' $iis 1
Write-Fake 'inetpub/logs/LogFiles/W3SVC1/u_ex260101.log' $iis 200   # older than -IisDays: must be ignored
Write-Fake 'inetpub/logs/LogFiles/W3SVC2/u_ex261023.log' 'junk without a #Fields header'
Write-Fake 'Windows/System32/inetsrv/config/applicationHost.config' @'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.applicationHost>
    <applicationPools>
      <add name="MSExchangeOWAAppPool"><processModel identityType="LocalSystem" /></add>
      <add name="CustomPool"><processModel identityType="SpecificUser" userName="CONTOSO\svc-web" /></add>
    </applicationPools>
    <sites>
      <site name="Default Web Site" id="1">
        <application path="/" applicationPool="DefaultAppPool"><virtualDirectory path="/" physicalPath="%SystemDrive%\inetpub\wwwroot" /></application>
        <application path="/owa" applicationPool="MSExchangeOWAAppPool"><virtualDirectory path="/" physicalPath="C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa" /></application>
        <bindings><binding protocol="https" bindingInformation="*:443:" /><binding protocol="http" bindingInformation="*:80:" /></bindings>
      </site>
      <site name="Exchange Back End" id="2">
        <bindings><binding protocol="https" bindingInformation="*:444:" /></bindings>
      </site>
      <siteDefaults><logFile directory="%FAKEENV%\inetpub\logs\LogFiles" /></siteDefaults>
    </sites>
  </system.applicationHost>
  <system.webServer>
    <globalModules>
      <add name="UriCacheModule" image="%windir%\System32\inetsrv\cachuri.dll" />
      <add name="ThirdPartyFilter" image="C:\Program Files\Acme\acmefilter.dll" />
    </globalModules>
  </system.webServer>
</configuration>
'@

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------
$exoFix = @("$here/Fixtures-EXO.ps1")
$entraFix = @("$here/Fixtures-Entra.ps1")
$onpremFix = @("$here/Fixtures-EXO.ps1", "$here/Fixtures-Entra.ps1", "$here/Fixtures-OnPrem.ps1")
$onpremEnv = @{ COMPUTERNAME = 'EX01'; USERDOMAIN = 'CONTOSO'; USERNAME = 'admin'; FAKEENV = $fe; ExchangeInstallPath = $x; windir = (Join-Path $fe 'Windows') }
function Merge-Env($a, $b) { $h = @{} + $a; foreach ($k in $b.Keys) { $h[$k] = $b[$k] }; $h }
$winOnly = @{ 'Topology-ActiveDirectory' = '[ADSI]/System.DirectoryServices do not exist off Windows' }

# Expect: Failed = sections allowed to fail (name -> reason); Known = failures that are real issues (reported, not counted);
#         Skipped = sections that must be skipped (SkippedOptional = may also be skipped, e.g. only in newer versions); Log = regexes that must appear in RunLog.txt;
#         Files = output file -> regex its content must match; NoManifest = script must exit before writing output.
$scenarios = @(
    @{ Name = 'exo-full'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $mods; Env = @{ COMPUTERNAME = 'TESTPC' }; Force = 'Start-Sleep'
        Args = @{ UserPrincipalName = 'admin@contoso.com' }
        Log = @('throttled; waiting 60s', 'Connected to Microsoft Graph', 'Get-OutboundConnector failed'); Zip = $true
        Files = @{ 'Evidence-MessageTrace-Summary.csv' = '"Get-MessageTraceV2","90","5360"'; 'Org-UserSyncCounts.csv' = '"50","42","8"'; 'DNS-Assessment.csv' = 'contoso\.com.*"True"'; 'MailFlow-Connectors-Summary.csv' = '"True","Outbound to OnPrem"'; 'Recipients-InactiveMailboxes.csv' = 'gone@contoso.com' } }
    @{ Name = 'exo-legacy-trace'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $mods; Env = @{ COMPUTERNAME = 'TESTPC'; FIX_PRECONNECTED = '1'; FIX_IPPS_FAIL = '1' }; Force = 'Start-Sleep'; NoStub = 'Get-MessageTraceV2'
        Args = @{ UserPrincipalName = 'other@contoso.com'; MessageTraceDays = 30; SkipGraph = $true; NoZip = $true }
        Failed = @{ 'Compliance-Retention' = 'fixture: account has no Purview role' }; Skipped = @('Org-DirectorySync', 'Org-Licensing')
        Log = @('Reusing the existing Exchange Online session', 'Existing session is for admin@contoso.com, not other@contoso.com', 'message trace limited to 10 days')
        Files = @{ 'Evidence-MessageTrace-Summary.csv' = '"Get-MessageTrace","10","50020"' } }
    @{ Name = 'exo-no-module'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $null; NoManifest = $true; Log = @('ExchangeOnlineManagement module not found') }
    @{ Name = 'exo-old-module'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $modsOld; NoManifest = $true; Log = @('2\.0\.5 found; version 3\.x or later is required') }
    @{ Name = 'exo-connect-fail'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $mods; Env = @{ FIX_CONNECT_FAIL = '1' }; NoManifest = $true; Log = @('Connect-ExchangeOnline failed: AADSTS50126') }
    @{ Name = 'exo-no-dns-no-audit'; Script = 'Get-EXODecomInventory.ps1'; Fix = $exoFix; Mods = $mods; Force = 'Start-Sleep'; NoStub = 'Resolve-DnsName,Search-UnifiedAuditLog'
        Args = @{ SkipMessageTrace = $true; SkipCompliance = $true }
        Failed = @{ 'DNS-Records' = 'Resolve-DnsName removed'; 'Evidence-UnifiedAuditLog' = 'Search-UnifiedAuditLog removed' }; Skipped = @('Evidence-MessageTrace', 'Compliance-Retention') }

    @{ Name = 'entra-full'; Script = 'Get-EntraConnectDecomInventory.ps1'; Fix = $entraFix; Mods = $mods; Env = @{ COMPUTERNAME = 'SYNC01' }; Force = 'Get-ItemProperty'; Zip = $true
        Files = @{ 'EntraConnect-Connectors.csv' = '"fabrikam.local","FAB\\svc-sync"'; 'EntraConnect-SyncRules-Summary.csv' = '"3","2","1","True","2"'; 'EntraConnect-OptionalFeatures.csv' = 'CompanyFeature:PasswordHashSync'; 'EntraConnect-RecentErrors.csv' = '"6100","2"' } }
    @{ Name = 'entra-no-adsync'; Script = 'Get-EntraConnectDecomInventory.ps1'; Fix = $entraFix; Mods = $null; Env = @{ COMPUTERNAME = 'SYNC01' }; Force = 'Get-ItemProperty'
        Skipped = @('EntraConnect-GlobalSettings', 'EntraConnect-Scheduler', 'EntraConnect-Connectors', 'EntraConnect-SyncRules', 'EntraConnect-OptionalFeatures', 'EntraConnect-LastRuns'); Log = @('ADSync module not found') }

    @{ Name = 'onprem-full'; Script = 'Get-ExchOnPremDecomInventory.ps1'; Fix = $onpremFix; Env = $onpremEnv; Force = 'Get-ItemProperty,Start-Sleep,Invoke-RestMethod'; Zip = $true
        Failed = $winOnly
        Known = @{ 'Evidence-HttpProxyLogs' = 'v1.2: ConvertTo-UncPath returns $null for a remote server and Get-ChildItem -LiteralPath $null is terminating (see TEST-NOTES.md)' }
        Log = @('Loaded 4 Microsoft 365 Exchange IPv4 ranges', 'IncludePreExchange2013')
        Files = @{
            'Evidence-SmtpReceiveProtocolLogs-BySource.csv' = 'LOGIN","CONTOSO\\svc-scanner'
            'Evidence-IisLogs-ByClient.csv' = '"ews","10\.0\.0\.60","False","CONTOSO\\svc-crm","ExchangeServicesClient/15\.00\.0913\.015","2"'
            'MailFlow-PopImap-ClientIPs.csv' = '"IMAP4","10\.0\.0\.88","CONTOSO\\carol"'
            'Evidence-MessageTracking-LocalDeliveries.csv' = '"user2@contoso.com"'
            'Recipients-RemoteMailboxes-Summary.csv' = '"2","1","1","1","1"'
            'Prerequisites-Summary.csv' = 'Not readable - check the admin share' } }
    @{ Name = 'onprem-switches'; Script = 'Get-ExchOnPremDecomInventory.ps1'; Fix = $onpremFix; Env = (Merge-Env $onpremEnv @{ FIX_NO_INTERNET = '1' }); Force = 'Get-ItemProperty,Start-Sleep,Invoke-RestMethod'
        Args = @{ SkipRemoteServers = $true; TrackingDays = 7; IncludeSubjects = $true; IncludeBackEndIisLogs = $true; NoZip = $true }
        Failed = $winOnly; Log = @('Could not download Microsoft 365 IP ranges', 'across 1 server')
        Files = @{ 'Evidence-MessageTracking-ReceiveBySource.csv' = 'Scanned document from printer on floor 3 - very long subject"'; 'Evidence-IisLogs-Depth.csv' = 'Exchange Back End'; 'Evidence-HttpProxyLogs-Depth.csv' = 'Mapi' } }
    @{ Name = 'onprem-no-exchange'; Script = 'Get-ExchOnPremDecomInventory.ps1'; Fix = $onpremFix; Env = $onpremEnv; Force = 'Get-ItemProperty,Start-Sleep,Invoke-RestMethod'; NoStub = 'Get-ExchangeServer,Add-PSSnapin'
        NoManifest = $true; Log = @('Could not load the Exchange cmdlets') }
    @{ Name = 'onprem-skips-no-install-path'; Script = 'Get-ExchOnPremDecomInventory.ps1'; Fix = $onpremFix; Env = (Merge-Env $onpremEnv @{ ExchangeInstallPath = ''; windir = '' }); Force = 'Get-ItemProperty,Start-Sleep,Invoke-RestMethod'
        Args = @{ SkipTrackingLogs = $true; SkipProtocolLogs = $true; SkipIisLogs = $true; NoZip = $true }
        Failed = ($winOnly + @{ 'Local-IIS' = 'windir unset (always set on Windows)'; 'Evidence-HttpProxyLogs' = 'install path unknown (expected)' })
        Skipped = @('Evidence-MessageTracking', 'Evidence-SmtpReceiveProtocolLogs', 'Evidence-IisLogs'); SkippedOptional = @('Evidence-ReceiveConnectorUsage')   # v1.2+
        Log = @('Exchange install path not found') }
)

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------
$results = [System.Collections.Generic.List[object]]::new()
function Add-Result($Scenario, $Check, $Ok, $Detail = '', $Status = $null) {
    $results.Add([PSCustomObject]@{ Scenario = $Scenario; Check = $Check; Status = $(if ($Status) { $Status } elseif ($Ok) { 'PASS' } else { 'FAIL' }); Detail = $Detail })
}

foreach ($s in $scenarios | Where-Object { $_.Name -like $Only }) {
    $target = Join-Path $repo $s.Script
    if (-not (Test-Path $target)) { Add-Result $s.Name 'script present' $false $target; continue }
    $dest = Join-Path $out $s.Name
    $a = @{ OutputRoot = $dest } + $(if ($s.Args) { $s.Args } else { @{} })
    $saved = @{}
    $envSet = @{ PSModulePath = $(if ($s.Mods) { "$($s.Mods)$sep$basePsModulePath" } else { $basePsModulePath }) } + $(if ($s.Env) { $s.Env } else { @{} })
    foreach ($k in $envSet.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, $(if ($envSet[$k] -eq '') { $null } else { $envSet[$k] })) }
    Write-Host "--- $($s.Name)" -ForegroundColor Cyan
    $log = Join-Path $out "$($s.Name).console.txt"
    $argv = @('-NoProfile', '-File', (Join-Path $here 'Harness.ps1'), '-Target', $target, '-Fixtures', ($s.Fix -join ','), '-ScriptArgsJson', ($a | ConvertTo-Json -Compress))
    if ($s.Force) { $argv += @('-ForceStub', $s.Force) }
    if ($s.NoStub) { $argv += @('-NoStub', $s.NoStub) }
    & (Join-Path $PSHOME 'pwsh') @argv *> $log
    $code = $LASTEXITCODE
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }

    $console = Get-Content -Raw $log
    Add-Result $s.Name 'exit code 0' ($code -eq 0) "exit=$code"
    Add-Result $s.Name 'no unhandled exception' ($console -notmatch '(?m)^\s*(At line:|.*Exception:|.*ParentContainsErrorRecordException)') ''
    $runLog = Join-Path $dest 'RunLog.txt'
    $runText = $(if (Test-Path $runLog) { Get-Content -Raw $runLog } else { '' })
    foreach ($re in @($s.Log)) { if ($re) { Add-Result $s.Name "log: $re" ($runText -match $re) } }

    $manifest = Join-Path $dest 'Manifest.csv'
    if ($s.NoManifest) { Add-Result $s.Name 'stops before collecting (no Manifest.csv)' (-not (Test-Path $manifest)); continue }
    if (-not (Test-Path $manifest)) { Add-Result $s.Name 'Manifest.csv written' $false; continue }
    $m = @(Import-Csv $manifest)
    $allowed = $(if ($s.Failed) { $s.Failed } else { @{} }); $known = $(if ($s.Known) { $s.Known } else { @{} })
    foreach ($f in $m | Where-Object Status -eq 'Failed') {
        if ($allowed.ContainsKey($f.Section)) { Add-Result $s.Name "failed as expected: $($f.Section)" $true $allowed[$f.Section] }
        elseif ($known.ContainsKey($f.Section)) { Add-Result $s.Name "KNOWN ISSUE: $($f.Section)" $true "$($known[$f.Section]) | $($f.Detail)" 'KNOWN' }
        else { Add-Result $s.Name "unexpected failure: $($f.Section)" $false $f.Detail }
    }
    foreach ($k in $allowed.Keys) { if (-not ($m | Where-Object { $_.Section -eq $k -and $_.Status -eq 'Failed' })) { Add-Result $s.Name "expected failure did not happen: $k" $false } }
    $skipped = @($m | Where-Object Status -eq 'Skipped' | ForEach-Object Section | Sort-Object)
    $wantSkip = @($s.Skipped | Where-Object { $_ })
    $optSkip = @($s.SkippedOptional | Where-Object { $_ })
    $missing = @($wantSkip | Where-Object { $_ -notin $skipped }); $extra = @($skipped | Where-Object { $_ -notin $wantSkip -and $_ -notin $optSkip })
    Add-Result $s.Name 'skipped sections' ($missing.Count -eq 0 -and $extra.Count -eq 0) ("got: $($skipped -join ', ')" + $(if ($missing) { " | missing: $($missing -join ', ')" }) + $(if ($extra) { " | unexpected: $($extra -join ', ')" }))
    Add-Result $s.Name 'sections collected' ($m.Count -gt 0) ("{0} collected / {1} total" -f @($m | Where-Object Status -eq 'Collected').Count, $m.Count)
    foreach ($file in @($s.Files.Keys)) {
        if (-not $file) { continue }
        $p = Join-Path $dest $file
        Add-Result $s.Name "content: $file" ((Test-Path $p) -and ((Get-Content -Raw $p) -match $s.Files[$file])) $s.Files[$file]
    }
    if ($s.Zip) { Add-Result $s.Name 'zip written' (Test-Path "$dest.zip") }
}

# ---------------------------------------------------------------------------
# Unit tests
# ---------------------------------------------------------------------------
if ($Only -eq '*') {
    $th = Join-Path $repo 'tests/Test-Helpers.ps1'
    if (Test-Path $th) {
        $saveTemp = $env:TEMP; if (-not $env:TEMP) { $env:TEMP = $WorkDir }
        $o = & (Join-Path $PSHOME 'pwsh') -NoProfile -File $th 2>&1; $code = $LASTEXITCODE
        $env:TEMP = $saveTemp
        Add-Result 'tests/Test-Helpers.ps1' 'all checks pass' ($code -eq 0) ("{0} PASS, {1} FAIL, {2} SKIP" -f @($o -match '^PASS').Count, @($o -match '^FAIL').Count, @($o -match '^SKIP').Count)
        @($o -match '^FAIL') | ForEach-Object { Add-Result 'tests/Test-Helpers.ps1' "$_" $false }
    }
    if (Get-Module -ListAvailable Pester | Where-Object { $_.Version.Major -ge 5 }) {
        $cfg = New-PesterConfiguration; $cfg.Run.Path = (Join-Path $here 'Helpers.Tests.ps1'); $cfg.Run.PassThru = $true; $cfg.Output.Verbosity = 'None'
        $env:REPO = $repo; $pr = Invoke-Pester -Configuration $cfg; Remove-Item Env:REPO
        Add-Result 'Helpers.Tests.ps1 (Pester)' 'all tests pass' ($pr.FailedCount -eq 0) "$($pr.PassedCount) passed, $($pr.FailedCount) failed"
        $pr.Failed | ForEach-Object { Add-Result 'Helpers.Tests.ps1 (Pester)' $_.ExpandedName $false ($_.ErrorRecord | Select-Object -First 1) }
    } else { Add-Result 'Helpers.Tests.ps1 (Pester)' 'Pester 5 available' $true 'not installed: Install-Module Pester -MinimumVersion 5.0' 'SKIP' }
}

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
$results | Format-Table -AutoSize -Wrap Scenario, Status, Check, Detail | Out-String -Width 220 | Write-Host
$results | Export-Csv -Path (Join-Path $WorkDir 'TestResults.csv') -NoTypeInformation
$fail = @($results | Where-Object Status -eq 'FAIL').Count
$knownN = @($results | Where-Object Status -eq 'KNOWN').Count
Write-Host ("{0} checks: {1} pass, {2} fail, {3} known issue(s). Results: {4}" -f $results.Count, @($results | Where-Object Status -eq 'PASS').Count, $fail, $knownN, (Join-Path $WorkDir 'TestResults.csv')) -ForegroundColor $(if ($fail) { 'Red' } else { 'Green' })
exit $fail
