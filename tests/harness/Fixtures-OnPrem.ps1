# On-prem Exchange fixtures. Load after Fixtures-EXO.ps1 (DNS, accepted domains) and Fixtures-Entra.ps1 (Windows bits).
$FE = $env:FAKEENV
$X = Join-Path $FE 'ExchangeServer/V15'
$global:FixState.X = $X

$global:Fix['Get-ExchangeServer'] = {
    [PSCustomObject]@{ Name = 'EX01'; Fqdn = 'EX01.contoso.com'; Site = 'contoso.com/Configuration/Sites/HQ'; Edition = 'Standard'; AdminDisplayVersion = 'Version 15.2 (Build 1544.4)'; ServerRole = 'Mailbox'; IsMailboxServer = $true; IsEdgeServer = $false; IsHubTransportServer = $false; IsClientAccessServer = $false; WhenCreated = (Get-Date).AddYears(-3) }
    [PSCustomObject]@{ Name = 'EX02'; Fqdn = 'EX02.contoso.com'; Site = 'contoso.com/Configuration/Sites/DR'; Edition = 'Standard'; AdminDisplayVersion = 'Version 15.2 (Build 1544.4)'; ServerRole = 'Mailbox'; IsMailboxServer = $true; IsEdgeServer = $false; IsHubTransportServer = $false; IsClientAccessServer = $false }
    [PSCustomObject]@{ Name = 'EDGE01'; Fqdn = 'edge01.dmz.local'; ServerRole = 'Edge'; IsMailboxServer = $false; IsEdgeServer = $true; IsHubTransportServer = $true }
}
$global:Fix['Get-OrganizationConfig'] = {
    [PSCustomObject]@{ Name = 'Contoso'; DistinguishedName = 'CN=Contoso,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=contoso,DC=com'; PublicFoldersEnabled = 'Local'; RemotePublicFolderMailboxes = @(); DistributionGroupNamingPolicy = '' }
}
$global:Fix['Get-TransportService'] = {
    param($p)
    $id = "$($p['Identity'])"
    $base = $(if ($id -eq 'EX01') { $global:FixState.X } else { 'D:\Exchange\V15' })
    [PSCustomObject]@{ Name = $id; MessageTrackingLogEnabled = $true; MessageTrackingLogPath = (Join-Path $base 'TransportRoles/Logs/MessageTracking'); MessageTrackingLogMaxAge = '30.00:00:00'; MessageTrackingLogMaxDirectorySize = '1000 MB'
        ReceiveProtocolLogPath = (Join-Path $base 'TransportRoles/Logs/Hub/ProtocolLog/SmtpReceive'); SendProtocolLogPath = ''; ReceiveProtocolLogMaxAge = '30.00:00:00'; ExternalIPAddress = '203.0.113.10'; ExternalDNSServers = @(); InternalDNSServers = @('10.0.0.2') }
}
$global:Fix['Get-FrontendTransportService'] = {
    param($p)
    $id = "$($p['Identity'])"
    if ($id -ne 'EX01') { throw "Couldn't find object $id" }
    [PSCustomObject]@{ Name = $id; ReceiveProtocolLogPath = (Join-Path $global:FixState.X 'TransportRoles/Logs/FrontEnd/ProtocolLog/SmtpReceive'); ReceiveProtocolLogMaxAge = '30.00:00:00' }
}
$global:Fix['Get-PopSettings'] = { param($p) [PSCustomObject]@{ LoginType = 'SecureLogin'; ProtocolLogEnabled = $true; LogFileLocation = $(if ("$($p['Server'])" -eq 'EX01') { Join-Path $global:FixState.X 'Logging/Pop3' } else { '' }); SSLBindings = @('[::]:995', '0.0.0.0:995'); UnencryptedOrTLSBindings = @('[::]:110') } }
$global:Fix['Get-ImapSettings'] = { [PSCustomObject]@{ LoginType = 'SecureLogin'; ProtocolLogEnabled = $false; LogFileLocation = ''; SSLBindings = @('0.0.0.0:993'); UnencryptedOrTLSBindings = $null } }

# Get-MailboxDatabase rejects -IncludePreExchange2013 (as Exchange 2019 does) to exercise the fallback
$global:Fix['Get-MailboxDatabase'] = {
    param($p)
    if ($p.Contains('IncludePreExchange2013')) { throw "A parameter cannot be found that matches parameter name 'IncludePreExchange2013'." }
    [PSCustomObject]@{ Name = 'DB01'; Identity = 'DB01'; Guid = [guid]'d0000000-0000-0000-0000-000000000001'; Server = 'EX01'; Mounted = $true; DatabaseSize = '120 GB'; LastFullBackup = (Get-Date).AddDays(-1); Servers = @('EX01', 'EX02') }
    [PSCustomObject]@{ Name = 'DB02'; Identity = 'DB02'; Guid = [guid]'d0000000-0000-0000-0000-000000000002'; Server = 'EX02'; Mounted = $true; DatabaseSize = '80 GB' }
}
$global:FixState.Mbx = @(foreach ($i in 1..4) {
    [PSCustomObject]@{ DisplayName = "User $i"; PrimarySmtpAddress = "user$i@contoso.com"; Alias = "user$i"; RecipientTypeDetails = $(if ($i -eq 4) { 'SharedMailbox' } else { 'UserMailbox' }); Database = 'DB01'; ServerName = 'ex01'
        ExchangeGuid = [guid]("e000000$i-0000-0000-0000-000000000000"); DistinguishedName = "CN=User $i,OU=Users,DC=contoso,DC=com"; GrantSendOnBehalfTo = $(if ($i -eq 1) { @('CONTOSO\assistant') } else { @() }); InPlaceHolds = @(); WhenCreated = (Get-Date).AddDays(-500) }
})
$global:Fix['Get-Mailbox'] = {
    param($p)
    foreach ($k in 'Arbitration', 'AuditLog', 'AuxAuditLog', 'Monitoring', 'PublicFolder') {
        if ($p.Contains($k)) { return [PSCustomObject]@{ DisplayName = "$k mbx"; RecipientTypeDetails = "${k}Mailbox"; DistinguishedName = "CN=$k,CN=Users,DC=contoso,DC=com"; ExchangeGuid = [guid]::NewGuid() } }
    }
    if ($p.Contains('AuxAuditLog')) { throw 'not on this build' }
    $global:FixState.Mbx
}
# stats returned for users 1-2 per database; 3-4 fall back to per-mailbox lookup
$global:Fix['Get-MailboxStatistics'] = {
    param($p)
    if ($p.Contains('Database')) {
        if ("$($p['Database'])" -eq 'd0000000-0000-0000-0000-000000000001') { foreach ($m in $global:FixState.Mbx[0..1]) { [PSCustomObject]@{ MailboxGuid = $m.ExchangeGuid; TotalItemSize = '1.2 GB (1,288,490,188 bytes)'; ItemCount = 1234; LastLogonTime = (Get-Date).AddDays(-2); LastLoggedOnUserAccount = 'CONTOSO\x' } } }
        return
    }
    if ("$($p['Identity'])" -like '*User 4*') { throw 'mailbox not found' }
    [PSCustomObject]@{ TotalItemSize = '10 MB'; ItemCount = 5; LastLogonTime = $null }
}
$global:Fix['Get-User'] = {
    param($p)
    if ($p.Contains('Identity')) { return [PSCustomObject]@{ DistinguishedName = $p['Identity']; UserAccountControl = 'AccountDisabled, NormalAccount' } }
    [PSCustomObject]@{ DistinguishedName = 'CN=User 1,OU=Users,DC=contoso,DC=com'; AccountDisabled = $false }
}
$global:Fix['Get-MailboxPermission'] = {
    [PSCustomObject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess', 'ReadPermission'); IsInherited = $false; Deny = $false }
    [PSCustomObject]@{ User = 'CONTOSO\helpdesk'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
    [PSCustomObject]@{ User = 'CONTOSO\Organization Management'; AccessRights = @('FullAccess'); IsInherited = $true; Deny = $false }
}
$global:Fix['Get-ADPermission'] = {
    param($p)
    if ("$($p['Identity'])" -like '*Relay*') { return [PSCustomObject]@{ User = 'NT AUTHORITY\ANONYMOUS LOGON'; ExtendedRights = @('ms-Exch-SMTP-Accept-Any-Recipient'); IsInherited = $false; Deny = $false } }
    [PSCustomObject]@{ User = 'CONTOSO\scanner'; ExtendedRights = @('Send-As'); IsInherited = $false; Deny = $false }
    [PSCustomObject]@{ User = 'S-1-5-21-123'; ExtendedRights = @('Send-As'); IsInherited = $false; Deny = $false }
}
$global:Fix['Get-RemoteMailbox'] = {
    [PSCustomObject]@{ DisplayName = 'Cloud 1'; PrimarySmtpAddress = 'cloud1@contoso.com'; RemoteRoutingAddress = 'cloud1@contoso.mail.onmicrosoft.com'; ExchangeGuid = [guid]::NewGuid(); EmailAddresses = @('SMTP:cloud1@contoso.com', 'smtp:cloud1@contoso.mail.onmicrosoft.com'); EmailAddressPolicyEnabled = $true }
    [PSCustomObject]@{ DisplayName = 'Cloud 2'; PrimarySmtpAddress = 'cloud2@contoso.com'; RemoteRoutingAddress = ''; ExchangeGuid = [guid]::Empty; EmailAddresses = @('SMTP:cloud2@contoso.com'); EmailAddressPolicyEnabled = $false }
}
$global:Fix['Get-SendConnector'] = { [PSCustomObject]@{ Name = 'Outbound to Office 365'; Enabled = $true; AddressSpaces = @('smtp:contoso.mail.onmicrosoft.com;1'); SmartHosts = @('contoso-com.mail.protection.outlook.com'); Fqdn = 'mail.contoso.com'; TlsAuthLevel = 'DomainValidation'; CloudServicesMailEnabled = $true } }
$global:Fix['Get-ReceiveConnector'] = {
    [PSCustomObject]@{ Server = 'EX01'; Name = 'Default Frontend EX01'; Identity = 'EX01\Default Frontend EX01'; DistinguishedName = 'CN=Default Frontend EX01,CN=SMTP Receive Connectors'; Enabled = $true; Bindings = @('0.0.0.0:25', '[::]:25'); RemoteIPRanges = @('0.0.0.0-255.255.255.255'); ProtocolLoggingLevel = 'Verbose'; Fqdn = 'EX01.contoso.com' }
    [PSCustomObject]@{ Server = 'EX01'; Name = 'Relay Apps'; Identity = 'EX01\Relay Apps'; DistinguishedName = 'CN=Relay Apps,CN=SMTP Receive Connectors'; Enabled = $true; Bindings = @('0.0.0.0:25'); RemoteIPRanges = @('192.168.1.20', '10.0.0.50'); ProtocolLoggingLevel = 'None'; Fqdn = 'relay.contoso.com'; PermissionGroups = 'AnonymousUsers' }
}
# Tracking events spread across each requested window
$global:Fix['Get-MessageTrackingLog'] = {
    param($p)
    $s = [datetime]$p['Start']; $e = [datetime]$p['End']; $srv = "$($p['Server'])"
    $mid = $s.AddSeconds(($e - $s).TotalSeconds / 2)
    [PSCustomObject]@{ Timestamp = $mid; EventId = 'RECEIVE'; Source = 'SMTP'; ClientIp = '10.0.0.50'; OriginalClientIp = ''; ClientHostname = 'app01'; ConnectorId = "$srv\Relay Apps"; Sender = 'Scanner@contoso.com'; Recipients = @('user1@contoso.com', 'someone@gmail.com'); TotalBytes = 20480; MessageSubject = 'Scanned document from printer on floor 3 - very long subject line to test the truncation logic' }
    [PSCustomObject]@{ Timestamp = $mid.AddMinutes(1); EventId = 'RECEIVE'; Source = 'SMTP'; ClientIp = '40.92.5.5'; OriginalClientIp = '198.51.100.7'; ClientHostname = 'NAM12.outbound.protection.outlook.com'; ConnectorId = "$srv\Default Frontend $srv"; Sender = 'ext@fabrikam.com'; Recipients = @('user2@contoso.com', 'x@deep.sub.contoso.com'); TotalBytes = 1024 }
    [PSCustomObject]@{ Timestamp = $mid; EventId = 'RECEIVE'; Source = 'STOREDRIVER'; Sender = 'user1@contoso.com'; Recipients = @('ext@gmail.com') }
    [PSCustomObject]@{ Timestamp = $mid; EventId = 'SEND'; Source = 'SMTP'; ServerIp = '52.100.1.2'; ServerHostname = 'contoso-com.mail.protection.outlook.com'; ConnectorId = 'Outbound to Office 365'; Recipients = @('ext@gmail.com', 'a@b.org') }
    [PSCustomObject]@{ Timestamp = $mid; EventId = 'DELIVER'; Source = 'STOREDRIVER'; Sender = 'ext@fabrikam.com'; Recipients = @('User2@contoso.com', 'HealthMailbox123@contoso.com'); MessageSubject = 'Hi' }
    [PSCustomObject]@{ Timestamp = $mid; EventId = 'FAIL'; Source = 'ROUTING'; RecipientStatus = @('550 5.1.1 RESOLVER.ADR.RecipientNotFound') }
}
$global:Fix['Get-AdminAuditLogConfig'] = { [PSCustomObject]@{ AdminAuditLogEnabled = $true; AdminAuditLogAgeLimit = '90.00:00:00'; AdminAuditLogCmdlets = @('*'); LogLevel = 'None' } }
$global:Fix['Search-AdminAuditLog'] = {
    foreach ($i in 1..6) { [PSCustomObject]@{ Caller = "contoso.com/Users/admin$($i % 2)"; CmdletName = @('Set-Mailbox', 'Get-Mailbox', 'New-RemoteMailbox')[$i % 3]; RunDate = (Get-Date).AddDays(-$i * 7); ObjectModified = "obj$i" } }
}
$global:Fix['Get-HybridConfiguration'] = { [PSCustomObject]@{ Name = 'Hybrid Configuration'; TlsCertificateName = '<I>CN=R3, O=Let''s Encrypt, C=US<S>CN=mail.contoso.com'; Features = @('FreeBusy', 'MoveMailbox', 'Mailtips'); OnPremisesSmartHost = 'mail.contoso.com' } }
$global:Fix['Get-OwaVirtualDirectory'] = { [PSCustomObject]@{ Server = 'EX01'; Name = 'owa (Default Web Site)'; InternalUrl = 'https://ex01.contoso.com/owa'; ExternalUrl = 'https://mail.contoso.com/owa'; InternalAuthenticationMethods = @('Basic', 'Fba'); BasicAuthentication = $true } }
$global:Fix['Get-WebServicesVirtualDirectory'] = { [PSCustomObject]@{ Server = 'EX01'; Name = 'EWS (Default Web Site)'; InternalUrl = 'https://ex01.contoso.com/EWS/Exchange.asmx'; ExternalUrl = $null } }
$global:Fix['Get-OutlookAnywhere'] = { [PSCustomObject]@{ Server = 'EX01'; Name = 'Rpc (Default Web Site)'; InternalHostname = 'ex01.contoso.com'; ExternalHostname = 'mail.contoso.com' } }
$global:Fix['Get-ExchangeCertificate'] = { [PSCustomObject]@{ Thumbprint = 'ABCDEF'; Subject = 'CN=mail.contoso.com'; CertificateDomains = @('mail.contoso.com', 'autodiscover.contoso.com'); NotAfter = (Get-Date).AddDays(40); Services = 'IIS, SMTP' } }
$global:Fix['Get-PublicFolder'] = { foreach ($i in 1..3) { [PSCustomObject]@{ Name = "PF$i" } } }

# Microsoft 365 endpoints (no network)
$global:Fix['Invoke-RestMethod'] = {
    @(
        [PSCustomObject]@{ id = 1; serviceArea = 'Exchange'; ips = @('40.92.0.0/15', '52.100.0.0/14', '2a01:111:f400::/48', '40.107.0.0/16', '104.47.0.0/17') }
        [PSCustomObject]@{ id = 2; serviceArea = 'SharePoint'; ips = @('13.107.136.0/22') }
        [PSCustomObject]@{ id = 3; serviceArea = 'Exchange'; urls = @('outlook.office.com') }
    )
}
$global:Fix['Get-NetTCPConnection'] = {
    param($p)
    if ("$($p['State'])" -eq 'Listen') { [PSCustomObject]@{ LocalAddress = '0.0.0.0'; LocalPort = 25; OwningProcess = 1 }; [PSCustomObject]@{ LocalAddress = '0.0.0.0'; LocalPort = 443; OwningProcess = 1 } }
    else { [PSCustomObject]@{ LocalPort = 25; RemoteAddress = '10.0.0.50'; OwningProcess = 1 }; [PSCustomObject]@{ LocalPort = 443; RemoteAddress = '52.100.1.2'; OwningProcess = 1 }; [PSCustomObject]@{ LocalPort = 443; RemoteAddress = '127.0.0.1'; OwningProcess = 1 } }
}
$global:Fix['Get-NetFirewallRule'] = { [PSCustomObject]@{ DisplayName = 'Allow SMTP from apps'; Profile = 'Domain'; Action = 'Allow'; Group = '' }; [PSCustomObject]@{ DisplayName = 'Core Networking - DHCP'; Group = '' } }
$global:Fix['Get-NetFirewallPortFilter'] = { [PSCustomObject]@{ LocalPort = @('25', '587') } }
$global:Fix['Get-NetFirewallApplicationFilter'] = { [PSCustomObject]@{ Program = 'Any' } }
$global:Fix['Get-NetIPAddress'] = { [PSCustomObject]@{ IPAddress = '10.0.0.10' }; [PSCustomObject]@{ IPAddress = '127.0.0.1' } }
$global:Fix['Get-DnsClientServerAddress'] = { [PSCustomObject]@{ ServerAddresses = @('10.0.0.2', '10.0.0.3') } }
$global:Fix['Get-HotFix'] = { [PSCustomObject]@{ HotFixID = 'KB5044277'; InstalledOn = (Get-Date).AddDays(-10) } }
if ($env:FIX_NO_INTERNET) { $global:Fix["Invoke-RestMethod"] = { throw "No such host is known. (endpoints.office.com:443)" } }
