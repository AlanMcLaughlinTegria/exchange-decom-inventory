# Exchange Online / Graph / DNS fixtures
$global:FixState.Connected = [bool]$env:FIX_PRECONNECTED
$global:FixState.TraceCalls = 0
$global:FixState.AuditPage = 0

$global:Fix['Get-ConnectionInformation'] = {
    if ($global:FixState.Connected) {
        [PSCustomObject]@{ State = 'Connected'; IsEopSession = $false; TokenStatus = 'Active'; UserPrincipalName = 'admin@contoso.com'; TenantID = '11111111-2222-3333-4444-555555555555' }
    }
}
$global:Fix['Connect-ExchangeOnline'] = { param($p) if ($env:FIX_CONNECT_FAIL) { throw 'AADSTS50126: Invalid username or password' }; $global:FixState.Connected = $true }
$global:Fix['Disconnect-ExchangeOnline'] = { $global:FixState.Connected = $false }

$global:Fix['Get-AcceptedDomain'] = {
    [PSCustomObject]@{ Name = 'contoso.com'; DomainName = 'contoso.com'; DomainType = 'Authoritative'; Default = $true; InitialDomain = $false; MatchSubDomains = $false }
    [PSCustomObject]@{ Name = 'Wild'; DomainName = '*.sub.contoso.com'; DomainType = 'InternalRelay'; Default = $false; InitialDomain = $false; MatchSubDomains = $true }
    [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com'; DomainName = 'contoso.onmicrosoft.com'; DomainType = 'Authoritative'; Default = $false; InitialDomain = $true }
}
$global:Fix['Get-OrganizationConfig'] = {
    [PSCustomObject]@{ Name = 'contoso.onmicrosoft.com'; DisplayName = 'Contoso'; IsDehydrated = $false; PublicFoldersEnabled = 'Local'; RemotePublicFolderMailboxes = @('PF1', 'PF2'); WhenCreated = (Get-Date).AddYears(-3) }
}
$global:Fix['Get-InboundConnector'] = {
    [PSCustomObject]@{ Name = 'Inbound from OnPrem'; Enabled = $true; ConnectorType = 'OnPremises'; SenderIPAddresses = @('203.0.113.10', '203.0.113.11'); TlsSenderCertificateName = 'mail.contoso.com'; SenderDomains = @('*') }
    [PSCustomObject]@{ Name = 'Partner'; Enabled = $true; ConnectorType = 'Partner'; SenderDomains = @('fabrikam.com') }
}
# The IncludeTestModeConnectors switch is rejected on this "tenant" to exercise the fallback
$global:Fix['Get-OutboundConnector'] = {
    param($p)
    if ($p.Contains('IncludeTestModeConnectors')) { throw "A parameter cannot be found that matches parameter name 'IncludeTestModeConnectors'." }
    [PSCustomObject]@{ Name = 'Outbound to OnPrem'; Enabled = $true; ConnectorType = 'OnPremises'; RecipientDomains = @('contoso.com'); SmartHosts = @('mail.contoso.com'); RouteAllMessagesViaOnPremises = $true; UseMXRecord = $false }
}
$global:Fix['Get-EXOMailbox'] = {
    param($p)
    if ($p.Contains('InactiveMailboxOnly')) { return [PSCustomObject]@{ DisplayName = 'Gone'; PrimarySmtpAddress = 'gone@contoso.com'; RecipientTypeDetails = 'UserMailbox'; WhenSoftDeleted = (Get-Date).AddDays(-20); LitigationHoldEnabled = $true; InPlaceHolds = @('mbx123') } }
    foreach ($i in 1..3) { [PSCustomObject]@{ DisplayName = "User $i"; PrimarySmtpAddress = "user$i@contoso.com"; RecipientTypeDetails = $(if ($i -eq 3) { 'SharedMailbox' } else { 'UserMailbox' }); IsDirSynced = ($i -ne 2); ExchangeGuid = [guid]::NewGuid(); InPlaceHolds = @(); WhenCreated = (Get-Date).AddDays(-$i * 10) } }
}
$global:Fix['Get-DkimSigningConfig'] = {
    [PSCustomObject]@{ Domain = 'contoso.com'; Enabled = $true; Status = 'Valid'; Selector1CNAME = 'selector1-contoso-com._domainkey.contoso.onmicrosoft.com' }
}

# Message trace V2: first day returns a full page (5000) to force paging; one throttle on call #3
$global:Fix['Get-MessageTraceV2'] = {
    param($p)
    $global:FixState.TraceCalls++
    if ($global:FixState.TraceCalls -eq 3 -and -not $global:FixState.Throttled) { $global:FixState.Throttled = $true; throw 'The request was throttled. (429 Too Many Requests)' }
    $start = [datetime]$p['StartDate']; $end = [datetime]$p['EndDate']
    $n = $(if ($global:FixState.TraceCalls -eq 1) { 5000 } else { 4 })
    $span = ($end - $start).TotalSeconds
    foreach ($i in 1..$n) {
        $r = $start.AddSeconds($span * ($n - $i + 1) / ($n + 1))   # newest first, like the service
        $kind = $i % 4
        [PSCustomObject]@{
            Received = $r
            SenderAddress = @('user1@contoso.com', 'ext@fabrikam.com', 'app@sub.contoso.com', 'noreply@vendor.net')[$kind]
            RecipientAddress = @('ext@gmail.com', 'user2@contoso.com', 'user3@contoso.com', 'x@other.org')[$kind]
            FromIP = @('203.0.113.10', '40.92.1.1', '203.0.113.11', '198.51.100.7')[$kind]
            ToIP = ''; Status = @('Delivered', 'Delivered', 'Failed', 'FilteredAsSpam')[$kind]
        }
    }
}
$global:Fix['Search-UnifiedAuditLog'] = {
    param($p)
    $global:FixState.AuditPage++
    $n = $(if ($global:FixState.AuditPage -eq 1) { 5000 } else { 7 })
    foreach ($i in 1..$n) {
        [PSCustomObject]@{ UserIds = "admin$($i % 3)@contoso.com"; Operations = @('Set-Mailbox', 'New-InboundConnector', 'Set-User')[$i % 3]; CreationDate = (Get-Date).AddMinutes(-$i); AuditData = (@{ ObjectId = "obj$i" } | ConvertTo-Json -Compress) }
    }
}
$global:Fix['Invoke-MgGraphRequest'] = {
    param($p)
    $uri = "$($p['Uri'])"
    switch -Regex ($uri) {
        'organization' { @{ value = @(@{ id = 'tid'; displayName = 'Contoso'; tenantType = 'AAD'; onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = (Get-Date).AddMinutes(-20); verifiedDomains = @(@{ name = 'contoso.com'; type = 'Managed'; isDefault = $true }, @{ name = 'contoso.onmicrosoft.com'; type = 'Managed'; isInitial = $true }) }) }; break }
        'onPremisesSynchronization' { @{ value = @(@{ features = @{ passwordSyncEnabled = $true } }) }; break }
        'users/\$count\?' { 42; break }
        'users/\$count' { 50; break }
        'subscribedSkus' { @{ value = @(@{ skuPartNumber = 'ENTERPRISEPACK'; skuId = 'sku1'; consumedUnits = 40; capabilityStatus = 'Enabled'; prepaidUnits = @{ enabled = 50; suspended = 0; warning = 0 }; servicePlans = @(@{ servicePlanName = 'EXCHANGE_S_ENTERPRISE'; provisioningStatus = 'Success' }, @{ servicePlanName = 'TEAMS1'; provisioningStatus = 'Success' }) }) }; break }
        default { throw "unexpected Graph URI $uri" }
    }
}
function global:Connect-MgGraph { param([string[]]$Scopes, [switch]$NoWelcome) $global:StubCalls.Add([PSCustomObject]@{ Cmd = 'Connect-MgGraph'; Params = "NoWelcome=$NoWelcome" }) }
function global:Connect-IPPSSession { param([string]$UserPrincipalName, [switch]$ShowBanner) $global:StubCalls.Add([PSCustomObject]@{ Cmd = 'Connect-IPPSSession'; Params = "UPN=$UserPrincipalName ShowBanner=$ShowBanner" }) }

# Resolve-DnsName (Windows-only) - fake answers; 1.1.1.1 "unreachable" is not tested, 8.8.8.8 works
$global:Fix['Resolve-DnsName'] = {
    param($p)
    $name = "$($p['Name'])"; $type = "$($p['Type'])"
    if ($name -match '^(webmail|owa)\.' -or $name -match '_smtp\._tls') { throw "$name : DNS name does not exist" }
    switch ($type) {
        'MX' { [PSCustomObject]@{ Type = 'MX'; Preference = 0; NameExchange = 'contoso-com.mail.protection.outlook.com'; TTL = 3600 }; [PSCustomObject]@{ Type = 'SOA'; TTL = 1 } }
        'TXT' { if ($name -like '_dmarc.*') { [PSCustomObject]@{ Type = 'TXT'; Strings = @('v=DMARC1; p=none'); TTL = 3600 } } elseif ($name -notmatch '^_') { [PSCustomObject]@{ Type = 'TXT'; Strings = @('v=spf1 ip4:203.0.113.10 include:spf.protection.outlook.com', ' -all'); TTL = 3600 } } }
        'CNAME' { [PSCustomObject]@{ Type = 'CNAME'; NameHost = $(if ($name -like 'selector1.*') { 'selector1-contoso-com._domainkey.contoso.onmicrosoft.com.' } else { 'autodiscover.outlook.com' }); TTL = 300 } }
        'A' { [PSCustomObject]@{ Type = 'A'; IPAddress = '203.0.113.10'; TTL = 300 } }
        'SRV' { [PSCustomObject]@{ Type = 'SRV'; Priority = 0; Weight = 0; Port = 443; NameTarget = 'mail.contoso.com'; TTL = 300 } }
        'PTR' { [PSCustomObject]@{ Type = 'PTR'; NameHost = 'mail.contoso.com'; TTL = 300 } }
    }
}
$global:Fix['Start-Sleep'] = { param($p) $global:FixState.Slept += @($p['Seconds']) }

# Legacy Get-MessageTrace (page-number paging)
$global:Fix['Get-MessageTrace'] = {
    param($p)
    $n = $(if ([int]$p['Page'] -eq 1) { 5000 } else { 2 })
    $start = [datetime]$p['StartDate']
    foreach ($i in 1..$n) { [PSCustomObject]@{ Received = $start.AddMinutes($i % 1000); SenderAddress = 'user1@contoso.com'; RecipientAddress = 'ext@gmail.com'; FromIP = '203.0.113.10'; ToIP = ''; Status = 'Delivered' } }
}
if ($env:FIX_IPPS_FAIL) { function global:Connect-IPPSSession { param([string]$UserPrincipalName, [switch]$ShowBanner) throw 'User is not assigned a Purview role' } }
