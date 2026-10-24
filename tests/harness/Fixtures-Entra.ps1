# ADSync fixtures
$global:Fix['Get-ADSyncGlobalSettings'] = {
    [PSCustomObject]@{ Parameters = @(
        [PSCustomObject]@{ Name = 'Microsoft.OptionalFeature.ExchangeMailPublicFolder'; Value = 'False' }
        [PSCustomObject]@{ Name = 'Microsoft.OptionalFeature.GroupWriteBack'; Value = 'True' }
        [PSCustomObject]@{ Name = 'Microsoft.SynchronizationOption.JoinCriteria'; Value = 'AlwaysProvision' }
        [PSCustomObject]@{ Name = 'Microsoft.Synchronize.ServerConfigurationVersion'; Value = '2.4.18.0' }
    ) }
}
$global:Fix['Get-ADSyncScheduler'] = { [PSCustomObject]@{ AllowedSyncCycleInterval = '00:30:00'; SyncCycleEnabled = $true; NextSyncCycleStartTimeInUTC = (Get-Date).ToUniversalTime().AddMinutes(12); StagingModeEnabled = $false; SchedulerSuspended = $false } }
$global:Fix['Get-ADSyncConnector'] = {
    $adParams = [System.Collections.Generic.List[object]]::new()
    $adParams.Add([PSCustomObject]@{ Name = 'forest-name'; Value = 'contoso.com' })
    $adParams.Add([PSCustomObject]@{ Name = 'forest-login-user'; Value = 'MSOL_abc123' })
    # Second connector uses a dictionary-style collection, as some ADSync builds do
    $dictParams = @{ 'forest-name' = [PSCustomObject]@{ Value = 'fabrikam.local' }; 'forest-login-user' = 'FAB\svc-sync' }
    [PSCustomObject]@{
        Name = 'contoso.com'; ConnectorTypeName = 'AD'; Identifier = [guid]'aaaaaaaa-0000-0000-0000-000000000001'; ConnectivityParameters = $adParams
        Partitions = @([PSCustomObject]@{ Name = 'DC=contoso,DC=com'; Selected = $true; ConnectorPartitionSelected = $true; ConnectorPartitionScope = [PSCustomObject]@{ ContainerInclusionList = @('OU=Users,DC=contoso,DC=com', 'OU=Groups,DC=contoso,DC=com'); ContainerExclusionList = @('OU=Disabled,OU=Users,DC=contoso,DC=com') } })
        AttributeInclusionList = @('mail', 'proxyAddresses', 'msExchRecipientTypeDetails', 'displayName', 'targetAddress')
        ObjectInclusionList = @('user', 'group', 'contact')
        AnchorConstructionSettings = @([PSCustomObject]@{ ObjectType = 'user'; AnchorAttributes = @('objectGUID') })
    }
    [PSCustomObject]@{
        Name = 'fabrikam.local'; ConnectorTypeName = 'AD'; Identifier = [guid]'aaaaaaaa-0000-0000-0000-000000000002'; ConnectivityParameters = $dictParams
        Partitions = @([PSCustomObject]@{ Name = 'DC=fabrikam,DC=local'; Selected = $true; ConnectorPartitionScope = [PSCustomObject]@{ ContainerInclusionList = @(); ContainerExclusionList = @() } })
        AttributeInclusionList = @('mail'); ObjectInclusionList = @('user')
    }
    [PSCustomObject]@{
        Name = 'contoso.onmicrosoft.com - AAD'; ConnectorTypeName = 'Extensible2'; Identifier = [guid]'bbbbbbbb-0000-0000-0000-000000000001'
        ConnectivityParameters = @([PSCustomObject]@{ Name = 'UserName'; Value = 'Sync_SRV01_abc@contoso.onmicrosoft.com' })
        GlobalParameters = @([PSCustomObject]@{ Name = 'Microsoft.OptionalFeature.ExchangeHybrid'; Value = 'True' }, [PSCustomObject]@{ Name = 'Other'; Value = 'x' })
        Partitions = @([PSCustomObject]@{ Name = 'default' })
    }
}
$global:Fix['Get-ADSyncRule'] = {
    [PSCustomObject]@{ Name = 'Out to AD - User Exchange Hybrid'; Direction = 'Outbound'; Precedence = 120; Disabled = $false; IsStandardRule = $true; TargetObjectType = 'user'; SourceObjectType = 'person'
        AttributeFlowMappings = @([PSCustomObject]@{ Destination = 'msExchArchiveStatus'; Source = @('cloudMSExchArchiveStatus'); FlowType = 'Direct' }, [PSCustomObject]@{ Destination = 'proxyAddresses'; Source = @('cloudLegacyExchangeDN'); FlowType = 'Expression'; Expression = 'IIF(...)' }) }
    [PSCustomObject]@{ Name = 'In from AD - User Custom'; Direction = 'Inbound'; Precedence = 50; Disabled = $false; IsStandardRule = $false; TargetObjectType = 'person'
        AttributeFlowMappings = @([PSCustomObject]@{ Destination = 'extensionAttribute1'; Source = @('department', 'company'); FlowType = 'Expression'; Expression = 'Join(...)'; ExecuteOnce = $false }) }
    [PSCustomObject]@{ Name = 'Disabled rule'; Direction = 'Inbound'; Precedence = 60; Disabled = $true; IsStandardRule = $false; TargetObjectType = 'person'; AttributeFlowMappings = @() }
}
$global:Fix['Get-ADSyncAADCompanyFeature'] = { [PSCustomObject]@{ PasswordHashSync = $true; ForcePasswordChangeOnLogOn = $false; UserWriteback = $false; DeviceWriteback = $false } }
$global:Fix['Get-ADSyncAutoUpgrade'] = { 'Enabled' }
$global:Fix['Get-ADSyncConnectorRunStatus'] = { }
$global:Fix['Get-ADSyncRunProfileResult'] = {
    [PSCustomObject]@{ ConnectorName = ''; ConnectorId = [guid]'aaaaaaaa-0000-0000-0000-000000000001'; RunProfileName = 'Delta Import'; StartDate = (Get-Date).AddMinutes(-30); EndDate = (Get-Date).AddMinutes(-29); Result = 'success' }
    [PSCustomObject]@{ ConnectorName = 'contoso.onmicrosoft.com - AAD'; RunProfileName = 'Export'; StartDate = (Get-Date).AddMinutes(-28); EndDate = (Get-Date).AddMinutes(-27); Result = 'completed-export-errors' }
}
$global:Fix['Get-WinEvent'] = {
    [PSCustomObject]@{ ProviderName = 'Directory Synchronization'; Id = 6100; TimeCreated = (Get-Date).AddHours(-2); Message = "The Microsoft Identity Integration Server sync failed`nsecond line"; LevelDisplayName = 'Error' }
    [PSCustomObject]@{ ProviderName = 'Directory Synchronization'; Id = 6100; TimeCreated = (Get-Date).AddHours(-1); Message = 'again'; LevelDisplayName = 'Error' }
    [PSCustomObject]@{ ProviderName = 'Outlook'; Id = 1; TimeCreated = (Get-Date); Message = 'unrelated'; LevelDisplayName = 'Warning' }
}
$global:Fix['Get-Service'] = { param($p) [PSCustomObject]@{ Name = "$($p['Pos0'])$($p['Name'])"; DisplayName = 'Microsoft Azure AD Sync'; Status = 'Running'; StartType = 'Automatic' } }
$global:Fix['Get-CimInstance'] = {
    param($p)
    switch ("$($p['Pos0'])$($p['ClassName'])") {
        'Win32_OperatingSystem' { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2019 Standard'; Version = '10.0.17763'; BuildNumber = '17763'; LastBootUpTime = (Get-Date).AddDays(-12); InstallDate = (Get-Date).AddYears(-4) } }
        'Win32_ComputerSystem' { [PSCustomObject]@{ Domain = 'contoso.com'; TotalPhysicalMemory = 34359738368; NumberOfLogicalProcessors = 8; Manufacturer = 'VMware'; Model = 'VMware7,1' } }
        'Win32_LogicalDisk' { [PSCustomObject]@{ DeviceID = 'C:'; FreeSpace = 50GB; Size = 127GB } }
        'Win32_Service' {
            [PSCustomObject]@{ Name = 'ADSync'; DisplayName = 'Microsoft Azure AD Sync'; State = 'Running'; StartMode = 'Auto'; StartName = 'NT SERVICE\ADSync'; PathName = '"C:\Program Files\Microsoft Azure AD Sync\Bin\miiserver.exe"' }
            [PSCustomObject]@{ Name = 'VeeamAgent'; DisplayName = 'Veeam Agent'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\Program Files\Veeam\agent.exe' }
            [PSCustomObject]@{ Name = 'MSExchangeTransport'; DisplayName = 'Microsoft Exchange Transport'; State = 'Running'; StartMode = 'Auto'; StartName = 'NT AUTHORITY\NetworkService'; PathName = 'C:\Program Files\Microsoft\Exchange Server\V15\Bin\MSExchangeTransport.exe' }
            [PSCustomObject]@{ Name = 'Spooler'; DisplayName = 'Print Spooler'; State = 'Running'; StartMode = 'Auto'; StartName = 'LocalSystem'; PathName = 'C:\Windows\System32\spoolsv.exe' }
        }
    }
}
$global:Fix['Get-ScheduledTask'] = {
    [PSCustomObject]@{ TaskPath = '\'; TaskName = 'Nightly export'; State = 'Ready'; Author = 'CONTOSO\admin'; Principal = [PSCustomObject]@{ UserId = 'SYSTEM' }; Actions = @([PSCustomObject]@{ Execute = 'powershell.exe'; Arguments = '-File C:\scripts\export.ps1' }); Triggers = @() }
    [PSCustomObject]@{ TaskPath = '\Microsoft\Windows\'; TaskName = 'Builtin'; State = 'Ready' }
}
$global:Fix['Get-ScheduledTaskInfo'] = { [PSCustomObject]@{ LastRunTime = (Get-Date).AddDays(-1); LastTaskResult = 0; NextRunTime = (Get-Date).AddHours(6) } }
# Registry uninstall keys (HKLM: does not exist on Linux)
$global:Fix['Get-ItemProperty'] = {
    param($p)
    $path = "$($p['Pos0'])$($p['Path'])"
    if ($path -like '*\Uninstall\*' -and $path -like 'HKLM:\SOFTWARE\Microsoft\*') {
        [PSCustomObject]@{ DisplayName = 'Microsoft Azure AD Connect'; DisplayVersion = '2.4.18.0'; Publisher = 'Microsoft Corporation'; InstallDate = '20240101' }
        [PSCustomObject]@{ DisplayName = 'Microsoft Exchange Server 2019 Cumulative Update 14'; DisplayVersion = '15.2.1544.4'; Publisher = 'Microsoft Corporation'; InstallDate = '20240301' }
        [PSCustomObject]@{ DisplayName = 'Veeam Backup Agent'; DisplayVersion = '6.0'; Publisher = 'Veeam'; InstallDate = '20230101' }
        [PSCustomObject]@{ DisplayName = 'Exchange Modern Hybrid Agent'; DisplayVersion = '1.0'; Publisher = 'Microsoft'; InstallDate = '20230101' }
    }
    elseif ($path -like '*NDP\v4\Full') { [PSCustomObject]@{ Release = 533320 } }
}
