# Pester tests for the pure helper functions, extracted from the scripts via the AST (no script execution).
BeforeAll {
    $repo = $(if ($env:REPO) { $env:REPO } else { Split-Path (Split-Path $PSScriptRoot -Parent) -Parent })
    function Import-ScriptFunctions {
        param([string]$Path, [string[]]$Names)
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        foreach ($f in $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and -not ($args[0].Parent -is [System.Management.Automation.Language.NamedBlockAst] -and $args[0].Parent.Parent.Parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) }, $true)) {
            if ($f.Name -in $Names) { . ([scriptblock]::Create(($f.Extent.Text -replace '^function ', 'function global:'))) }
        }
        $ast
    }
    $onprem = Import-ScriptFunctions "$repo/Get-ExchOnPremDecomInventory.ps1" 'ConvertTo-UncPath', 'Get-EndpointIp', 'Test-MicrosoftIP', 'Find-FieldIndex', 'Get-AccountDisabled', 'Get-AdsiValue', 'Get-DaysAvailable', 'Test-InternalRecipient', 'Get-DirStats', 'Open-LogReader'
    $null = Import-ScriptFunctions "$repo/Get-EntraConnectDecomInventory.ps1" 'Get-ParamValue'
    $null = Import-ScriptFunctions "$repo/Get-EXODecomInventory.ps1" 'ConvertTo-FlatValue'
    # Re-run the script's own CIDR parsing statement against a known list
    $cidrStmt = $onprem.FindAll({ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and $args[0].Left.Extent.Text -eq '$script:MsCidrParsed' }, $true) | Select-Object -First 1
    function global:Set-Cidrs([string[]]$List) { $script:MsCidrs = $List; . ([scriptblock]::Create($cidrStmt.Extent.Text)); $global:MsCidrParsed = $script:MsCidrParsed }
}

Describe 'ConvertTo-UncPath' {
    It 'maps a drive path to the admin share' { ConvertTo-UncPath 'EX02' 'D:\Exchange\Logs\MessageTracking' | Should -Be '\\EX02\D$\Exchange\Logs\MessageTracking' }
    It 'returns null for empty or UNC input' { ConvertTo-UncPath 'EX02' '' | Should -BeNullOrEmpty; ConvertTo-UncPath 'EX02' '\\x\y' | Should -BeNullOrEmpty }
}

Describe 'Get-EndpointIp' {
    It '<In> -> <Out>' -TestCases @(
        @{ In = '10.1.2.3:25'; Out = '10.1.2.3' }, @{ In = '[fe80::1]:25'; Out = 'fe80::1' }, @{ In = '10.1.2.3'; Out = '10.1.2.3' }
        @{ In = ' "192.168.0.1:587" '; Out = '192.168.0.1' }, @{ In = 'fe80::1'; Out = 'fe80::1' }, @{ In = ''; Out = '' }
    ) { Get-EndpointIp $In | Should -Be $Out }
}

Describe 'Test-MicrosoftIP (CIDR matching)' {
    BeforeAll { Set-Cidrs @('40.92.0.0/15', '52.100.0.0/14', '104.47.0.0/17', '1.2.3.4/32', 'bogus', '9.9.9.0/notanumber') }
    It 'parses only the valid ranges' { $global:MsCidrParsed.Count | Should -Be 4 }
    It '<Ip> -> <Expected>' -TestCases @(
        @{ Ip = '40.92.0.0'; Expected = 'True' }, @{ Ip = '40.93.255.255'; Expected = 'True' }, @{ Ip = '40.94.0.0'; Expected = 'False' }, @{ Ip = '40.91.255.255'; Expected = 'False' }
        @{ Ip = '52.103.1.1:25'; Expected = 'True' }, @{ Ip = '52.104.0.0'; Expected = 'False' }, @{ Ip = '104.47.127.255'; Expected = 'True' }, @{ Ip = '104.47.128.0'; Expected = 'False' }
        @{ Ip = '1.2.3.4'; Expected = 'True' }, @{ Ip = '1.2.3.5'; Expected = 'False' }, @{ Ip = '10.0.0.1'; Expected = 'False' }
        @{ Ip = 'fe80::1'; Expected = '' }, @{ Ip = ''; Expected = '' }, @{ Ip = '999.1.1.1'; Expected = '' }
    ) { $script:MsCidrParsed = $global:MsCidrParsed; Test-MicrosoftIP $Ip | Should -Be $Expected }
    It 'handles /0 and /1 masks' {
        Set-Cidrs @('0.0.0.0/0'); $script:MsCidrParsed = $global:MsCidrParsed; Test-MicrosoftIP '203.0.113.1' | Should -Be 'True'
        Set-Cidrs @('128.0.0.0/1'); $script:MsCidrParsed = $global:MsCidrParsed; Test-MicrosoftIP '200.1.1.1' | Should -Be 'True'; Test-MicrosoftIP '100.1.1.1' | Should -Be 'False'
    }
    It 'returns blank when no ranges were downloaded' { $script:MsCidrParsed = @(); Test-MicrosoftIP '40.92.0.1' | Should -Be '' }
}

Describe 'Find-FieldIndex' {
    It 'finds a renamed column' { Find-FieldIndex @('dateTime', 'sessionId', 'seqNumber', 'sIp', ' cIp ', 'user') @('cIp', 'c-ip') 9 | Should -Be 4 }
    It 'falls back to the default' { Find-FieldIndex @('a', 'b') @('cIp') 4 | Should -Be 4 }
}

Describe 'Test-InternalRecipient' {
    BeforeAll { $script:AcceptedDomainNames = @('contoso.com'); $script:WildcardDomains = @('sub.contoso.com') }
    It '<A> -> <E>' -TestCases @(
        @{ A = 'x@contoso.com'; E = $true }, @{ A = 'X@CONTOSO.COM'; E = $true }, @{ A = 'x@a.sub.contoso.com'; E = $true }
        @{ A = 'x@evilcontoso.com'; E = $false }, @{ A = 'x@sub.contoso.com.evil'; E = $false }, @{ A = 'noat'; E = $false }, @{ A = ''; E = $false }
    ) { $script:AcceptedDomainNames = @('contoso.com'); $script:WildcardDomains = @('sub.contoso.com'); Test-InternalRecipient $A | Should -Be $E }
}

Describe 'Get-AccountDisabled' {
    It 'prefers AccountDisabled' { Get-AccountDisabled ([PSCustomObject]@{ AccountDisabled = $true }) | Should -Be 'True' }
    It 'falls back to UserAccountControl' { Get-AccountDisabled ([PSCustomObject]@{ UserAccountControl = 'AccountDisabled, NormalAccount' }) | Should -Be 'True'; Get-AccountDisabled ([PSCustomObject]@{ UserAccountControl = 'NormalAccount' }) | Should -Be 'False' }
    It 'blank for null' { Get-AccountDisabled $null | Should -Be '' }
}

Describe 'Get-ParamValue (Entra)' {
    It 'list-style' { Get-ParamValue @([PSCustomObject]@{ Name = 'forest-name'; Value = 'contoso.com' }) '^forest-name$' | Should -Be 'contoso.com' }
    It 'dictionary with .Value objects' { Get-ParamValue @{ 'forest-name' = [PSCustomObject]@{ Value = 'fab.local' } } '^forest-name$' | Should -Be 'fab.local' }
    It 'dictionary with plain strings' { Get-ParamValue @{ 'forest-login-user' = 'FAB\svc' } 'forest-login-user' | Should -Be 'FAB\svc' }
    It 'missing -> blank' { Get-ParamValue @() 'x' | Should -Be ''; Get-ParamValue $null 'x' | Should -Be '' }
}

Describe 'ConvertTo-FlatValue' {
    It 'dates' { ConvertTo-FlatValue ([datetime]'2026-01-02 03:04:05') | Should -Be '2026-01-02 03:04:05' }
    It 'arrays with nulls' { ConvertTo-FlatValue @('a', $null, 'b') | Should -Be 'a; b' }
    It 'hashtable' { ConvertTo-FlatValue ([ordered]@{ a = 1; b = 2 }) | Should -Be 'a=1; b=2' }
    It 'bytes' { ConvertTo-FlatValue ([byte[]](1, 2, 3)) | Should -Be '<3 bytes>' }
    It 'null' { ConvertTo-FlatValue $null | Should -Be '' }
}

Describe 'Open-LogReader' {
    It 'reads a file another handle is still writing to' {
        $p = Join-Path ([IO.Path]::GetTempPath()) "lockt_$PID.log"
        $w = [IO.FileStream]::new($p, 'Create', 'Write', 'ReadWrite')
        $bytes = [Text.Encoding]::ASCII.GetBytes("line1`nline2`n"); $w.Write($bytes, 0, $bytes.Length); $w.Flush()
        try { $sr = Open-LogReader $p; $sr.ReadLine() | Should -Be 'line1'; $sr.Close() } finally { $w.Close(); Remove-Item $p }
    }
}
