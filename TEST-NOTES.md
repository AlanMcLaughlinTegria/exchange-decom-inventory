# Test notes: FullLanguage run of the inventory scripts

**Date:** 2026-10-23
**Tested by:** nimbice, with Claude Code
**Why:** the scripts are written on a machine that runs PowerShell in ConstrainedLanguage mode, so some code paths
(.NET types, `[scriptblock]::Create`, `List[object]`, `Stopwatch`, `FileStream`, the quoted-CSV parser) were never
run there. This was a run in **FullLanguage** to check them.

| Branch | Commit | Result |
|---|---|---|
| `main` | `c3e64d7` | **91/91 checks pass** |
| `discovery-v1.2` | `3c3be7d` | **92/92 checks pass, plus 1 known issue** (finding 1 below) |

Environment: PowerShell 7.6.7 on Linux (FullLanguage), Pester 5.7.1, PSScriptAnalyzer 1.25.

## What was run

1. **Parse + lint.** All three scripts parse with no errors. PSScriptAnalyzer: no PowerShell 5.1 syntax
   incompatibilities (`PSUseCompatibleSyntax`, target 5.1). The only warnings are style warnings
   (`Write-Host`, empty `catch`) and false positives on the scripts' own `Write-Log` function.
2. **`tests/Test-Helpers.ps1`** (v1.2 branch): **30 PASS, 0 FAIL, 0 SKIP.** Under FullLanguage the quoted-field
   `Split-CsvLine` cases, which are skipped under ConstrainedLanguage, run and pass.
3. **`tests/harness/Helpers.Tests.ps1`** (new, Pester): **47/47 pass** on both branches. It covers
   `ConvertTo-UncPath`, `Get-EndpointIp`, `Test-MicrosoftIP` (CIDR math: /0, /1, /32, range edges, IPv6, junk),
   `Find-FieldIndex`, `Test-InternalRecipient` (wildcard domains, look-alike domains), `Get-AccountDisabled`,
   Entra `Get-ParamValue` (list and dictionary styles), `ConvertTo-FlatValue`, and `Open-LogReader` reading a file
   another handle still has open for writing.
4. **End-to-end runs of all three scripts** (`tests/harness/Run-AllTests.ps1`) under a harness that stubs every
   Exchange, Graph, ADSync and Windows-only command with realistic fake data, plus a generated fake Exchange
   server folder (message tracking, SMTP receive protocol logs, POP3/IMAP4, HttpProxy and IIS logs,
   `applicationHost.config`). Each run checks the exit code, unhandled errors, the Manifest status of each section,
   the RunLog messages, specific values in the output CSVs, and that the ZIP is written.

### Scenarios

| Scenario | What it exercises | main | v1.2 |
|---|---|---|---|
| `exo-full` | sign-in, Graph, 90-day `Get-MessageTraceV2` with a 5000-row page (paging), a throttled request (wait + retry), `-IncludeTestModeConnectors` rejected (fallback), audit log ReturnLargeSet paging, DNS/DKIM assessment, Purview | 23/23 collected | 25/25 collected |
| `exo-legacy-trace` | session already open (reused; UPN mismatch warning), only `Get-MessageTrace` available (10-day cap, page-number paging), `-SkipGraph`, Purview role missing | ✓ | ✓ |
| `exo-no-module` / `exo-old-module` / `exo-connect-fail` | exits cleanly with the right message and no output | ✓ | ✓ |
| `exo-no-dns-no-audit` | `Resolve-DnsName` and `Search-UnifiedAuditLog` absent, `-SkipMessageTrace`, `-SkipCompliance` | ✓ | ✓ |
| `entra-full` | connectors (list- and dictionary-style parameters), OU filtering, sync rules, writeback flows, optional features, company feature, run history, event log | 8/8 collected | 8/8 collected |
| `entra-no-adsync` | ADSync module missing: 6 sections skipped, 2 still collected | ✓ | ✓ |
| `onprem-full` | 3 servers (local, remote, Edge), all log parsers, M365 IP tagging, permissions, remote mailboxes, DNS + PTR, prerequisites summary | 46/47 collected* | 49/51 collected* |
| `onprem-switches` | `-SkipRemoteServers -TrackingDays 7 -IncludeSubjects -IncludeBackEndIisLogs`, no internet (IsMicrosoftIP blank) | ✓ | ✓ (HttpProxy parser exercised here) |
| `onprem-no-exchange` | Exchange cmdlets not loadable: clean exit | ✓ | ✓ |
| `onprem-skips-no-install-path` | `-SkipTrackingLogs -SkipProtocolLogs -SkipIisLogs`, no `ExchangeInstallPath` | ✓ | ✓ |

\* `Topology-ActiveDirectory` fails off Windows because `[ADSI]` and `System.DirectoryServices` do not exist there.
That is expected and is not a script bug. The code was reviewed by reading only (see the limitations below). The
second v1.2 failure is finding 1.

Parser checks that passed:
- **SMTP receive logs:** the authenticated account (`*,DOMAIN\user,authenticated`), STARTTLS / X-ANONYMOUSTLS,
  TLS lines containing quoted commas, IPv6 `[addr]:port`, relay sessions with several MAIL FROM commands.
- **POP3/IMAP4 logs:** columns found from the `#Fields` header, and the default column positions when the header
  is missing.
- **IIS logs:** probes and HealthMailbox requests filtered out; ExchangeServicesClient kept; files older than
  `-IisDays` ignored; the Back End site skipped unless `-IncludeBackEndIisLogs` is given.
- **HttpProxy logs (v1.2):** the target found from `mailboxId=<guid>` or `AnchorMailbox`, quoted user agents
  containing commas, IPv6 client addresses.
- **Message tracking:** wildcard accepted domains counted as internal, subjects only with `-IncludeSubjects`
  (cut to 60 characters), HealthMailbox deliveries excluded.

## Findings

None of these stops a run. Line numbers are from `discovery-v1.2`.

1. **v1.2: `Evidence-HttpProxyLogs` fails as a whole when one remote server's path cannot be converted to UNC.**
   *Low severity on Windows, real robustness bug.*
   `Get-ExchOnPremDecomInventory.ps1:1588`: `ConvertTo-UncPath` returns `$null` when the local install path is not
   `X:\...`, and `Get-ChildItem -LiteralPath $null` throws a parameter-binding error. `-ErrorAction SilentlyContinue`
   does not stop that error, so the section is marked Failed and the **local** server's HttpProxy results are lost
   too. On a normal Windows install the path is `C:\...`, so this rarely triggers, but every other log section
   already guards against an empty path (`Get-DirStats` checks `-not $Path`). Suggested fix:
   ```powershell
   $root = $(if ($s.Name -eq $script:LocalServer) { $localRoot } else { ConvertTo-UncPath $s.Name $localRoot })
   if (-not $root) { Write-Log "  HttpProxy path for $($s.Name) is not a drive path; skipped" 'WARN'; continue }
   ```
2. **EXO: the Security & Compliance session is left connected when an Exchange Online session was reused.**
   `Get-EXODecomInventory.ps1:896` opens it with `Connect-IPPSSession`, but the disconnect at `:921` only runs when
   `$script:WeConnectedExo` is true. This goes against the v1.1 note "Sessions are only disconnected at the end if
   this script opened them": the script opened the IPPS session but does not close it. A
   `$script:WeConnectedIpps` flag would fix it.
3. **Entra: `AnchorAttribute` shows `:` instead of blank** for connectors with no `AnchorConstructionSettings`
   (`Get-EntraConnectDecomInventory.ps1:203`). Piping `$null` into `ForEach-Object` runs the block once. Wrapping
   it as `@($c.AnchorConstructionSettings | Where-Object { $_ } | ForEach-Object ...)` fixes it.
4. **On-prem: `LatestHotfix` uses the culture date format** (`KB5044277 10/13/2026 17:06:56`)
   (`Get-ExchOnPremDecomInventory.ps1:1663`), unlike the `yyyy-MM-dd HH:mm:ss` used everywhere else. Cosmetic.
5. **On-prem DNS also queries `*.onmicrosoft.com` accepted domains** (`:1798`); the EXO script excludes them. Some
   host names are also resolved twice (once from the `mail.<domain>` list, once from the connector/vdir "extra"
   list). This only adds harmless extra rows.
6. **On-prem under PowerShell 7:** `Get-Service -ComputerName` (`:762`, `:1089`) does not exist in PS 7, so the
   POP/IMAP service state of remote servers shows `n/a`. Not an issue in the Exchange Management Shell
   (Windows PowerShell 5.1), which is what the README tells people to use.

## Limitations (what this run cannot show)

- Nothing real was contacted. Real Exchange, Graph and Purview responses, permission errors and throttling
  behaviour are simulated.
- `[ADSI]` / `System.DirectoryServices` (`Topology-ActiveDirectory`, and the forest parts of
  `Topology-ForestExchangePresence` in v1.2) only run on Windows.
- Reading other servers' logs over `\\server\C$` was not exercised on Linux, apart from the "not readable" path.
- Real Windows cmdlets (`Get-CimInstance`, `Get-Service`, `Get-WinEvent`, `Get-ScheduledTask`, `Get-NetTCPConnection`,
  registry reads) were stubbed.
- One run on a real Windows Exchange server (and a real Entra Connect server) is still the final check.

## How to run

```bash
pwsh -NoProfile -File tests/harness/Run-AllTests.ps1
pwsh -NoProfile -File tests/harness/Run-AllTests.ps1 -Only 'onprem-*'
```

PowerShell 7 in FullLanguage is required. Pester 5 is optional; without it the Pester suite is reported as SKIP.
The runner is written for Linux/macOS pwsh, where none of the real Exchange or Windows cmdlets exist. On Windows
the real cmdlets would be used instead of the stubs, and the results would differ.
Output goes to a new temp folder (`-WorkDir` to choose one): one folder per scenario with the script's normal
output, `*.console.txt`, and `TestResults.csv`. Exit code = number of failed checks. All data is fictitious
(contoso.com, RFC 5737 / private addresses). Nothing is sent anywhere.

Files in `tests/harness/`:

| File | Purpose |
|---|---|
| `Run-AllTests.ps1` | builds the fake modules and fake server, runs every scenario, checks the results |
| `Harness.ps1` | runs one script with every missing command stubbed (finds them from the script's AST) |
| `Fixtures-EXO.ps1` | Exchange Online, Graph, message trace, audit log and DNS fake data |
| `Fixtures-Entra.ps1` | ADSync fake data, plus the Windows bits (CIM, services, registry, scheduled tasks, event log) |
| `Fixtures-OnPrem.ps1` | on-prem Exchange fake data (servers, databases, mailboxes, connectors, tracking log, network) |
| `Helpers.Tests.ps1` | Pester unit tests for the pure helper functions (extracted from the scripts via the AST) |
