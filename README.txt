Exchange decommission inventory scripts
=======================================

All three scripts are read-only. Each one writes a timestamped folder and a ZIP of
that folder next to the script (or C:\DecomInventory, then %TEMP%, if the script
folder is not writable). Manifest.csv in each output lists every section as
Collected / Skipped / Failed with the reason. Change notes are at the top of each script.
Nothing is emailed or uploaded; the reports are only saved locally.

  Get-ExchOnPremDecomInventory.ps1     on-prem Exchange - run on an Exchange server
  Get-EntraConnectDecomInventory.ps1   run on the Entra Connect (Azure AD Connect) server
  Get-EXODecomInventory.ps1            Exchange Online - any Windows machine with internet access


Before running (once per machine, in the PowerShell window you will use)
-------------------------------------------------------------------------
Scripts copied from email or a download can be blocked by Windows. Run:

    Unblock-File .\*.ps1
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

The second command applies to the current window only.


1. On-prem Exchange
-------------------
Where:    one Exchange server, in the Exchange Management Shell opened with
          "Run as administrator".
Account:  member of Organization Management, and local administrator on the
          Exchange servers.
Run:      .\Get-ExchOnPremDecomInventory.ps1

Log files on the other Exchange servers are read over the admin share (\\server\C$).
If that is blocked, run the script on every Exchange server with:
          .\Get-ExchOnPremDecomInventory.ps1 -SkipRemoteServers

Run time is minutes to several hours; message tracking and IIS log analysis take
most of it. Keep the window open. To shorten it:
          .\Get-ExchOnPremDecomInventory.ps1 -TrackingDays 30 -IisDays 30

Message subjects are not collected unless -IncludeSubjects is added.


2. Entra Connect
----------------
Where:    the Entra Connect server, PowerShell opened with "Run as administrator".
Account:  local administrator, or a member of the ADSyncAdmins group.
Run:      .\Get-EntraConnectDecomInventory.ps1


3. Exchange Online
------------------
Where:    any Windows machine with internet access.
Needs:    Install-Module ExchangeOnlineManagement -Scope CurrentUser     (version 3.x)
          Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   (optional:
          licensing and directory sync status)
Account:  Exchange Administrator, or Global Reader. The audit log section needs the
          View-Only Audit Logs role; the retention section needs read access in
          Microsoft Purview. Sections the account cannot read are recorded in Manifest.csv.
Run:      .\Get-EXODecomInventory.ps1 -UserPrincipalName admin@customer.com

Expect up to three sign-in prompts: Exchange Online, Microsoft Graph, and
Security & Compliance.

The message trace covers the last 90 days and can take hours in a busy tenant.
To shorten it:
          .\Get-EXODecomInventory.ps1 -UserPrincipalName admin@customer.com -MessageTraceDays 30


What to return
--------------
  DecomInventory_OnPrem_<server>_<timestamp>.zip        (one per server it was run on)
  DecomInventory_EntraConnect_<server>_<timestamp>.zip
  DecomInventory_EXO_<timestamp>.zip

The files contain names, email addresses, IP addresses and configuration details.
Transfer them through the customer's approved channel.
