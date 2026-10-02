<#
.SYNOPSIS
    Windows Day 1 Environment Assessment

.DESCRIPTION
    Collects non-invasive information from the local Windows computer and
    exports the results to HTML, JSON, and text files.

    This script does NOT scan subnets, enumerate remote systems, or attempt
    to bypass access controls.

.NOTES
    Run in PowerShell 5.1 or PowerShell 7+.
    Administrator rights are optional, but some sections may contain more
    information when the script is run as Administrator.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:USERPROFILE\Documents\Windows_Environment_Assessment",
    [switch]$IncludeInstalledSoftware,
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Get-SafeData {
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory)]
        [string]$SectionName
    )

    try {
        & $ScriptBlock
    }
    catch {
        [pscustomobject]@{
            Status  = "Unavailable"
            Section = $SectionName
            Error   = $_.Exception.Message
        }
    }
}

function Convert-ToDisplayText {
    param([object]$InputObject)

    if ($null -eq $InputObject) {
        return "No data returned."
    }

    return ($InputObject | Format-List * | Out-String -Width 240).Trim()
}

function Test-IsAdministrator {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        return $false
    }
}

function Get-InstalledSecurityProducts {
    $results = New-Object System.Collections.Generic.List[object]

    # Windows Security Center registered products
    try {
        $products = Get-CimInstance `
            -Namespace "root/SecurityCenter2" `
            -ClassName AntiVirusProduct `
            -ErrorAction Stop

        foreach ($product in $products) {
            $results.Add([pscustomobject]@{
                Source       = "Windows Security Center"
                ProductName  = $product.displayName
                Executable   = $product.pathToSignedProductExe
                ProductState = $product.productState
            })
        }
    }
    catch {
        $results.Add([pscustomobject]@{
            Source       = "Windows Security Center"
            ProductName  = "Unable to query"
            Executable   = ""
            ProductState = $_.Exception.Message
        })
    }

    # Common endpoint-management and security services
    $patterns = @(
        "Sentinel", "CrowdStrike", "Falcon", "Defender", "Sophos",
        "Carbon Black", "Cylance", "Tanium", "Ninja", "Automox",
        "ConnectWise", "ScreenConnect", "Splashtop", "Kaseya",
        "Datto", "ManageEngine", "PDQ", "Qualys", "Rapid7",
        "GlobalProtect", "Cisco Secure", "AnyConnect", "Zscaler"
    )

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop

        foreach ($service in $services) {
            $matched = $false

            foreach ($pattern in $patterns) {
                if (
                    $service.Name -like "*$pattern*" -or
                    $service.DisplayName -like "*$pattern*" -or
                    $service.PathName -like "*$pattern*"
                ) {
                    $matched = $true
                    break
                }
            }

            if ($matched) {
                $results.Add([pscustomobject]@{
                    Source       = "Windows Service"
                    ProductName  = $service.DisplayName
                    Executable   = $service.PathName
                    ProductState = $service.State
                })
            }
        }
    }
    catch {
        $results.Add([pscustomobject]@{
            Source       = "Windows Service"
            ProductName  = "Unable to query"
            Executable   = ""
            ProductState = $_.Exception.Message
        })
    }

    return $results | Sort-Object Source, ProductName -Unique
}

# ---------------------------------------------------------------------------
# Initialize report folder
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$computerName = $env:COMPUTERNAME
$outputFolder = Join-Path $OutputRoot "${computerName}_$timestamp"

New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null

$reportPath = Join-Path $outputFolder "Environment_Assessment.html"
$jsonPath   = Join-Path $outputFolder "Environment_Assessment.json"
$summaryPath = Join-Path $outputFolder "Quick_Summary.txt"
$gpoPath = Join-Path $outputFolder "Group_Policy_Report.html"

$isAdmin = Test-IsAdministrator

# ---------------------------------------------------------------------------
# Collect information
# ---------------------------------------------------------------------------

$assessment = [ordered]@{}

$assessment["Assessment Metadata"] = [pscustomobject]@{
    ComputerName    = $computerName
    CollectedAt     = Get-Date
    CollectedBy     = "$env:USERDOMAIN\$env:USERNAME"
    PowerShell      = $PSVersionTable.PSVersion.ToString()
    IsAdministrator = $isAdmin
    OutputFolder    = $outputFolder
}

$assessment["Computer System"] = Get-SafeData -SectionName "Computer System" -ScriptBlock {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, Name, Domain, Workgroup,
            PartOfDomain, SystemType, TotalPhysicalMemory, UserName
}

$assessment["Operating System"] = Get-SafeData -SectionName "Operating System" -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture,
            InstallDate, LastBootUpTime, LocalDateTime, WindowsDirectory
}

$assessment["BIOS"] = Get-SafeData -SectionName "BIOS" -ScriptBlock {
    Get-CimInstance Win32_BIOS |
        Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber,
            ReleaseDate
}

$assessment["Physical Memory"] = Get-SafeData -SectionName "Physical Memory" -ScriptBlock {
    Get-CimInstance Win32_PhysicalMemory |
        Select-Object BankLabel, DeviceLocator, Manufacturer,
            @{Name="CapacityGB";Expression={[math]::Round($_.Capacity / 1GB, 2)}},
            Speed, PartNumber, SerialNumber
}

$assessment["Disk Volumes"] = Get-SafeData -SectionName "Disk Volumes" -ScriptBlock {
    Get-CimInstance Win32_LogicalDisk |
        Select-Object DeviceID, VolumeName, FileSystem, DriveType,
            @{Name="SizeGB";Expression={
                if ($_.Size) {[math]::Round($_.Size / 1GB, 2)}
            }},
            @{Name="FreeGB";Expression={
                if ($_.FreeSpace) {[math]::Round($_.FreeSpace / 1GB, 2)}
            }},
            @{Name="PercentFree";Expression={
                if ($_.Size -gt 0) {
                    [math]::Round(($_.FreeSpace / $_.Size) * 100, 1)
                }
            }}
}

$assessment["Network Adapters"] = Get-SafeData -SectionName "Network Adapters" -ScriptBlock {
    Get-NetAdapter |
        Select-Object Name, InterfaceDescription, Status, LinkSpeed,
            MacAddress, MediaType, PhysicalMediaType, ifIndex
}

$assessment["IP Configuration"] = Get-SafeData -SectionName "IP Configuration" -ScriptBlock {
    Get-NetIPConfiguration -Detailed |
        Select-Object InterfaceAlias, InterfaceDescription, NetProfile,
            IPv4Address, IPv6Address, IPv4DefaultGateway, IPv6DefaultGateway,
            DNSServer, NetAdapter
}

$assessment["IP Addresses"] = Get-SafeData -SectionName "IP Addresses" -ScriptBlock {
    Get-NetIPAddress |
        Where-Object {
            $_.AddressState -eq "Preferred" -and
            $_.IPAddress -notlike "fe80:*"
        } |
        Select-Object InterfaceAlias, AddressFamily, IPAddress,
            PrefixLength, Type, PrefixOrigin, SuffixOrigin
}

$assessment["DNS Client Servers"] = Get-SafeData -SectionName "DNS Client Servers" -ScriptBlock {
    Get-DnsClientServerAddress |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily,
            ServerAddresses
}

$assessment["DNS Client Settings"] = Get-SafeData -SectionName "DNS Client Settings" -ScriptBlock {
    Get-DnsClient |
        Select-Object InterfaceAlias, ConnectionSpecificSuffix,
            RegisterThisConnectionsAddress, UseSuffixWhenRegistering
}

$assessment["Routes"] = Get-SafeData -SectionName "Routes" -ScriptBlock {
    Get-NetRoute |
        Where-Object {
            $_.State -eq "Alive" -or $_.State -eq $null
        } |
        Sort-Object AddressFamily, RouteMetric, DestinationPrefix |
        Select-Object AddressFamily, DestinationPrefix, NextHop,
            InterfaceAlias, RouteMetric, Protocol
}

$assessment["Network Profiles"] = Get-SafeData -SectionName "Network Profiles" -ScriptBlock {
    Get-NetConnectionProfile |
        Select-Object Name, InterfaceAlias, InterfaceIndex,
            NetworkCategory, IPv4Connectivity, IPv6Connectivity
}

$assessment["Wi-Fi Interface"] = Get-SafeData -SectionName "Wi-Fi Interface" -ScriptBlock {
    $output = netsh wlan show interfaces 2>&1
    [pscustomobject]@{
        Details = ($output -join [Environment]::NewLine)
    }
}

$assessment["Wi-Fi Profiles"] = Get-SafeData -SectionName "Wi-Fi Profiles" -ScriptBlock {
    $output = netsh wlan show profiles 2>&1
    [pscustomobject]@{
        Details = ($output -join [Environment]::NewLine)
    }
}

$assessment["Domain and Logon"] = Get-SafeData -SectionName "Domain and Logon" -ScriptBlock {
    [pscustomobject]@{
        UserDomain       = $env:USERDOMAIN
        UserDNSDomain    = $env:USERDNSDOMAIN
        LogonServer      = $env:LOGONSERVER
        ComputerDomain   = (Get-CimInstance Win32_ComputerSystem).Domain
        PartOfDomain     = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
        CurrentUser      = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Authentication   = [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
    }
}

$assessment["Entra and Device Registration"] = Get-SafeData `
    -SectionName "Entra and Device Registration" `
    -ScriptBlock {
        $output = dsregcmd /status 2>&1
        [pscustomobject]@{
            Details = ($output -join [Environment]::NewLine)
        }
    }

$assessment["Mapped Drives"] = Get-SafeData -SectionName "Mapped Drives" -ScriptBlock {
    Get-CimInstance Win32_LogicalDisk |
        Where-Object { $_.DriveType -eq 4 } |
        Select-Object DeviceID, ProviderName, VolumeName, FileSystem
}

$assessment["SMB Connections"] = Get-SafeData -SectionName "SMB Connections" -ScriptBlock {
    Get-SmbConnection |
        Select-Object ServerName, ShareName, UserName, Credential,
            Dialect, NumOpens, Encrypted
}

$assessment["Printers"] = Get-SafeData -SectionName "Printers" -ScriptBlock {
    Get-Printer |
        Select-Object Name, DriverName, PortName, Type,
            Shared, Published, ComputerName
}

$assessment["Printer Ports"] = Get-SafeData -SectionName "Printer Ports" -ScriptBlock {
    Get-PrinterPort |
        Select-Object Name, Description, PrinterHostAddress,
            PortNumber, Protocol, SNMPEnabled
}

$assessment["Firewall Profiles"] = Get-SafeData -SectionName "Firewall Profiles" -ScriptBlock {
    Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction,
            DefaultOutboundAction, AllowInboundRules,
            AllowLocalFirewallRules, NotifyOnListen
}

$assessment["BitLocker"] = Get-SafeData -SectionName "BitLocker" -ScriptBlock {
    Get-BitLockerVolume |
        Select-Object MountPoint, VolumeType, VolumeStatus,
            ProtectionStatus, EncryptionMethod, EncryptionPercentage,
            AutoUnlockEnabled
}

$assessment["Windows Defender"] = Get-SafeData -SectionName "Windows Defender" -ScriptBlock {
    Get-MpComputerStatus |
        Select-Object AMServiceEnabled, AntivirusEnabled,
            AntispywareEnabled, BehaviorMonitorEnabled,
            IoavProtectionEnabled, NISEnabled,
            OnAccessProtectionEnabled, RealTimeProtectionEnabled,
            AntivirusSignatureLastUpdated, QuickScanEndTime,
            FullScanEndTime
}

$assessment["Security and Management Products"] = Get-SafeData `
    -SectionName "Security and Management Products" `
    -ScriptBlock {
        Get-InstalledSecurityProducts
    }

$assessment["Certificates - Local Computer Personal"] = Get-SafeData `
    -SectionName "Certificates - Local Computer Personal" `
    -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\My |
            Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter,
                HasPrivateKey, EnhancedKeyUsageList
    }

$assessment["Certificates - Trusted Roots"] = Get-SafeData `
    -SectionName "Certificates - Trusted Roots" `
    -ScriptBlock {
        Get-ChildItem Cert:\LocalMachine\Root |
            Where-Object {
                $_.Subject -notlike "*Microsoft*" -and
                $_.Subject -notlike "*DigiCert*" -and
                $_.Subject -notlike "*GlobalSign*" -and
                $_.Subject -notlike "*Entrust*" -and
                $_.Subject -notlike "*Amazon*"
            } |
            Select-Object Subject, Issuer, Thumbprint, NotBefore, NotAfter
    }

$assessment["Services - Automatic but Stopped"] = Get-SafeData `
    -SectionName "Services - Automatic but Stopped" `
    -ScriptBlock {
        Get-CimInstance Win32_Service |
            Where-Object {
                $_.StartMode -eq "Auto" -and $_.State -ne "Running"
            } |
            Select-Object Name, DisplayName, State, StartMode, StartName
    }

$assessment["Recent System Errors"] = Get-SafeData `
    -SectionName "Recent System Errors" `
    -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Level     = 2
            StartTime = (Get-Date).AddDays(-3)
        } -MaxEvents 50 |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
                Message
    }

$assessment["Recent Application Errors"] = Get-SafeData `
    -SectionName "Recent Application Errors" `
    -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = "Application"
            Level     = 2
            StartTime = (Get-Date).AddDays(-3)
        } -MaxEvents 50 |
            Select-Object TimeCreated, Id, ProviderName, LevelDisplayName,
                Message
    }

if ($IncludeInstalledSoftware) {
    $assessment["Installed Software"] = Get-SafeData `
        -SectionName "Installed Software" `
        -ScriptBlock {
            $registryPaths = @(
                "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
                "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )

            Get-ItemProperty $registryPaths -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher,
                    InstallDate, InstallLocation |
                Sort-Object DisplayName -Unique
        }
}

# Generate a full Group Policy HTML report separately.
$assessment["Group Policy"] = Get-SafeData -SectionName "Group Policy" -ScriptBlock {
    $gpResult = gpresult /r 2>&1

    try {
        gpresult /h $gpoPath /f | Out-Null
        $htmlStatus = "Created: $gpoPath"
    }
    catch {
        $htmlStatus = "Could not create HTML GPO report: $($_.Exception.Message)"
    }

    [pscustomobject]@{
        Summary          = ($gpResult -join [Environment]::NewLine)
        DetailedHTMLFile = $htmlStatus
    }
}

# ---------------------------------------------------------------------------
# Create HTML report
# ---------------------------------------------------------------------------

$css = @"
<style>
    body {
        font-family: "Segoe UI", Arial, sans-serif;
        margin: 28px;
        background: #f3f5f7;
        color: #1f2933;
    }

    h1 {
        margin-bottom: 4px;
    }

    .subtitle {
        color: #52606d;
        margin-bottom: 24px;
    }

    .notice {
        background: #fff8db;
        border-left: 5px solid #d6a700;
        padding: 12px 16px;
        margin-bottom: 20px;
    }

    details {
        background: white;
        border: 1px solid #d9e2ec;
        border-radius: 8px;
        margin-bottom: 12px;
        padding: 10px 14px;
    }

    summary {
        cursor: pointer;
        font-weight: 600;
        font-size: 16px;
    }

    pre {
        white-space: pre-wrap;
        word-wrap: break-word;
        background: #f7f9fb;
        border: 1px solid #e4e7eb;
        border-radius: 6px;
        padding: 12px;
        overflow-x: auto;
    }

    table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 10px;
        font-size: 13px;
    }

    th, td {
        border: 1px solid #d9e2ec;
        padding: 7px;
        text-align: left;
        vertical-align: top;
    }

    th {
        background: #e9eef3;
    }

    .footer {
        margin-top: 22px;
        color: #7b8794;
        font-size: 12px;
    }
</style>
"@

$htmlSections = New-Object System.Collections.Generic.List[string]

foreach ($section in $assessment.GetEnumerator()) {
    $sectionName = [System.Net.WebUtility]::HtmlEncode($section.Key)
    $sectionData = $section.Value

    try {
        if (
            $sectionData -is [string] -or
            (
                $sectionData.PSObject.Properties.Name -contains "Details" -and
                $sectionData.PSObject.Properties.Count -le 3
            )
        ) {
            $text = Convert-ToDisplayText $sectionData
            $encoded = [System.Net.WebUtility]::HtmlEncode($text)
            $content = "<pre>$encoded</pre>"
        }
        else {
            $content = $sectionData |
                ConvertTo-Html -Fragment |
                Out-String
        }
    }
    catch {
        $encoded = [System.Net.WebUtility]::HtmlEncode(
            (Convert-ToDisplayText $sectionData)
        )
        $content = "<pre>$encoded</pre>"
    }

    $htmlSections.Add(
        "<details><summary>$sectionName</summary>$content</details>"
    )
}

$adminMessage = if ($isAdmin) {
    "The script was run with Administrator rights."
}
else {
    "The script was not run as Administrator. Some sections may be incomplete."
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Windows Environment Assessment - $computerName</title>
$css
</head>
<body>
<h1>Windows Environment Assessment</h1>
<div class="subtitle">
    Computer: $computerName<br>
    Collected: $(Get-Date)<br>
    User: $env:USERDOMAIN\$env:USERNAME
</div>

<div class="notice">
    $adminMessage This report may contain internal hostnames, IP addresses,
    usernames, certificate details, and security-product information.
    Store and share it according to company policy.
</div>

$($htmlSections -join [Environment]::NewLine)

<div class="footer">
    Generated by Windows Day 1 Environment Assessment.
</div>
</body>
</html>
"@

$html | Set-Content -Path $reportPath -Encoding UTF8

# JSON is useful for future comparison, automation, and parsing.
$assessment |
    ConvertTo-Json -Depth 8 |
    Set-Content -Path $jsonPath -Encoding UTF8

# ---------------------------------------------------------------------------
# Create quick summary
# ---------------------------------------------------------------------------

$ipSummary = Get-SafeData -SectionName "Quick IP Summary" -ScriptBlock {
    Get-NetIPConfiguration |
        Where-Object { $_.IPv4Address } |
        ForEach-Object {
            [pscustomobject]@{
                Interface = $_.InterfaceAlias
                IPv4      = ($_.IPv4Address.IPAddress -join ", ")
                Gateway   = ($_.IPv4DefaultGateway.NextHop -join ", ")
                DNS       = ($_.DNSServer.ServerAddresses -join ", ")
            }
        }
}

$wifiSummary = Get-SafeData -SectionName "Quick Wi-Fi Summary" -ScriptBlock {
    netsh wlan show interfaces 2>&1 |
        Select-String "^\s*(Name|Description|State|SSID|BSSID|Radio type|Authentication|Cipher|Channel|Receive rate|Transmit rate|Signal)\s*:"
}

$summary = @"
WINDOWS ENVIRONMENT ASSESSMENT
==============================

Computer:        $computerName
User:            $env:USERDOMAIN\$env:USERNAME
Date:            $(Get-Date)
Administrator:   $isAdmin

NETWORK SUMMARY
---------------
$(Convert-ToDisplayText $ipSummary)

WI-FI SUMMARY
-------------
$($wifiSummary | Out-String)

FILES
-----
HTML Report:     $reportPath
JSON Data:       $jsonPath
Group Policy:    $gpoPath

IMPORTANT
---------
This report can contain confidential internal IT information. Store and share
it only according to your employer's policies.
"@

$summary | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Assessment complete." -ForegroundColor Green
Write-Host "Output folder: $outputFolder"
Write-Host "HTML report:  $reportPath"
Write-Host "JSON data:    $jsonPath"
Write-Host "Quick summary: $summaryPath"
Write-Host ""

if ($OpenReport) {
    Start-Process $reportPath
}
