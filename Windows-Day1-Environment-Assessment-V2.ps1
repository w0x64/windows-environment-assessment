<#
.SYNOPSIS
    Windows Day 1 Environment Assessment - Version 2

.DESCRIPTION
    Collects local Windows environment information and can optionally perform
    a controlled, authorized discovery scan of a specified IPv4 subnet.

    The network-discovery features are OFF by default.

    This script does NOT:
      - Attempt passwords or credentials
      - Exploit vulnerabilities
      - Evade detection
      - Perform stealth scanning
      - Modify remote systems
      - Enumerate remote shares, users, or sensitive data
      - Automatically scan a subnet without explicit operator input

.NOTES
    Use only on networks you own or are explicitly authorized to assess.
    PowerShell 5.1 or PowerShell 7+ supported.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = "$env:USERPROFILE\Documents\Windows_Environment_Assessment",

    [switch]$IncludeInstalledSoftware,

    [switch]$OpenReport,

    [switch]$EnableNetworkDiscovery,

    [string]$TargetSubnet,

    [ValidateRange(50, 5000)]
    [int]$PingTimeoutMs = 500,

    [ValidateRange(1, 128)]
    [int]$MaxConcurrentChecks = 24,

    [ValidateRange(1, 65535)]
    [int[]]$Ports = @(53, 80, 88, 135, 139, 389, 443, 445, 636, 3389, 5985, 5986),

    [ValidateRange(1, 4096)]
    [int]$MaxHosts = 512
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

    return ($InputObject | Format-List * | Out-String -Width 260).Trim()
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

function Convert-IPv4ToUInt32 {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress
    )

    $bytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-UInt32ToIPv4 {
    param(
        [Parameter(Mandatory)]
        [uint32]$Value
    )

    $bytes = [BitConverter]::GetBytes($Value)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-IPv4RangeFromCIDR {
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,

        [Parameter(Mandatory)]
        [int]$MaximumHosts
    )

    if ($CIDR -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d|[12]\d|3[0-2])$') {
        throw "TargetSubnet must use IPv4 CIDR notation, such as 192.168.10.0/24."
    }

    $ipString = $Matches[1]
    $prefixLength = [int]$Matches[2]

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($ipString, [ref]$parsed)) {
        throw "Invalid IPv4 address in TargetSubnet."
    }

    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        throw "Only IPv4 subnets are supported."
    }

    $octets = $ipString.Split('.') | ForEach-Object { [int]$_ }
    if ($octets | Where-Object { $_ -lt 0 -or $_ -gt 255 }) {
        throw "Invalid IPv4 octet in TargetSubnet."
    }

    $ipValue = Convert-IPv4ToUInt32 -IPAddress $ipString

    $mask = if ($prefixLength -eq 0) {
        [uint32]0
    }
    else {
        [uint32]([uint64]0xFFFFFFFF -shl (32 - $prefixLength))
    }

    $network = [uint32]($ipValue -band $mask)
    $broadcast = [uint32]($network -bor (-bnot $mask))

    if ($prefixLength -eq 32) {
        $first = $network
        $last = $network
    }
    elseif ($prefixLength -eq 31) {
        $first = $network
        $last = $broadcast
    }
    else {
        $first = [uint32]($network + 1)
        $last = [uint32]($broadcast - 1)
    }

    $hostCount = [uint64]$last - [uint64]$first + 1

    if ($hostCount -gt $MaximumHosts) {
        throw "Subnet contains $hostCount usable addresses, exceeding MaxHosts=$MaximumHosts. Use a smaller subnet or intentionally raise MaxHosts."
    }

    $addresses = New-Object System.Collections.Generic.List[string]

    for ($current = [uint64]$first; $current -le [uint64]$last; $current++) {
        $addresses.Add((Convert-UInt32ToIPv4 -Value ([uint32]$current)))
    }

    return [pscustomobject]@{
        CIDR          = $CIDR
        PrefixLength  = $prefixLength
        Network       = Convert-UInt32ToIPv4 -Value $network
        Broadcast     = Convert-UInt32ToIPv4 -Value $broadcast
        UsableHosts   = $hostCount
        Addresses     = $addresses
    }
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory)]
        [string]$IPAddress,

        [Parameter(Mandatory)]
        [int]$Port,

        [Parameter(Mandatory)]
        [int]$TimeoutMs
    )

    $client = New-Object System.Net.Sockets.TcpClient

    try {
        $asyncResult = $client.BeginConnect($IPAddress, $Port, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

        if (-not $connected) {
            return $false
        }

        $client.EndConnect($asyncResult)
        return $client.Connected
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
        $client.Dispose()
    }
}

function Resolve-HostNameSafe {
    param([string]$IPAddress)

    try {
        return ([System.Net.Dns]::GetHostEntry($IPAddress)).HostName
    }
    catch {
        return $null
    }
}

function Get-ArpMacAddress {
    param([string]$IPAddress)

    try {
        $arpOutput = arp -a $IPAddress 2>$null
        $match = $arpOutput | Select-String -Pattern (
            [regex]::Escape($IPAddress) + '\s+([0-9a-fA-F-]{17})'
        ) | Select-Object -First 1

        if ($match -and $match.Matches.Count -gt 0) {
            return $match.Matches[0].Groups[1].Value.ToUpperInvariant()
        }
    }
    catch {
        return $null
    }

    return $null
}

function Invoke-AuthorizedNetworkDiscovery {
    param(
        [Parameter(Mandatory)]
        [string]$Subnet,

        [Parameter(Mandatory)]
        [int[]]$TargetPorts,

        [Parameter(Mandatory)]
        [int]$TimeoutMs,

        [Parameter(Mandatory)]
        [int]$ThrottleLimit,

        [Parameter(Mandatory)]
        [int]$MaximumHosts
    )

    $range = Get-IPv4RangeFromCIDR -CIDR $Subnet -MaximumHosts $MaximumHosts
    $results = New-Object System.Collections.Generic.List[object]

    Write-Host ""
    Write-Host "AUTHORIZED NETWORK DISCOVERY ENABLED" -ForegroundColor Yellow
    Write-Host "Target subnet: $($range.CIDR)"
    Write-Host "Usable addresses: $($range.UsableHosts)"
    Write-Host "Ports: $($TargetPorts -join ', ')"
    Write-Host ""

    $useParallel = $PSVersionTable.PSVersion.Major -ge 7

    if ($useParallel) {
        $parallelResults = $range.Addresses | ForEach-Object -Parallel {
            $ip = $_
            $timeout = $using:TimeoutMs
            $portsToCheck = $using:TargetPorts

            $reachable = $false
            try {
                $reachable = Test-Connection `
                    -TargetName $ip `
                    -Count 1 `
                    -TimeoutSeconds ([math]::Max(1, [math]::Ceiling($timeout / 1000))) `
                    -Quiet `
                    -ErrorAction SilentlyContinue
            }
            catch {
                $reachable = $false
            }

            $openPorts = New-Object System.Collections.Generic.List[int]

            # Check ports even when ICMP is blocked, because many devices do not reply to ping.
            foreach ($port in $portsToCheck) {
                $client = New-Object System.Net.Sockets.TcpClient

                try {
                    $async = $client.BeginConnect($ip, $port, $null, $null)
                    $ok = $async.AsyncWaitHandle.WaitOne($timeout, $false)

                    if ($ok) {
                        try {
                            $client.EndConnect($async)
                            if ($client.Connected) {
                                $openPorts.Add($port)
                            }
                        }
                        catch {}
                    }
                }
                catch {}
                finally {
                    $client.Close()
                    $client.Dispose()
                }
            }

            if ($reachable -or $openPorts.Count -gt 0) {
                $hostname = $null
                try {
                    $hostname = ([System.Net.Dns]::GetHostEntry($ip)).HostName
                }
                catch {}

                [pscustomobject]@{
                    IPAddress    = $ip
                    ICMPReply    = $reachable
                    HostName     = $hostname
                    OpenPorts    = ($openPorts -join ",")
                    OpenPortCount = $openPorts.Count
                }
            }
        } -ThrottleLimit $ThrottleLimit

        foreach ($item in $parallelResults) {
            if ($null -ne $item) {
                $mac = Get-ArpMacAddress -IPAddress $item.IPAddress

                $results.Add([pscustomobject]@{
                    IPAddress     = $item.IPAddress
                    ICMPReply     = $item.ICMPReply
                    HostName      = $item.HostName
                    MACAddress    = $mac
                    OpenPorts     = $item.OpenPorts
                    OpenPortCount = $item.OpenPortCount
                })
            }
        }
    }
    else {
        $counter = 0

        foreach ($ip in $range.Addresses) {
            $counter++
            Write-Progress `
                -Activity "Authorized network discovery" `
                -Status "$counter of $($range.UsableHosts): $ip" `
                -PercentComplete (($counter / $range.UsableHosts) * 100)

            $reachable = $false

            try {
                $reachable = Test-Connection `
                    -ComputerName $ip `
                    -Count 1 `
                    -Quiet `
                    -ErrorAction SilentlyContinue
            }
            catch {
                $reachable = $false
            }

            $openPorts = New-Object System.Collections.Generic.List[int]

            foreach ($port in $TargetPorts) {
                if (Test-TcpPort -IPAddress $ip -Port $port -TimeoutMs $TimeoutMs) {
                    $openPorts.Add($port)
                }
            }

            if ($reachable -or $openPorts.Count -gt 0) {
                $hostname = Resolve-HostNameSafe -IPAddress $ip
                $mac = Get-ArpMacAddress -IPAddress $ip

                $results.Add([pscustomobject]@{
                    IPAddress     = $ip
                    ICMPReply     = $reachable
                    HostName      = $hostname
                    MACAddress    = $mac
                    OpenPorts     = ($openPorts -join ",")
                    OpenPortCount = $openPorts.Count
                })
            }
        }

        Write-Progress -Activity "Authorized network discovery" -Completed
    }

    return [pscustomobject]@{
        Range   = $range
        Results = $results | Sort-Object {
            [version]$_.IPAddress
        }
    }
}

function Get-InstalledSecurityProducts {
    $results = New-Object System.Collections.Generic.List[object]

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
# Validate discovery request
# ---------------------------------------------------------------------------

if ($EnableNetworkDiscovery -and [string]::IsNullOrWhiteSpace($TargetSubnet)) {
    throw "When EnableNetworkDiscovery is used, TargetSubnet is required. Example: -TargetSubnet 192.168.10.0/24"
}

if (-not $EnableNetworkDiscovery -and -not [string]::IsNullOrWhiteSpace($TargetSubnet)) {
    throw "TargetSubnet was supplied, but EnableNetworkDiscovery was not specified."
}

# ---------------------------------------------------------------------------
# Initialize report folder
# ---------------------------------------------------------------------------

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$computerName = $env:COMPUTERNAME
$outputFolder = Join-Path $OutputRoot "${computerName}_$timestamp"

New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null

$reportPath = Join-Path $outputFolder "Environment_Assessment_V2.html"
$jsonPath = Join-Path $outputFolder "Environment_Assessment_V2.json"
$summaryPath = Join-Path $outputFolder "Quick_Summary_V2.txt"
$gpoPath = Join-Path $outputFolder "Group_Policy_Report.html"
$networkCsvPath = Join-Path $outputFolder "Authorized_Network_Discovery.csv"

$isAdmin = Test-IsAdministrator
$assessment = [ordered]@{}

# ---------------------------------------------------------------------------
# Local assessment
# ---------------------------------------------------------------------------

$assessment["Assessment Metadata"] = [pscustomobject]@{
    Version                 = "2.0"
    ComputerName            = $computerName
    CollectedAt             = Get-Date
    CollectedBy             = "$env:USERDOMAIN\$env:USERNAME"
    PowerShell              = $PSVersionTable.PSVersion.ToString()
    IsAdministrator         = $isAdmin
    NetworkDiscoveryEnabled = [bool]$EnableNetworkDiscovery
    TargetSubnet            = $TargetSubnet
    OutputFolder            = $outputFolder
}

$assessment["Computer System"] = Get-SafeData -SectionName "Computer System" -ScriptBlock {
    Get-CimInstance Win32_ComputerSystem |
        Select-Object Manufacturer, Model, Name, Domain, Workgroup,
            PartOfDomain, SystemType,
            @{Name="TotalPhysicalMemoryGB";Expression={
                [math]::Round($_.TotalPhysicalMemory / 1GB, 2)
            }},
            UserName
}

$assessment["Operating System"] = Get-SafeData -SectionName "Operating System" -ScriptBlock {
    Get-CimInstance Win32_OperatingSystem |
        Select-Object Caption, Version, BuildNumber, OSArchitecture,
            InstallDate, LastBootUpTime, LocalDateTime, WindowsDirectory
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

$assessment["DNS Configuration"] = Get-SafeData -SectionName "DNS Configuration" -ScriptBlock {
    Get-DnsClientServerAddress |
        Where-Object { $_.ServerAddresses.Count -gt 0 } |
        Select-Object InterfaceAlias, InterfaceIndex, AddressFamily,
            ServerAddresses
}

$assessment["Routes"] = Get-SafeData -SectionName "Routes" -ScriptBlock {
    Get-NetRoute |
        Sort-Object AddressFamily, RouteMetric, DestinationPrefix |
        Select-Object AddressFamily, DestinationPrefix, NextHop,
            InterfaceAlias, RouteMetric, Protocol, State
}

$assessment["ARP and Neighbor Cache"] = Get-SafeData -SectionName "ARP and Neighbor Cache" -ScriptBlock {
    Get-NetNeighbor |
        Where-Object {
            $_.State -notin @("Unreachable", "Incomplete") -and
            $_.IPAddress -notlike "ff*"
        } |
        Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State,
            AddressFamily
}

$assessment["Wi-Fi Interface"] = Get-SafeData -SectionName "Wi-Fi Interface" -ScriptBlock {
    [pscustomobject]@{
        Details = ((netsh wlan show interfaces 2>&1) -join [Environment]::NewLine)
    }
}

$assessment["Domain and Logon"] = Get-SafeData -SectionName "Domain and Logon" -ScriptBlock {
    $system = Get-CimInstance Win32_ComputerSystem

    [pscustomobject]@{
        UserDomain     = $env:USERDOMAIN
        UserDNSDomain  = $env:USERDNSDOMAIN
        LogonServer    = $env:LOGONSERVER
        ComputerDomain = $system.Domain
        PartOfDomain   = $system.PartOfDomain
        CurrentUser    = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Authentication = [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
    }
}

$assessment["Entra and Device Registration"] = Get-SafeData `
    -SectionName "Entra and Device Registration" `
    -ScriptBlock {
        [pscustomobject]@{
            Details = ((dsregcmd /status 2>&1) -join [Environment]::NewLine)
        }
    }

$assessment["Mapped Drives"] = Get-SafeData -SectionName "Mapped Drives" -ScriptBlock {
    Get-CimInstance Win32_LogicalDisk |
        Where-Object { $_.DriveType -eq 4 } |
        Select-Object DeviceID, ProviderName, VolumeName, FileSystem
}

$assessment["SMB Connections"] = Get-SafeData -SectionName "SMB Connections" -ScriptBlock {
    Get-SmbConnection |
        Select-Object ServerName, ShareName, UserName, Dialect,
            NumOpens, Encrypted
}

$assessment["Printers"] = Get-SafeData -SectionName "Printers" -ScriptBlock {
    Get-Printer |
        Select-Object Name, DriverName, PortName, Type,
            Shared, Published, ComputerName
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

$assessment["Local Listening TCP Ports"] = Get-SafeData `
    -SectionName "Local Listening TCP Ports" `
    -ScriptBlock {
        Get-NetTCPConnection -State Listen |
            Select-Object LocalAddress, LocalPort, OwningProcess,
                @{Name="ProcessName";Expression={
                    try {
                        (Get-Process -Id $_.OwningProcess -ErrorAction Stop).ProcessName
                    }
                    catch {
                        "Unknown"
                    }
                }} |
            Sort-Object LocalPort
    }

$assessment["Recent System Errors"] = Get-SafeData `
    -SectionName "Recent System Errors" `
    -ScriptBlock {
        Get-WinEvent -FilterHashtable @{
            LogName   = "System"
            Level     = 2
            StartTime = (Get-Date).AddDays(-3)
        } -MaxEvents 50 |
            Select-Object TimeCreated, Id, ProviderName,
                LevelDisplayName, Message
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
# Optional authorized network discovery
# ---------------------------------------------------------------------------

$networkDiscovery = $null

if ($EnableNetworkDiscovery) {
    $networkDiscovery = Invoke-AuthorizedNetworkDiscovery `
        -Subnet $TargetSubnet `
        -TargetPorts $Ports `
        -TimeoutMs $PingTimeoutMs `
        -ThrottleLimit $MaxConcurrentChecks `
        -MaximumHosts $MaxHosts

    $networkDiscovery.Results |
        Export-Csv -Path $networkCsvPath -NoTypeInformation -Encoding UTF8

    $assessment["Authorized Network Discovery Summary"] = [pscustomobject]@{
        TargetSubnet   = $networkDiscovery.Range.CIDR
        NetworkAddress = $networkDiscovery.Range.Network
        Broadcast      = $networkDiscovery.Range.Broadcast
        AddressesTested = $networkDiscovery.Range.UsableHosts
        DevicesFound   = @($networkDiscovery.Results).Count
        PortsChecked   = ($Ports -join ", ")
        CSVFile        = $networkCsvPath
    }

    $assessment["Authorized Network Discovery Results"] = $networkDiscovery.Results
}
else {
    $assessment["Authorized Network Discovery"] = [pscustomobject]@{
        Status = "Disabled"
        Note   = "Run with -EnableNetworkDiscovery and an explicitly authorized -TargetSubnet to enable."
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

    .discovery {
        background: #e8f4fd;
        border-left: 5px solid #2b7bbb;
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

$discoveryMessage = if ($EnableNetworkDiscovery) {
    "Authorized discovery was performed against $TargetSubnet. Devices found: $(@($networkDiscovery.Results).Count)."
}
else {
    "Network discovery was disabled. Only the local computer and its existing network knowledge were assessed."
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Windows Environment Assessment V2 - $computerName</title>
$css
</head>
<body>
<h1>Windows Environment Assessment V2</h1>
<div class="subtitle">
    Computer: $computerName<br>
    Collected: $(Get-Date)<br>
    User: $env:USERDOMAIN\$env:USERNAME
</div>

<div class="notice">
    $adminMessage This report may contain confidential internal hostnames,
    IP addresses, usernames, certificate details, and security-product
    information. Store and share it according to company policy.
</div>

<div class="discovery">
    $discoveryMessage
</div>

$($htmlSections -join [Environment]::NewLine)

<div class="footer">
    Generated by Windows Day 1 Environment Assessment V2.
</div>
</body>
</html>
"@

$html | Set-Content -Path $reportPath -Encoding UTF8

$assessment |
    ConvertTo-Json -Depth 10 |
    Set-Content -Path $jsonPath -Encoding UTF8

$networkSummaryText = if ($EnableNetworkDiscovery) {
@"
NETWORK DISCOVERY
-----------------
Target:          $TargetSubnet
Devices found:   $(@($networkDiscovery.Results).Count)
Ports checked:   $($Ports -join ", ")
CSV:             $networkCsvPath
"@
}
else {
@"
NETWORK DISCOVERY
-----------------
Disabled
"@
}

$summary = @"
WINDOWS ENVIRONMENT ASSESSMENT V2
=================================

Computer:        $computerName
User:            $env:USERDOMAIN\$env:USERNAME
Date:            $(Get-Date)
Administrator:   $isAdmin

$networkSummaryText

FILES
-----
HTML Report:     $reportPath
JSON Data:       $jsonPath
Group Policy:    $gpoPath

IMPORTANT
---------
Only use network discovery on systems and networks you own or have explicit
authorization to assess. This report can contain confidential internal IT
information.
"@

$summary | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host ""
Write-Host "Assessment complete." -ForegroundColor Green
Write-Host "Output folder: $outputFolder"
Write-Host "HTML report:  $reportPath"
Write-Host "JSON data:    $jsonPath"
Write-Host "Quick summary: $summaryPath"

if ($EnableNetworkDiscovery) {
    Write-Host "Network CSV:  $networkCsvPath"
}

Write-Host ""

if ($OpenReport) {
    Start-Process $reportPath
}
