# Windows Day 1 Environment Assessment

A PowerShell toolkit for **rapidly documenting an unfamiliar Windows environment** — the kind of thing you want on your first day supporting a new site, a new client, or a machine you've never seen before.

Run it, and a few seconds later you have a clean HTML report (plus JSON and a quick-summary text file) covering the endpoint's configuration, identity, networking, and security posture. No guessing, no clicking through twenty Settings panes.

> **Read-only by design.** It collects information. It does not change settings, touch remote machines, attempt credentials, or exploit anything. The optional network-discovery feature is **off by default** and only runs against a subnet you explicitly name.

## Why I built it

Walking into a new environment, the first 30 minutes are always the same questions: What is this machine? What domain is it on? How's it getting to the network? What security agents are running? Is BitLocker on? What's broken in the event log? I got tired of answering those by hand, so I automated the whole sweep into one script — *if I do it twice, I automate it.*

## Two versions

| File | What it does |
|---|---|
| **`Windows-Day1-Environment-Assessment.ps1`** | The core, 100% local, read-only assessment. Start here. |
| **`Windows-Day1-Environment-Assessment-V2.ps1`** | Everything in V1, plus an **optional, explicitly authorized** IPv4 subnet discovery scan (off by default) with concurrency, timeouts and CSV output. |

## What it collects

**System** — manufacturer/model, OS build, BIOS, memory, disk volumes with free space.
**Identity** — domain membership, logon server, current user, and Entra / device registration (`dsregcmd`).
**Networking** — adapters, IP config, DNS, routes, ARP/neighbor cache, Wi-Fi interface and saved profiles, network category.
**Security posture** — firewall profiles, BitLocker status, Windows Defender state, local machine & trusted-root certificates, and an inventory of common **security / RMM agents** (SentinelOne, CrowdStrike, Defender, Sophos, ConnectWise, NinjaOne, Qualys, GlobalProtect, Zscaler and more).
**Operations** — mapped drives, SMB connections, printers and printer ports, auto-start services that aren't running, local listening TCP ports (with owning process), and recent System/Application errors from the event log.
**Policy** — a full `gpresult` summary plus a standalone Group Policy HTML report.

### V2 adds: authorized network discovery (opt-in)

When you pass `-EnableNetworkDiscovery` **and** an explicit `-TargetSubnet`, V2 will, against that subnet only:

- test reachability (ICMP) and a configurable set of TCP ports — it checks ports even when ping is blocked, since many devices don't answer ICMP;
- resolve reverse DNS and read the ARP/MAC for responders;
- run in parallel on PowerShell 7+ (falls back to a sequential scan with a progress bar on 5.1);
- cap the host count (`-MaxHosts`, default 512) so you can't accidentally point it at a `/16`;
- write a per-device CSV inventory.

It will **refuse to run** discovery without an explicit subnet, and refuse a subnet without the enable switch — you have to mean it.

## Usage

```powershell
# Core local assessment
.\Windows-Day1-Environment-Assessment.ps1 -OpenReport

# Include an installed-software inventory
.\Windows-Day1-Environment-Assessment.ps1 -IncludeInstalledSoftware -OpenReport

# V2 with authorized discovery of one subnet you are permitted to assess
.\Windows-Day1-Environment-Assessment-V2.ps1 `
    -EnableNetworkDiscovery `
    -TargetSubnet 192.168.10.0/24 `
    -OpenReport
```

Reports are written to `Documents\Windows_Environment_Assessment\<ComputerName>_<timestamp>\` by default (override with `-OutputRoot`).

Works on **Windows PowerShell 5.1** and **PowerShell 7+**. Administrator rights are optional but fill in a few sections that are otherwise restricted. Both scripts are parse-validated.

## Responsible use

Only run the discovery feature on networks you own or are **explicitly authorized** to assess. The output can contain confidential internal information — hostnames, IP addresses, usernames, certificate and security-agent details — so store and share it according to your organization's policy. The report itself says so, at the top.

## License

[MIT](LICENSE).
