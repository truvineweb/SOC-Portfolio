# SOClog

SOClog is a Kali Linux CLI tool that connects to one or more Windows hosts,
collects recent:

- Sysmon logs (if Sysmon is installed),
- Windows Security event logs,
- Running process list with SHA-256 hashes,

and saves everything into a timestamped directory and ZIP file on Kali, together
with a `manifest.json` that contains integrity hashes for each artefact. The
manifest can optionally be signed with GPG.

This is designed for SOC analysts / DFIR who want a simple way to grab
forensic artefacts from lab Windows machines without writing code.

> ❗ Always keep your experiments in a safe, isolated lab.  
> Do not run SOClog or its techniques against production or external systems
> without proper authorization.

## What this tool does (in one paragraph)

From Kali, you run a single command (`soclog`). It uses WinRM to talk to
Windows, runs PowerShell commands to pull recent Sysmon and Security logs
plus the current process list, receives everything as JSON, writes files into
`~/soclog_output/<hostname>/<timestamp>/`, generates `manifest.json` with
SHA-256 hashes of each file, and then creates a `soclog_<hostname>_<timestamp>.zip`
for offline analysis.

## High-level architecture

- **Kali / Linux**
  - Python 3 CLI (`soclog`) using `pywinrm` and `PyYAML`.
  - Optional GPG for manifest signing.
- **Windows endpoints**
  - WinRM enabled.
  - PowerShell available (default on modern Windows).
  - Account with permission to read event logs and process info.

Interaction:

1. `soclog` connects to Windows via WinRM.
2. Runs PowerShell to fetch logs/processes as JSON.
3. Saves files + manifest + ZIP on Kali.

## Sysmon vs Security logs (quick explanation)

- **Sysmon log** (Microsoft Sysinternals Sysmon):
  - Extra telemetry: process creation with hashes, network connections, file
    changes, etc.
  - Great for attack simulation and detection engineering.
  - Not installed by default; you (or your lab) must install and configure it.

- **Windows Security log**:
  - Built-in log (LogName: `Security`).
  - Contains authentication events (logon/logoff), privilege use, policy changes,
    etc.
  - Core source for many SOC detections, especially around identity.

SOClog simply pulls recent events from both to give you a small “snapshot”
for analysis.

## Quick start

If you just want the commands, see  
[docs/kali_install.md](docs/kali_install.md) and  
[docs/windows_setup.md](docs/windows_setup.md).

Typical usage after setup:

```bash
# Single host
soclog --host 192.168.56.10 --user LAB\\analyst --hours 4 --ask-pass

# Or with a hosts file (examples/hosts_example.yaml)
soclog --config examples/hosts_example.yaml --days 1
