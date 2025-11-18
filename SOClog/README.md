# SOClog – Windows DFIR Collector

SOClog is a **Kali-based DFIR helper tool** that connects to Windows endpoints over **WinRM (NTLM)** and collects:

- Recent **Sysmon** event logs (if installed)
- Recent **Windows Security** event logs
- A **running process inventory** with SHA-256 hashes
- An **integrity manifest** (file hashes, size, timestamps), plus optional GPG signature
- A timestamped **ZIP archive** per host for offline analysis

> **Lab use only.** SOClog is designed for **educational / lab environments**, not for production systems.

---

## What this tool does (plain language)

Imagine you’re a SOC / DFIR analyst and you need a quick evidence bundle from a Windows machine:

- “Give me the last few hours of Sysmon and Security logs.”
- “Show me which processes were running and their hashes.”
- “Give me a bundle I can store, hash, and share with the incident team.”

SOClog does exactly that from **Kali Linux**:

1. Connects to a Windows host over **WinRM (NTLM)**.
2. Runs **PowerShell** to export:
   - Sysmon events (if the Sysmon log exists).
   - Security log events.
   - Running processes (PID, name, path, user where possible, SHA-256).
3. Saves everything into:
   - `~/soclog_output/<hostname>/<YYYYMMDD_HHMMSS>/`
4. Creates:
   - `manifest.json` with SHA-256 hashes, sizes, timestamps, host info.
   - Optional `manifest.sig` (GPG signature).
   - `soclog_<hostname>_<timestamp>.zip` with all artefacts.

---

## High-level architecture

**Controller (Kali):**

- Python 3 CLI: `soclog`
- Uses [`pywinrm`](https://pypi.org/project/pywinrm/) to talk to WinRM on Windows.
- Reads a **YAML config file** of hosts (`hosts.yaml`) or a single `--host / --user`.
- Writes JSON artefacts, manifest, and ZIP into `~/soclog_output`.

**Windows endpoints:**

- Windows 10 / 11 lab machines.
- WinRM enabled over HTTP (port 5985) with **NTLM** authentication.
- PowerShell cmdlets used:
  - `Get-WinEvent` for Sysmon + Security logs.
  - `Get-Process`, `Get-Item`, and hashing via `.NET` for processes.
- No agent is installed; everything is done over remote PowerShell.

---

## Requirements

### On Windows

- Windows 10 or 11 (lab VM recommended).
- **WinRM enabled** (HTTP, unencrypted allowed for lab).
- A user account (e.g. `Divine-Lab\soclog_analyst`) that:
  - Has local admin rights (for event logs + process/hashes).
  - Has a known password you can type into Kali.
- Optional: **Sysmon** installed with logging to:
  `Microsoft-Windows-Sysmon/Operational`.

> Detailed Windows steps: see [`docs/windows_setup.md`](docs/windows_setup.md)

### On Kali

- Kali Linux (or Debian-based) with:
  - Python 3
  - `python3-winrm`
  - `python3-yaml`
- For APT installation:
  - Access to your **custom SOClog APT repo** (simple HTTP server).

> Detailed Kali install options: see [`docs/kali_install.md`](docs/kali_install.md)

---

## Quick start (APT install)

These steps assume someone in your lab has already:

- Built the `soclog_0.1.0-1_all.deb`.
- Published it via a simple APT repo (see `docs/kali_install.md`).

On Kali:

```bash
# 1. Add the SOClog repo (replace IP with your repo host)
echo "deb [trusted=yes] http://192.168.115.130:8080/ ./" | \
  sudo tee /etc/apt/sources.list.d/soclog.list

sudo apt update

# 2. Install SOClog
sudo apt install -y soclog

# 3. Confirm it runs
soclog --help
