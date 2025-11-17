import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Optional

from .windows_remote import WindowsRemote, WindowsRemoteError


def _make_start_time(hours: Optional[int] = None, days: Optional[int] = None) -> str:
    """
    Compute a UTC ISO timestamp string for 'now minus X hours/days'.

    Returned as e.g. '2025-11-16T12:34:56'.
    """
    if hours is None and days is None:
        hours = 24  # default: last 24 hours

    delta = timedelta()
    if hours:
        delta += timedelta(hours=hours)
    if days:
        delta += timedelta(days=days)

    start_dt = datetime.now(timezone.utc) - delta
    return start_dt.strftime("%Y-%m-%dT%H:%M:%S")


def collect_sysmon_logs(
    client: WindowsRemote, hours: Optional[int] = None, days: Optional[int] = None
) -> Tuple[str, Dict]:
    """
    Collect recent Sysmon events from Windows as JSON.

    Returns a tuple (status, data):
      - status: "ok", "missing", or "empty"
      - data: dictionary or list (parsed JSON), or {"message": "..."} if missing/empty.
    """
    start_time = _make_start_time(hours, days)
    script = f"""
$ErrorActionPreference = "Stop"
$logName = "Microsoft-Windows-Sysmon/Operational"
$log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
if (-not $log) {{
    Write-Output "SYSMON_NOT_INSTALLED"
    exit 0
}}
$startTime = [datetime]"{start_time}"
$events = Get-WinEvent -FilterHashtable @{{LogName=$logName; StartTime=$startTime}} -ErrorAction SilentlyContinue
if (-not $events) {{
    Write-Output "NO_EVENTS"
    exit 0
}}
$events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
    ConvertTo-Json -Depth 5
"""

    status_code, stdout, stderr = client.run_powershell(script)

    if "SYSMON_NOT_INSTALLED" in stdout:
        return "missing", {"message": "Sysmon is not installed on this host."}
    if "NO_EVENTS" in stdout:
        return "empty", {"message": "No Sysmon events found for the requested time range."}

    if status_code != 0 and not stdout:
        raise WindowsRemoteError(
            f"Failed to collect Sysmon logs. Exit code {status_code}, stderr: {stderr}"
        )

    stdout = stdout.strip()
    if not stdout:
        return "empty", {"message": "Sysmon output was empty."}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # If JSON parsing fails, keep raw text for troubleshooting.
        data = {"raw": stdout}
    return "ok", data


def collect_security_logs(
    client: WindowsRemote, hours: Optional[int] = None, days: Optional[int] = None
) -> Tuple[str, Dict]:
    """
    Collect recent Security log events (Windows Security log) as JSON.

    Same status pattern as Sysmon collector: "ok" / "empty".
    """
    start_time = _make_start_time(hours, days)
    script = f"""
$ErrorActionPreference = "Stop"
$logName = "Security"
$startTime = [datetime]"{start_time}"
$events = Get-WinEvent -FilterHashtable @{{LogName=$logName; StartTime=$startTime}} -ErrorAction SilentlyContinue
if (-not $events) {{
    Write-Output "NO_EVENTS"
    exit 0
}}
$events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, MachineName, Message |
    ConvertTo-Json -Depth 5
"""

    status_code, stdout, stderr = client.run_powershell(script)

    if "NO_EVENTS" in stdout:
        return "empty", {"message": "No Security events found for the requested time range."}

    if status_code != 0 and not stdout:
        raise WindowsRemoteError(
            f"Failed to collect Security logs. Exit code {status_code}, stderr: {stderr}"
        )

    stdout = stdout.strip()
    if not stdout:
        return "empty", {"message": "Security log output was empty."}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        data = {"raw": stdout}
    return "ok", data


def collect_processes(client: WindowsRemote) -> Dict:
    """
    Collect a list of running processes with PID, Name, Path, User (if feasible),
    and SHA-256 of the executable (where accessible).

    Returns a dict like {"processes": [...]}.
    """
    script = r"""
$ErrorActionPreference = "SilentlyContinue"

# Create a hashtable mapping PID -> user for efficiency
$wmiProcs = Get-WmiObject Win32_Process
$userMap = @{}
foreach ($p in $wmiProcs) {
    try {
        $owner = $p.GetOwner()
        if ($owner.ReturnValue -eq 0) {
            $userMap[$p.ProcessId] = "$($owner.Domain)\$($owner.User)"
        }
    } catch {}
}

$results = @()

foreach ($p in Get-Process) {
    $path = $null
    $hash = $null
    $user = $null

    try {
        $path = $p.MainModule.FileName
    } catch {}

    if ($userMap.ContainsKey($p.Id)) {
        $user = $userMap[$p.Id]
    }

    if ($path) {
        try {
            $hashObj = Get-FileHash -Algorithm SHA256 -LiteralPath $path
            $hash = $hashObj.Hash
        } catch {}
    }

    $results += [PSCustomObject]@{
        PID = $p.Id
        Name = $p.ProcessName
        Path = $path
        User = $user
        HashSHA256 = $hash
    }
}

$results | ConvertTo-Json -Depth 4
"""

    status_code, stdout, stderr = client.run_powershell(script, timeout=300)

    if status_code != 0 and not stdout:
        raise WindowsRemoteError(
            f"Failed to collect process list. Exit code {status_code}, stderr: {stderr}"
        )

    stdout = stdout.strip()
    if not stdout:
        return {"processes": []}

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # If JSON parsing fails, keep raw text
        return {"raw": stdout}

    # Ensure we always return a dict with "processes"
    if isinstance(data, list):
        return {"processes": data}
    elif isinstance(data, dict) and "processes" in data:
        return data
    else:
        return {"processes": data}
