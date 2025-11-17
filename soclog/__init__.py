"""
SOClog - Simple remote Windows log and process collector for SOC analysts.

This package provides the `soclog` command line tool, which connects
from Kali Linux to one or more Windows hosts using WinRM, collects
recent Sysmon and Security logs plus a running process list, and saves
everything into a timestamped directory and ZIP file with integrity
hashes (and optional GPG signing of a manifest file).
"""

__version__ = "0.1.0"
