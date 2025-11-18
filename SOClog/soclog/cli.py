import argparse
import getpass
import json
import os
import warnings
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import __version__
from .collectors import (
    collect_sysmon_logs,
    collect_security_logs,
    collect_processes,
)
from .config import (
    HostConfig,
    load_hosts_from_yaml,
    resolve_password_for_host,
)
from .integrity import (
    build_manifest,
    write_manifest,
    sign_manifest_with_gpg,
)
from .windows_remote import WindowsRemote, WindowsRemoteError
import zipfile

# =========================
#  Warning suppression
#  (hide spnego/ARC4 deprecation noise)
# =========================
try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:
    # If cryptography layout changes, just ignore
    pass

# =========================
#  Simple ANSI colours
# =========================
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"


def print_banner() -> None:
    """Print the SOC SIEM ASCII banner and SOClog tagline."""
    print()
    # Clear, readable "SOC SIEM" in ASCII
    print(f"{BOLD}{CYAN}  SSS   OOO   CCCC       SSS   III  EEEEE  MM   MM{RESET}")
    print(f"{BOLD}{CYAN} S     O   O  C          S       I   E      MMM MMM{RESET}")
    print(f"{BOLD}{CYAN}  SSS  O   O  C           SSS    I   EEEE   MM M MM{RESET}")
    print(f"{BOLD}{CYAN}     S O   O  C              S   I   E      MM   MM{RESET}")
    print(f"{BOLD}{CYAN}  SSS   OOO   CCCC       SSS    III  EEEEE  MM   MM{RESET}")
    print()

    print(f"{BOLD}{GREEN}SOClog - Windows DFIR Collector{RESET}")
    print(f"{DIM}     * Remote Sysmon + Security logs{RESET}")
    print(f"{DIM}     * Process inventory + hashes{RESET}")
    print(f"{DIM}     * Integrity manifest + ZIP.{RESET}")
    print()
    print(f"{BOLD}{YELLOW}USE FOR EDUCATIONAL PURPOSES!{RESET}")
    print(f"{BOLD}{MAGENTA}Author: @truvineweb{RESET}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="soclog",
        description=(
            "SOClog - collect Windows Sysmon + Security logs and process list "
            "from Kali via WinRM, and package into a ZIP file with integrity hashes."
        ),
    )

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument(
        "--host",
        help="Single Windows host (IP or hostname). Use with --user.",
    )
    target.add_argument(
        "--config",
        help="YAML file listing multiple Windows hosts (see examples/hosts_example.yaml).",
    )

    parser.add_argument(
        "--user",
        help="Username for single host mode, e.g. 'LAB\\analyst'.",
    )

    time_group = parser.add_mutually_exclusive_group()
    time_group.add_argument(
        "--hours",
        type=int,
        help="Collect logs for the last N hours (default: 24).",
    )
    time_group.add_argument(
        "--days",
        type=int,
        help="Collect logs for the last N days.",
    )

    parser.add_argument(
        "--output-dir",
        default=str(Path.home() / "soclog_output"),
        help="Base output directory on Kali (default: ~/soclog_output).",
    )

    parser.add_argument(
        "--ask-pass",
        action="store_true",
        help="Prompt for password (single host mode only).",
    )

    parser.add_argument(
        "--password-env",
        help=(
            "Environment variable holding password for single host mode, "
            "e.g. SOCLOG_PASS. Optional."
        ),
    )

    parser.add_argument(
        "--sign-manifest",
        action="store_true",
        help="Sign manifest.json with GPG (requires gpg installed).",
    )

    parser.add_argument(
        "--gpg-key",
        help="GPG key ID or email to use when signing manifest. Optional.",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser.parse_args()


def make_host_configs_from_single(
    host: str,
    user: str,
    password_env: Optional[str],
    ask_pass: bool,
) -> List[HostConfig]:
    cfg = HostConfig(
        name=host,
        host=host,
        username=user,
        password_env=password_env,
        ask_password=ask_pass,
    )
    return [cfg]


def prepare_output_dir(base_output: str, host_name: str) -> Path:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(base_output).expanduser().resolve() / host_name / ts
    path.mkdir(parents=True, exist_ok=True)
    return path


def print_progress(stage: str, current_step: int, total_steps: int) -> None:
    """
    Print a simple stage-based progress bar.

    This is not per-event or per-byte; it's per major stage:
      1) Connect
      2) Sysmon
      3) Security
      4) Processes
      5) Manifest (+sign)
      6) ZIP
    """
    percent = int(current_step * 100 / total_steps)
    bar_width = 30
    filled = int(bar_width * percent / 100)
    bar = "█" * filled + "-" * (bar_width - filled)
    print(f"{BLUE}[>]{RESET} {stage}")
    print(f"    {BOLD}{GREEN}{bar}{RESET} {BOLD}{percent:3d}%{RESET}")


def create_zip_from_dir(target_dir: Path, zip_path: Path) -> None:
    """Zip the contents of a directory into zip_path."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(target_dir):
            for filename in files:
                full_path = Path(root) / filename
                # store relative path (inside host/timestamp dir)
                rel_path = full_path.relative_to(target_dir)
                zf.write(full_path, arcname=rel_path)


def main() -> None:
    print_banner()
    args = parse_args()

    if args.host and not args.user:
        raise SystemExit(f"{RED}Error: --host requires --user.{RESET}")

    if args.config and args.user:
        raise SystemExit(f"{RED}Error: --config mode does not use --user.{RESET}")

    # Determine hours/days
    hours = args.hours
    days = args.days

    # Build host configs
    if args.config:
        host_configs = load_hosts_from_yaml(args.config)
    else:
        host_configs = make_host_configs_from_single(
            args.host, args.user, args.password_env, args.ask_pass
        )

    base_output = args.output_dir

    for cfg in host_configs:
        print(
            f"{BOLD}{CYAN}[*]{RESET} {BOLD}Collecting from host:{RESET} "
            f"{YELLOW}{cfg.name}{RESET} {DIM}({cfg.host}){RESET}"
        )

        password = resolve_password_for_host(cfg)

        ask_pass = cfg.ask_password or args.ask_pass
        if password is None and ask_pass:
            password = getpass.getpass(
                prompt=f"Password for {cfg.username}@{cfg.host}: "
            )

        if password is None:
            print(
                f"{RED}[!]{RESET} No password available for host {cfg.name}. "
                "Use an env var (password_env) or --ask-pass."
            )
            continue

        total_steps = 6

        # ========== CONNECT ==========
        print_progress("Connecting via WinRM (NTLM)...", 1, total_steps)
        try:
            client = WindowsRemote(
                host=cfg.host,
                username=cfg.username,
                password=password,
                use_https=False,  # HTTP for lab; switch later for HTTPS if desired
                ask_password_if_missing=False,
            )
        except WindowsRemoteError as exc:
            print(f"{RED}[!]{RESET} Failed to connect to {cfg.name}: {exc}")
            continue

        out_dir = prepare_output_dir(base_output, cfg.name)
        print(
            f"    {BOLD}Output directory:{RESET} "
            f"{MAGENTA}{out_dir}{RESET}"
        )

        collected_files: List[str] = []

        # ========== SYSMON ==========
        print_progress(
            "Starting Sysmon collection (this may take a bit)...",
            2,
            total_steps,
        )
        try:
            status, sysmon_data = collect_sysmon_logs(client, hours=hours, days=days)
            sysmon_path = out_dir / "sysmon_events.json"
            with open(sysmon_path, "w", encoding="utf-8") as f:
                json.dump(sysmon_data, f, indent=2)
            collected_files.append(str(sysmon_path))

            if status == "missing":
                print(f"    {YELLOW}[!]{RESET} Sysmon not installed on this host.")
            elif status == "empty":
                print(
                    f"    {YELLOW}[*]{RESET} No Sysmon events for requested time range."
                )
            else:
                print(f"    {GREEN}[+]{RESET} Sysmon events collected.")
        except WindowsRemoteError as exc:
            print(f"    {RED}[!]{RESET} Failed to collect Sysmon logs: {exc}")

        # ========== SECURITY LOG ==========
        print_progress(
            "Starting Security log collection...", 3, total_steps
        )
        try:
            status, sec_data = collect_security_logs(client, hours=hours, days=days)
            sec_path = out_dir / "security_events.json"
            with open(sec_path, "w", encoding="utf-8") as f:
                json.dump(sec_data, f, indent=2)
            collected_files.append(str(sec_path))

            if status == "empty":
                print(
                    f"    {YELLOW}[*]{RESET} No Security log events for requested time range."
                )
            else:
                print(f"    {GREEN}[+]{RESET} Security log events collected.")
        except WindowsRemoteError as exc:
            print(f"    {RED}[!]{RESET} Failed to collect Security logs: {exc}")

        # ========== PROCESSES ==========
        print_progress(
            "Collecting running processes and hashes...", 4, total_steps
        )
        try:
            proc_data = collect_processes(client)
            proc_path = out_dir / "processes.json"
            with open(proc_path, "w", encoding="utf-8") as f:
                json.dump(proc_data, f, indent=2)
            collected_files.append(str(proc_path))
            print(f"    {GREEN}[+]{RESET} Process list collected.")
        except WindowsRemoteError as exc:
            print(f"    {RED}[!]{RESET} Failed to collect process list: {exc}")

        # ========== MANIFEST & INTEGRITY ==========
        if collected_files:
            print_progress("Building integrity manifest...", 5, total_steps)
            manifest = build_manifest(collected_files, host=cfg.name)
            manifest_path = out_dir / "manifest.json"
            write_manifest(manifest, str(manifest_path))
            collected_files.append(str(manifest_path))
            print(f"    {GREEN}[+]{RESET} manifest.json generated.")

            if args.sign_manifest:
                sig_path = out_dir / "manifest.sig"
                try:
                    sign_manifest_with_gpg(
                        str(manifest_path),
                        str(sig_path),
                        gpg_key=args.gpg_key,
                    )
                    collected_files.append(str(sig_path))
                    print(f"    {GREEN}[+]{RESET} manifest.sig created (GPG signature).")
                except Exception as exc:
                    print(
                        f"    {YELLOW}[!]{RESET} Failed to sign manifest with GPG: {exc}"
                    )

            # ========== ZIP ==========
            print_progress("Packaging artefacts into ZIP...", 6, total_steps)
            zip_path = out_dir / f"soclog_{cfg.name}_{out_dir.name}.zip"
            try:
                create_zip_from_dir(out_dir, zip_path)
                print(f"    {GREEN}[+]{RESET} ZIP created: {BOLD}{zip_path}{RESET}")
            except OSError as exc:
                if exc.errno == 28:
                    print(
                        f"    {YELLOW}[!]{RESET} Failed to create ZIP: no space left on device. "
                        f"Collected files and manifest are still available in {out_dir}."
                    )
                else:
                    print(f"    {RED}[!]{RESET} Failed to create ZIP: {exc}")
        else:
            print(
                f"    {YELLOW}[!]{RESET} No artefacts collected; skipping manifest and ZIP."
            )


if __name__ == "__main__":
    main()
