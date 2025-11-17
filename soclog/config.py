import os
from dataclasses import dataclass
from typing import List, Optional

import yaml


@dataclass
class HostConfig:
    """Configuration for a single Windows host."""

    name: str
    host: str
    username: str
    password_env: Optional[str] = None
    ask_password: bool = False


def load_hosts_from_yaml(path: str) -> List[HostConfig]:
    """
    Load host definitions from a YAML file.

    Expected format:

    hosts:
      - name: win10lab
        host: 192.168.56.10
        username: LAB\\analyst
        password_env: SOCLOG_WIN10_PASS

      - name: win11lab
        host: win11.lab.local
        username: LAB\\dfir
        ask_password: true
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    hosts_data = data.get("hosts", [])
    hosts: List[HostConfig] = []

    for item in hosts_data:
        name = item.get("name") or item.get("host")
        if not name:
            raise ValueError("Each host entry must have at least 'name' or 'host'.")

        host = item.get("host")
        username = item.get("username")
        if not host or not username:
            raise ValueError(f"Host {name!r} is missing 'host' or 'username'.")

        password_env = item.get("password_env")
        ask_password = bool(item.get("ask_password", False))

        hosts.append(
            HostConfig(
                name=name,
                host=host,
                username=username,
                password_env=password_env,
                ask_password=ask_password,
            )
        )

    return hosts


def resolve_password_for_host(cfg: HostConfig) -> Optional[str]:
    """
    Return the password for this host if it is provided via environment
    variable. If ask_password is True, this function does NOT prompt;
    the CLI layer will do that interactively.

    Returns:
        Password string or None.
    """
    if cfg.password_env:
        return os.environ.get(cfg.password_env)
    return None
