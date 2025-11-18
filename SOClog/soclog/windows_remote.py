import getpass
from typing import Optional

import winrm


class WindowsRemoteError(Exception):
    """Custom exception for Windows remote errors."""


class WindowsRemote:
    """
    Small wrapper around pywinrm to run PowerShell on a remote Windows host.

    For our use case:
      - We use HTTP WinRM (port 5985) in a lab environment.
      - Authentication: basic (username + password).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        use_https: bool = False,
        port: Optional[int] = None,
        verify_ssl: bool = False,
        ask_password_if_missing: bool = False,
    ) -> None:
        self.host = host
        self.username = username

        if password is None and ask_password_if_missing:
            password = getpass.getpass(
                prompt=f"Password for {username}@{host}: "
            )

        if password is None:
            raise WindowsRemoteError(
                "No password provided and ask_password_if_missing is False."
            )

        scheme = "https" if use_https else "http"
        if port is None:
            port = 5986 if use_https else 5985

        self.url = f"{scheme}://{host}:{port}/wsman"
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl

        # auth: basic is simplest for lab (over HTTP, inside isolated network)
        self.session = winrm.Session(
            self.url,
            auth=(self.username, self.password),
            server_cert_validation="validate" if verify_ssl else "ignore",
        )

        def run_powershell(self, script: str, timeout: int = 120):
        """
        Execute a PowerShell script remotely and return (status_code, stdout, stderr).

        Note: Some pywinrm versions do not support a 'timeout' argument on run_ps,
        so we ignore the timeout parameter here and just call run_ps(script).
        """
        try:
            # pywinrm run_ps defaults to UTF-8 output
            result = self.session.run_ps(script)
        except Exception as exc:  # broad but fine for outer boundary
            raise WindowsRemoteError(f"Failed to run PowerShell: {exc}") from exc

        stdout = result.std_out.decode("utf-8", errors="replace") if isinstance(
            result.std_out, (bytes, bytearray)
        ) else result.std_out
        stderr = result.std_err.decode("utf-8", errors="replace") if isinstance(
            result.std_err, (bytes, bytearray)
        ) else result.std_err

        return result.status_code, stdout, stderr

