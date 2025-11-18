```markdown
On the Windows 10/11 endpoint (run all PowerShell commands as Administrator):

1. Note these values
ipconfig          # IPv4 address (e.g. 192.168.125.128)
hostname          # Computer name (e.g. vine-Lab)
whoami            # Username (e.g. vine-Lab\soclog_analyst)


You’ll need:

Host IP

Hostname

Username you’ll use for SOClog (make sure you know the password!)

2. Enable WinRM for lab use (HTTP, unencrypted, Basic allowed)
Enable-PSRemoting -Force
winrm quickconfig

Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value True
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value True

# Optional but good:
winrm get winrm/config/service/auth
winrm get winrm/config/service

3. Confirm WinRM works locally
Test-WsMan localhost


You should see a small XML block (WS-Management identity stuff).

4. (Optional) Check if Sysmon is installed
Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational"


If it returns info → Sysmon log exists.

If it errors → Sysmon probably not installed; SOClog will just say “Sysmon not installed”.
