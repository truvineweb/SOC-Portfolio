```markdown
1. Create a hosts config file

On their Kali:

mkdir -p ~/soclog_configs
nano ~/soclog_configs/hosts_lab.yaml


Example content (adjust IP + username):

hosts:
  - name: win11lab
    host: 192.168.115.128          # Windows IP
    username: Divine-Lab\\soclog_analyst
    ask_password: true


Save and exit.

2. Run a small test (1–2 hours of logs)

From Kali:

soclog --config ~/soclog_configs/hosts_lab.yaml --hours 1


You’ll see:

SOC SIEM banner

SOClog tagline

Live stage progress:

[*] Collecting from host: win11lab (192.168.115.128)
Password for Divine-Lab\\soclog_analyst@192.168.115.128: ****

[>] Connecting via WinRM (NTLM)...
    █████-------------------------  16%

Output directory: /home/kali/soclog_output/win11lab/...

[>] Starting Sysmon collection (this may take a bit)...
    ██████████--------------------  33%
...

3. Output location

Each run creates:

~/soclog_output/<hostname>/<YYYYMMDD_HHMMSS>/


Example:

cd ~/soclog_output/win11lab
ls
# e.g. 20251118_150625

cd 20251118_150625
ls -lh


You’ll see:

sysmon_events.json

security_events.json

processes.json

manifest.json

soclog_win11lab_YYYYMMDD_HHMMSS.zip
