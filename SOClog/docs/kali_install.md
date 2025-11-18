```markdown
1. Add your SOClog APT repo

Suppose your SOClog repo is served from your Kali at http://192.168.115.130:8080/
(Replace with your real IP.)

On their Kali:

# See their IP to confirm connectivity to your repo box
ip a

# Add your SOClog repo (trusted for lab)
echo "deb [trusted=yes] http://192.168.115.130:8080/ ./" | \
  sudo tee /etc/apt/sources.list.d/soclog.list

sudo apt update

2. Install SOClog
sudo apt install -y soclog


Check it’s installed:

soclog --help


They should see your new banner + help text.



