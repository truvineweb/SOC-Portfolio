```markdown
# Installing SOClog on Kali

You can use SOClog in two ways:

1. **Run from source** (simplest first step).
2. Build a **.deb package** and serve it via a small apt repository.

---

## 1. Requirements on Kali

Install basic tools:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv gpg

#For building Debian packages:
sudo apt install -y devscripts debhelper dh-python build-essential
