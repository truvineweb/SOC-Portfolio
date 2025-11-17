```markdown
# Using SOClog

This guide assumes:

- Windows hosts are prepared (see `windows_setup.md`).
- SOClog is installed on Kali (`soclog` command available).

---

## 1. Basic one-host run

Example:

```bash
soclog --host 192.168.56.10 --user LAB\\analyst --hours 4 --ask-pass
