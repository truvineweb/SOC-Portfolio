```markdown
# Windows Setup for SOClog

This guide explains how to prepare a **lab Windows machine** so that SOClog,
running on Kali, can collect logs and process data.

> All steps below assume a **lab** environment.  
> Do not enable WinRM like this on production systems without a proper security
> review.

---

## 1. Create / pick a user for remote collection

You need a Windows user that SOClog will use.

- If you're in a lab domain:
  - Example: `LAB\analyst`
- If you're in a workgroup:
  - Example local user: `WIN10LAB\analyst`

The easiest option for a lab is to make this user a local Administrator, but a
more restricted account plus specific permissions is better long-term.

---

## 2. Enable WinRM on Windows

Open **PowerShell as Administrator** on the Windows machine and run:

```powershell
Enable-PSRemoting -Force
winrm quickconfig
