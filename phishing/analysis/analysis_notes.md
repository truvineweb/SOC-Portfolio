# Analysis Notes – CloudSync Billing Phish (Lab)

Case ID: PHISH-20251119-001  
Analyst: Truvine (SOC Analyst L1)  
Date: 19 Nov 2025  

---

## 1. Quick context

- Controlled **lab phishing simulation**.
- Sender: lab Gmail account (`jt214113@gmail.com`).
- Recipient: lab Outlook account (`socanalyst65@outlook.com`).
- Pretext: **payment failed / account at risk** for fictitious service **"CloudSync Storage"**.
- Goal: practise:
  - Reading and interpreting email headers.
  - Spotting phishing indicators (content + infrastructure).
  - Extracting IOCs.
  - Writing a short, incident-style report.

---

## 2. First impressions (as a SOC analyst)

What stood out immediately:

- Subject: `CloudSync Storage: payment could not be processed.`  
  → Classic payment / billing lure.
- Sender domain is **Gmail**, not a CloudSync corporate domain.
- Strong urgency:
  - Account “past due”.
  - Threat of disruption to backups and shared files.
  - 24-hour window to act.
- Single clear CTA: **“Review billing details”**.

If this turned up in a real corporate mailbox, I’d already be thinking “phish until proven otherwise”.

---

## 3. Header review – key points

From the raw headers:

- **Mail path**
  - `Received` chain shows legitimate Google → Microsoft 365 routing.
  - Source IP: `209.85.128.49` (`mail-wm1-f49.google.com`).
- **Authentication**
  - `spf=pass`, `dkim=pass`, `dmarc=pass`, `compauth=pass`.
  - So technically the email is valid for `gmail.com`.
- **Spam score**
  - `X-MS-Exchange-Organization-SCL: 1` → low spam likelihood.

Takeaway:

> This is a good example that a phish can pass all the “fancy” email auth checks and still be malicious based on content and intent. You can’t rely on SPF/DKIM/DMARC alone.

---

## 4. Content & social engineering notes

Main tactics used in the body:

- **Authority & brand impersonation**
  - Claims to be from “CloudSync Storage” billing, even though the domain is Gmail.
- **Urgency**
  - 24-hour deadline to fix billing before service disruption.
- **Fear of loss**
  - Mentions backups and shared files being affected.
- **Simplicity**
  - Short, direct message with one main option: click the button.
- **Friction reduction**
  - “If you’ve already updated your payment info, ignore this” – lowers suspicion.

User-facing red flags I’d train people on:

- Personal/free email address for a “billing team”.
- No direct reference to contract number, company name, or official contacts.
- Link goes to an unknown domain.

---

## 5. URL analysis – thoughts

Actual link:

- `https://billing-login.example/invoice?id=87421&user=testuser`  
- Defanged: `hxxps://billing-login[.]example/invoice?id=87421&user=testuser`

Observations:

- Domain looks like a **generic billing portal**, not clearly related to “CloudSync”.
- Could easily be swapped with a real lookalike domain in a real campaign.
- Query parameters (`invoice id` + `user`) make it look personalised and legitimate.

How I would handle this in a real case:

- Only interact with the URL from:
  - A **sandbox** or detonation environment.
  - Or a trusted URL analysis tool.
- Look for:
  - Fake login page mimicking a known provider.
  - Forms collecting credentials or card data.
  - Hidden redirects to other domains.
  - Embedded scripts talking to command-and-control infrastructure.

In this lab, `.example` keeps things clearly safe and non-resolving.

---

## 6. Attachment analysis – thoughts

Attachment:

- `Invoice_87421.docx`
- SHA256: `A62EA44249D1E3E52A9032F0EF14264DFD9F1C2923E3176993B0AEEDB976399F`
- Lab behaviour: simple text, no macros, benign.

In real incidents, similar docs are often:

- Macro-enabled to drop/run malware.
- Used to call out to remote URLs (e.g. PowerShell, LOLBins).
- Weaponised with Office exploits.

Standard playbook in production:

- Detonate in a sandbox.
- Monitor:
  - Child processes from `WINWORD.EXE`.
  - Network calls.
  - Dropped files / registry changes.
- Extract additional IOCs (domains, IPs, hashes, file names).

Here, the focus is on the **workflow**, not actual malware.

---

## 7. Detection ideas (what I’d build rules for)

Notes for future SIEM / mail security rules:

1. **External billing from free email domains**
   - Trigger when:
     - From domain is `gmail.com`, `outlook.com`, etc.
     - Subject/body contains “payment could not be processed”, “invoice overdue”, “billing issue”, etc.
     - Recipient is internal.

2. **Brand/domain mismatch**
   - Email content references a brand (e.g. “CloudSync Storage”) but:
     - Sender domain doesn’t match any known domains for that brand.
   - This is more advanced and may need content inspection or keyword lists.

3. **Unknown external domains in links**
   - Flag emails where:
     - Domain in URL is not in the organisation’s list of approved SaaS / partners.
   - Especially when combined with “login”, “billing”, “portal” in hostname or path.

4. **User behaviour correlation (in real life)**
   - Combine mail IOCs with:
     - Unusual logins from new IPs immediately after email delivery.
     - Password reset events or new device registrations.

---

## 8. Gaps & improvements for the next lab run

- Add a **second variant** of the phish (e.g. HR policy update, payroll change) to practise comparing two different lures.
- Include a **fake login page screenshot** (static, offline) for training to talk through what I’d look for in source code and network calls.
- Simulate a user “click” by:
  - Manually creating pretend login events in a log source (e.g. “user attempted login at time X”), then hunting them in a SIEM scenario.
- Extend the report with a small “detection rule sketch” section:
  - Example pseudo-SPL / KQL to detect similar emails.

---

## 9. Personal takeaways

- Good reminder that **SPF/DKIM/DMARC pass ≠ safe email**.
- I’m more comfortable now:
  - Reading complex headers from Microsoft 365 and Gmail.
  - Breaking down phishing content into technique and impact.
  - Turning raw artefacts into a **clean incident report + IOC list**.
- This case is a solid portfolio piece to show:
  - End-to-end lab design.
  - Evidence collection.
  - Analysis and documentation skills.
