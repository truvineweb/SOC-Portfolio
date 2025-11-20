**Case ID: PHISH-20251119-001**

**Title: CloudSync Storage Billing Phish to Test Outlook Mailbox.**

**Author: Truvine, SOC Analyst L1**

**Created: 19 Nov 2025 23:20 WAT / 22:20 UTC**

**TLP: CLEAR**

**Status: Closed (Simulated Incident)**

**Severity: Medium**

**Executive Summary**

   On 19 Nov 2025 at 23:53 WAT (22:53 UTC), a simulated phishing email was delivered from a lab Gmail account to a lab Outlook mailbox as part of a controlled training exercise. The email impersonated a fictitious cloud storage provider, “CloudSync Storage”, and claimed that a recent payment could not be processed. It urged the recipient to “review billing details” within 24 hours to avoid disruption to backups and shared files.
   The email passed SPF, DKIM, and DMARC checks and received a low spam score in Microsoft 365, meaning it would realistically land in a user’s inbox. The body included a “Review billing details” call-to-action that linked to a fake billing URL, and attached a benign Word document named Invoice_87421.docx. The attachment contained only harmless text but was presented as an overdue invoice to mimic real campaigns.
   Using the received message, we collected full headers, analysed the URL structure, extracted the file hash, and built an IOC set for hunting and alert tuning. There was no real impact: all accounts, domains, and files were under lab control and no malware or real customer data was involved. The main outcome is improved analyst confidence in reading headers, spotting social engineering patterns, and writing incident-style documentation.

**Scope & Impact**
**Affected assets:**

-   One test Outlook mailbox (socanalyst65@outlook.com)
-   One lab Gmail sender account (jt2141**@gmail.com)

**Users:**

-   1 test user mailbox involved (no production users)

**Data sensitivity:**

-   No production data. Email content and attachment are synthetic and non-sensitive.

**CIA impact:**

-   Confidentiality: None (lab-only)
-   Integrity: None
-   Availability: None

**Business impact:**

-   No operational or financial impact.
-   Positive training value for SOC processes, phishing detection, and reporting.
Note: This incident is a controlled lab simulation and not a real compromise.

**Timeline (WAT / UTC)**
| Time (WAT / UTC) | Actor         | Event                                                                  |
| ---------------- | ------------- | ---------------------------------------------------------------------- |
| 23:53 / 22:53    | Gmail / M365  | Phishing email relayed from Gmail to Microsoft 365 protection service. |
| 23:53 / 22:53    | Microsoft 365 | Message accepted and delivered to test Outlook inbox.                  |
| 23:58 / 22:58    | SOC           | Analyst opens the email, flags it as a simulated phishing attempt.     |
| 00:05 / 23:05    | SOC           | Full message headers exported from Outlook and saved as evidence.      |
| 00:10 / 23:10    | SOC           | Email body, CTA link, and actual hyperlink target recorded.            |
| 00:15 / 23:15    | SOC           | Attachment `Invoice_87421.docx` saved and SHA256 hash calculated.      |
| 00:30 / 23:30    | SOC           | IOCs extracted; draft incident notes and report structure created.     |
| 00:45 / 23:45    | SOC           | Simulated case closed; artefacts prepared for GitHub lab project.      |


**Detection & Triage**
**Detection source:**

-   Manual review in a lab context. In a real environment, this pattern could be detected by SIEM rules focused on external billing emails with links to non-corporate domains.
-   Initial indicators noticed by the analyst:
-   Sender uses a free email domain (@gmail.com) but claims to represent “CloudSync Storage”.
-   Subject line references payment failure: “CloudSync Storage: payment could not be processed.”
-   Urgent language and risk to backups and shared data.
-   A single prominent “Review billing details” CTA pointing to a non-corporate domain.
-   The message was quickly identified as part of the planned simulation and handled as training material.

**Technical Analysis**
**Email identity and authentication**

-   From: T***as J <jt2141**@gmail.com>
-   To: socanalyst65@outlook.com
-   Subject: CloudSync Storage: payment could not be processed.
-   Return-Path: jt2141**@gmail.com
-   Key header results:
-   SPF: pass (Gmail IP authorised for gmail.com)
-   DKIM: pass (gmail.com and 1e100.net signatures valid)
-   DMARC: pass (alignment valid for gmail.com)
-   Composite Authentication: pass
-   Spam score (SCL): 1 (low spam likelihood)

Conclusion: technically, this is a legitimate Gmail-sent email. The malicious aspect in a real scenario would be the social engineering and link destination, not a forged sender infrastructure.

**Content and social engineering**
**Main body points:**

-   Claims a payment failure for “CloudSync Storage”.
-   States the account is past due and at risk of service disruption.
-   Imposes a 24-hour window to act.
-   Provides a single CTA: “Review billing details”.
-   Signs off as “CloudSync Billing Team / CloudSync Storage”.
-   Marks the email as automated and non-monitored.

These elements combine urgency, fear of service loss, and a very clear “do this now” action, which matches common phishing patterns aimed at harvesting credentials or payment details.

**URL behaviour (conceptual)**
**Call-to-action URL:**

-   Actual link: https://billing-login.example/invoice?id=87421&user=testuser
-   Defanged: hxxps://billing-login[.]example/invoice?id=87421&user=testuser

**Breakdown:**

-   Domain: billing-login.example – looks like a billing portal but is not tied to any known CloudSync domain.
-   Path: /invoice
-   Parameters: id=87421 (invoice ID), user=testuser (user identifier)

In a real incident, this would be investigated in a sandbox environment and checked for fake login pages, data capture forms, or redirects. In this lab, the .example domain is intentionally non-functional, so no live traffic analysis is performed.

**Attachment behaviour (conceptual)**
**Attachment details:**

-   File: Invoice_87421.docx
-   Type: Word document
-   SHA256: A62EA44249D1E3E52A9032F0EF14264DFD9F1C2923E3176993B0AEEDB976399F

**In the lab:**

-   The document contains simple text only.
-   No macros, no embedded payloads, no network activity.
-   In a real case, a similar file might:
-   Prompt the user to enable macros.
-   Use macro code to download and run malware.
-   Exploit Office vulnerabilities to gain code execution.

Standard handling would include detonating the file in a sandbox, capturing any process and network activity, and extracting secondary IOCs.

**Indicators of Compromise**

| Type              | Value                                                                  | Notes                              |
| ----------------- | ---------------------------------------------------------------------- | ---------------------------------- |
| Sender display    | Thomas J                                                               | Displayed name in From header.     |
| Sender address    | `jt214113@gmail.com`                                                   | External Gmail sender used in lab. |
| Recipient address | `socanalyst65@outlook.com`                                             | Test mailbox receiving the phish.  |
| Subject           | `CloudSync Storage: payment could not be processed.`                   | Billing failure lure.              |
| Source IP         | `209.85.128.49`                                                        | Gmail mail server IP.              |
| HELO / host       | `mail-wm1-f49.google.com`                                              | Gmail SMTP host.                   |
| Sender domain     | `gmail.com`                                                            | Authenticated sending domain.      |
| Phish domain      | `billing-login.example`                                                | Fake billing portal domain.        |
| URL (live form)   | `https://billing-login.example/invoice?id=87421&user=testuser`         | CTA destination (lab-only).        |
| URL (defanged)    | `hxxps://billing-login[.]example/invoice?id=87421&user=testuser`       | Safe representation for reports.   |
| Attachment name   | `Invoice_87421.docx`                                                   | Fake invoice.                      |
| Attachment SHA256 | `A62EA44249D1E3E52A9032F0EF14264DFD9F1C2923E3176993B0AEEDB976399F`     | Hash of benign document.           |
| Message-ID        | `<CALaKBZyQuPS6oKuwy=JkdqQ6qBjBCfKHVJTq2C09n7S8Lod8cA@mail.gmail.com>` | Unique Gmail message ID.           |

These IOCs can be used in a SIEM or mail trace to practise detection logic, even though they are lab-only.

**Response Actions (Lab)**
Because this was a planned simulation, actions focused on collection and learning rather than containment:

-   Exported full message headers from Outlook.
-   Saved the email body and captured both visible and actual URLs.
-   Downloaded the attachment and calculated its SHA256 hash.
-   Built an IOC table for future reference and SIEM rule testing.
-   Documented the incident in this report and prepared artefacts for a GitHub portfolio project.

**Recommendations & Lessons Learned**

1. **Strengthen user awareness**
   - Train users to question billing emails from free email domains.
   - Encourage them to visit known portals directly instead of clicking links in emails.

2. **Highlight external senders**
   - Ensure external emails are clearly tagged with an “External” banner.
   - Use simple rules (e.g. external sender + payment issue + link) as cues to be cautious.

3. **Enhance phishing detection rules**
   - Build SIEM use cases for:
     - Payment/invoice subjects from `@gmail.com`, `@outlook.com`, etc.
     - Links to domains outside the organisation’s approved SaaS list.

4. **Improve attachment handling**
   - Sandbox Office attachments from external senders, especially invoices and payment notices.

5. **Repeat simulations regularly**
   - Run similar phishing simulations with different themes (HR, delivery, password reset).
   - Rotate scenarios so users and analysts see varied lures over time.
