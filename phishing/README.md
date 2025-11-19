# Phishing Investigation Lab – CloudSync Billing Scenario

This folder contains a self-contained phishing investigation carried out in an isolated lab environment.

## Scenario overview

A test Gmail account sends a phishing-style billing email to a test Outlook mailbox.  
The email impersonates a fictitious cloud storage provider ("CloudSync Storage") and claims a payment could not be processed.  

Key elements:

- External sender: `jt2141**@gmail.com` (lab account)
- Recipient: `socanalyst65@outlook.com` (lab account)
- Subject: `CloudSync Storage: payment could not be processed.`
- CTA link to a fake billing portal:
  - `https://billing-login.example/invoice?id=87421&user=testuser`
- Benign attachment:
  - `Invoice_87421.docx` (no macros, safe content)

All accounts, URLs, and files are lab-only and harmless.

## Repository layout

- `email/`
  - `headers.txt` – full raw message headers and MIME body from Outlook.
  - `phishing_email.md` – rendered email body, visible CTA text, and URL details.
- `analysis/`
  - `iocs.md` – extracted indicators of compromise (IOCs) with context.
- `report/`
  - `phishing_incident_report.md` – full incident-style report in markdown.

## Safety notes

- This project is **purely educational**.
- No real users, production systems, or live malware are involved.
- The `.example` domain is reserved and non-functional.
- The Word document attachment is benign and contains only harmless text.

You can use this lab to practise:

- Reading and interpreting email headers.
- Identifying phishing indicators in email content.
- Extracting IOCs for detection and hunting.
- Writing professional incident reports for your portfolio.
