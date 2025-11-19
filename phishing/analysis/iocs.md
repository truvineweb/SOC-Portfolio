# Indicators of Compromise – CloudSync Billing Phish (Lab)

| Type               | Value                                                                                                  | Context / Notes                                                        |
|--------------------|--------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| Sender display     | Thomas J                                                                                               | Display name in `From` header                                          |
| Sender address     | `jt2141**@gmail.com`                                                                                   | Authenticated Gmail sender, impersonating CloudSync billing            |
| Return-Path        | `jt2141**@gmail.com`                                                                                   | Envelope sender                                                        |
| Recipient address  | `socanalyst65@outlook.com`                                                                             | Lab victim mailbox                                                     |
| Subject            | `CloudSync Storage: payment could not be processed.`                                                   | Phishing subject (billing / payment failure)                           |
| Source IP          | `209.85.128.49`                                                                                        | Gmail mail server IP used in this simulation                           |
| HELO / host        | `mail-wm1-f49.google.com`                                                                              | Gmail SMTP host                                                        |
| Sender domain      | `gmail.com`                                                                                            | Authenticated sending domain                                           |
| Recipient domain   | `outlook.com`                                                                                          | Lab recipient domain                                                   |
| Phish domain       | `billing-login.example`                                                                                | Fake billing portal domain in link                                     |
| Full URL           | `https://billing-login.example/invoice?id=87421&user=testuser`                                         | CTA link in email HTML                                                 |
| Full URL (defang)  | `hxxps://billing-login[.]example/invoice?id=87421&user=testuser`                                      | Defanged for safe sharing                                              |
| File name          | `Invoice_87421.docx`                                                                                   | Attached “invoice”                                                     |
| File hash (SHA256) | `A62EA44249D1E3E52A9032F0EF14264DFD9F1C2923E3176993B0AEEDB976399F`                                     | Hash of benign lab attachment                                          |
| Message-ID         | `<CALaKBZyQuPS6oKuwy=JkdqQ6qBjBCfKHVJTq2C09n7S8Lod8cA@mail.gmail.com>`                                 | Gmail Message-ID                                                       |
| M365 Msg ID        | `44de9af8-2a64-41d1-4d71-08de27be6e36`                                                                 | Microsoft 365 network message ID                                       |
| Auth results       | `spf=pass; dkim=pass; dmarc=pass; compauth=pass`                                                       | Shows email passes standard authentication                             |
| Spam score (SCL)   | `1`                                                                                                    | Low spam confidence – likely inbox delivery                            |
