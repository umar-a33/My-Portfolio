# SOC140: Malicious Phishing Mail with Attachment

**Verdict:** 🔴 True Positive  
**Severity:** High  
**Analyst:** Umar Ahmed  
**Date:** 2026-05-23  
**Case ID:** SOC140  

---

## 1. Triage & Analysis

### Alert Summary

An inbound email was flagged by the organization's email security gateway as a potential phishing attempt carrying a malicious attachment. The message was automatically quarantined before reaching the recipient's inbox.

### Email Details

| Field | Value |
|---|---|
| **From** | `aaronluo@cmail.carleton.ca` |
| **To** | `mark@letsdefend.io` |
| **Subject** | *Invoice Attached — Action Required* |
| **Originating IP** | `189.162.189.15` |
| **Protocol** | SMTP (inbound) |
| **Attachment** | `Invoice_2026_May.docm` (184 KB) |
| **Delivery Status** | **Blocked** — Gateway quarantine |

### Analysis

1. **Sender Envelope:** The sender address `aaronluo@cmail.carleton.ca` uses a legitimate Carleton University domain, but the originating IP `189.162.189.15` does not resolve to any known Carleton University mail infrastructure. SPF check **failed** — the IP is not authorized to send on behalf of `cmail.carleton.ca`, indicating domain spoofing.

2. **Attachment Analysis:** The attached file `Invoice_2026_May.docm` is a Word document with embedded macros (`.docm` format). Static analysis revealed:
   - VBA macro auto-executes on document open (`Document_Open` subroutine)
   - Macro contains obfuscated PowerShell commands
   - Payload attempts to reach out to an external C2 endpoint

3. **Sandbox / Hybrid Analysis:** The file was submitted to Hybrid Analysis for detonation. Result: **100% malicious** — confirmed as a dropper that downloads and executes a second-stage payload. Behavioral indicators included:
   - Process injection into `svchost.exe`
   - Registry persistence key creation (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`)
   - Outbound connection to a known malicious IP over HTTPS (port 443)

4. **Gateway Action:** The email security gateway correctly identified the attachment as a macro-enabled document and **blocked delivery** before it reached the recipient. The message was moved to the quarantine store.

### Verdict Justification

This is a **True Positive**. The email exhibits multiple phishing and malware delivery indicators: spoofed sender domain, SPF failure, macro-laden attachment, 100% malicious sandbox score, and confirmed C2 behavior. The gateway's automated blocking prevented a potential compromise.

---

## 2. Containment

The following containment actions were executed immediately upon confirming the True Positive verdict:

1. **Sender IP Blocked** — IP `189.162.189.15` was added to the email gateway deny-list and the perimeter firewall block-list to prevent any further communication from this source.

2. **Sender Domain Flagged** — While `cmail.carleton.ca` is a legitimate domain, the spoofed sender address `aaronluo@cmail.carleton.ca` was added to the organization's internal threat intelligence feed and the email gateway's custom block-list for enhanced scrutiny of future messages.

3. **Attachment Hash Distributed** — The SHA-256 hash of `Invoice_2026_May.docm` was shared with the email gateway, endpoint detection and response (EDR) platform, and the organization's threat intel platform to enable detection across all security layers.

4. **Quarantine Verified** — Confirmed the email remains in gateway quarantine and was not delivered to any mailbox. No end-user interaction with the attachment occurred.

5. **Hunt for Similar Emails** — A retrospective search was conducted across the email gateway logs for any other messages from `189.162.189.15` or containing `.docm`/`.xlsm` attachments with similar subject lines in the past 30 days. No additional matches were found.

---

## 3. Artifacts / IOCs

### Network Indicators

| Indicator | Type | Description |
|---|---|---|
| `189.162.189.15` | IPv4 | Originating IP of phishing email |
| `cmail.carleton.ca` | Domain | Spoofed sender domain |

### File Indicators

| Indicator | Type | Description |
|---|---|---|
| `Invoice_2026_May.docm` | Filename | Malicious macro-enabled Word attachment |
| `SHA256:3a7f...e9b2` | File Hash | SHA-256 of the malicious attachment *(redacted for public repo)* |

### Host-Based Indicators (from sandbox detonation)

| Indicator | Type | Description |
|---|---|---|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\UpdateCheck` | Registry Key | Persistence mechanism created by payload |
| `svchost.exe` (injected) | Process | Target of process injection by second-stage payload |

### Confidence Assessment

- **IP Reputation:** High confidence — IP is not associated with any legitimate mail infrastructure for the claimed sending domain.
- **File Maliciousness:** High confidence — 100% malicious score on Hybrid Analysis with confirmed C2 behavior.
- **Sender Authenticity:** High confidence — SPF failure confirms spoofing.

---

## 4. Detection Engineering

### Sigma Rule: Malicious Macro-Enabled Email Attachments

The following Sigma rule detects emails delivered through the gateway that contain macro-enabled Office documents (`.docm`, `.xlsm`) — a common initial access vector for phishing campaigns.

```yaml
title: Malicious Macro-Enabled Office Document Attachment
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: production
description: Detects inbound emails carrying macro-enabled Office documents (.docm, .xlsm) which are frequently used as malware delivery vehicles in phishing campaigns.
author: Umar Ahmed
date: 2026-05-23
references:
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1204/002/
logsource:
  category: proxy
  product: email_gateway
detection:
  selection:
    event_type: email_delivered
    attachment_extension:
      - '.docm'
      - '.xlsm'
  condition: selection
falsepositives:
  - Legitimate business documents with macros sent by trusted internal or partner senders
  - Automated reporting systems that distribute macro-enabled templates
level: high
tags:
  - attack.initial_access
  - attack.t1566.001
  - attack.execution
  - attack.t1204.002
```

**Notes on tuning:**
- In production, consider adding an allow-list for known trusted senders or partner domains to reduce false positives.
- Can be extended to include `.pptm` (PowerPoint macro-enabled) if the threat landscape warrants it.
- Pair with attachment sandbox detonation results for higher-fidelity alerting.

---

### Splunk Query: Email Gateway Log Hunt

The following Splunk SPL query hunts email gateway logs for messages originating from the malicious IP or containing macro-enabled attachments, useful for retrospective threat hunting and incident validation.

```spl
index=email_gateway sourcetype=gateway:logs
| eval attachment_ext=lower(attachment_filename)
| where (src_ip="189.162.189.15")
   OR (match(attachment_ext, "\.(docm|xlsm)$") AND action="delivered")
| eval risk_score=case(
    src_ip="189.162.189.15" AND match(attachment_ext, "\.(docm|xlsm)$"), "critical",
    src_ip="189.162.189.15", "high",
    match(attachment_ext, "\.(docm|xlsm)$"), "medium",
    true(), "low"
  )
| table _time, src_ip, sender, recipient, subject, attachment_filename, action, risk_score
| sort - _time
```

**Query breakdown:**
- Searches the `email_gateway` index for all gateway log events.
- Filters for messages from the known-bad IP `189.162.189.15` **OR** any delivered emails with `.docm`/`.xlsm` attachments.
- Assigns a `risk_score` to prioritize triage: messages matching both criteria are flagged as `critical`.
- Results are sorted by time (newest first) for efficient review.

**Recommended scheduled search:** Run every 15 minutes with a 24-hour lookback window. Alert on `critical` and `high` risk scores.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| T+0:00 | Phishing email received by gateway from `189.162.189.15` |
| T+0:02 | Gateway scans attachment; macro-enabled document detected |
| T+0:03 | Email quarantined — delivery blocked |
| T+0:05 | Alert generated and assigned to SOC analyst |
| T+0:15 | Analyst begins triage — SPF check fails, sender IP mismatch identified |
| T+0:30 | Attachment submitted to Hybrid Analysis |
| T+2:00 | Hybrid Analysis returns 100% malicious verdict |
| T+2:15 | Verdict confirmed as True Positive |
| T+2:30 | Containment actions executed (IP/domain block, hash distribution) |
| T+3:00 | Retrospective hunt completed — no additional matches |
| T+4:00 | Case closed; detection rules updated |

---

## Lessons Learned & Recommendations

1. **Gateway effectiveness:** The email gateway's macro-enabled document policy correctly blocked this threat. Ensure this policy remains enforced and is regularly audited.

2. **User awareness:** Even though delivery was blocked, the phishing email used a plausible pretext ("Invoice Attached — Action Required"). Reinforce user training on verifying sender authenticity before opening attachments, especially macro-enabled documents.

3. **Block macro-enabled attachments by default:** Consider implementing a gateway policy to strip or block all macro-enabled Office attachments (`docm`, `xlsm`, `pptm`) from external senders, with an exception process for verified business needs.

4. **Threat intel integration:** The sender IP and file hash should be automatically ingested into the organization's TIP (Threat Intelligence Platform) to enrich future detection and correlation.

---

*Case closed — True Positive. No endpoint compromise occurred.*
