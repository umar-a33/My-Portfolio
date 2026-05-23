## 🟢 SOC120: Phishing Mail Detected (Internal to Internal)

**Verdict:** False Positive

**Analyst:** Umar Ahmed
**Date:** 2025-06-18
**Severity:** Low — Informational
**Ticket ID:** INC-2025-04712
**Status:** Closed

---

### 1. Triage & Analysis

* **Alert Trigger:** The email security gateway fired a "Phishing Mail Detected" alert on an internal-to-internal SMTP exchange. The rule was designed to catch credential-harvesting lures and spoofed internal communications.
* **Sender:** `john@letsdefend.io`
* **Recipient:** `susie@letsdefend.io`
* **Subject:** "Updated Q3 Policy Documents — Please Review"
* **Attachment Count:** 0
* **Extracted Artifacts:** Pulled the `.eml` from the mail gateway quarantine for manual review.

**Investigation Steps:**

1. **Email Header Analysis:** Opened the `.eml` and confirmed the `From:` header aligned with a valid internal mailbox (`john@letsdefend.io`). The `Return-Path` and `Reply-To` fields matched — no signs of header tampering or display-name spoofing.
2. **Attachment & Link Inspection:** The email body contained no file attachments and no embedded URLs beyond an internal SharePoint link (`https://letsdefend.sharepoint.com/...`) that resolved to a legitimate on-premises resource.
3. **Mail Routing Analysis:** Reviewed Exchange server transport logs. The message traversed the expected internal mail hop (`EXCH-MAIL01 → EXCH-MAIL02 → Susie's Mailbox`) with no anomalous relays, external forwarding, or unauthorized connectors.
4. **VirusTotal Enrichment:** Submitted the sender domain and the SHA-256 hash of the `.eml` to VirusTotal. Result: **0/72 vendors flagged** the content as malicious. Clean across all engines.
5. **User Confirmation:** Contacted John and Susie via Teams. Both confirmed the message was part of a routine internal policy review cycle. No credentials or sensitive data were solicited in the body.

**Conclusion:** The email was legitimate internal communication. The SIEM rule fired because the email body contained the phrase "please review" combined with a SharePoint URL — a pattern that matches the rule's heuristic for credential-harvesting lures.

---

### 2. Containment & Remediation

* **Containment:** No containment action required. No hostile infrastructure was involved, and no endpoint compromise was observed.
* **Ticket Update:** Updated ticket `INC-2025-04712` with full analysis notes, VirusTotal results, and user confirmation. Marked as **Closed — False Positive**.
* **Recommended Action — SIEM Rule Tuning:** Recommended to the detection engineering team that the phishing correlation rule be adjusted to reduce false positives on verified internal-to-internal mail. Specific tuning suggestion: add an exception condition for `sender_domain == recipient_domain` when both resolve to the organization's accepted domains list, **unless** the message body matches known credential-harvesting lure patterns (e.g., "verify your account," "reset password," "unusual login activity").
* **MTTR Reduction Recommendation:** Proposed adding a SentinelDefend enrichment step that auto-resolves sender/recipient domain matches against the internal directory via LDAP lookup — if both parties are confirmed active employees, the alert severity drops automatically from Medium to Low, reducing analyst triage load.

---

### 3. Artifacts (IOCs)

| Artifact Type | Value | Verdict |
|---|---|---|
| Sender Address | `john@letsdefend.io` | Benign — Valid internal user |
| Recipient Address | `susie@letsdefend.io` | Benign — Valid internal user |
| Sender IP (SMTP) | `10.10.20.15` (EXCH-MAIL01) | Benign — Internal mail server |
| Attachment SHA-256 | `N/A` (no attachments) | — |
| Embedded URL | `https://letsdefend.sharepoint.com/...` | Benign — Legitimate internal resource |
| `.eml` SHA-256 | Clean on VirusTotal (0/72) | Benign |
| VirusTotal Result | 0 detections | Benign |

**No hostile IOCs were identified.** No blocklist updates were necessary.

---

### 4. Detection Engineering

#### Sigma Rule: Internal Phishing Mail Alert

The following Sigma rule is designed to catch genuine internal-to-internal phishing attempts — such as when a compromised internal account is leveraged to send lure emails — while avoiding false positives from routine internal mail:

```yaml
title: Phishing Mail Detected - Internal to Internal
id: 8f3c1a2e-9b4d-4e71-a6f3-1d5c7b9e2f04
status: production
description: >
  Detects potential phishing emails sent from an internal sender to an internal recipient
  that contain known credential-harvesting keywords or embedded links. Tuned to reduce
  false positives on routine internal communications.
author: Umar Ahmed
date: 2025/06/18
logsource:
  product: emailsecurity
  service: mailgateway
detection:
  selection:
    event_type: "Email.Delivered"
    sender_domain|endswith: "letsdefend.io"
    recipient_domain|endswith: "letsdefend.io"
    alert_type: "Phishing Mail Detected"
  keywords:
    - "verify your account"
    - "reset your password"
    - "unusual activity"
    - "account suspended"
    - "confirm your identity"
    - "urgent action required"
    - "click here to"
    - "login to your account"
  condition: selection and keywords
  filter:
    - sender: "noreply@letsdefend.io"
    - sender: "alerts@letsdefend.io"
    - sender: "mailer-daemon@letsdefend.io"
  filter_out:
    subject|contains:
      - "RE:"
      - "FWD:"
    body|contains:
      - "teams meeting"
      - "project update"
      - "status report"
falsepositives:
  - Legitimate automated system alerts from known internal senders
  - Routine internal mail containing benign links (SharePoint, Confluence)
  - Internal phishing awareness test campaigns
level: medium
tags:
  - attack.initial_access
  - attack.t1566.001
```

#### SIEM Tuning Recommendations

To reduce false-positive noise from the internal phishing detection rule, the following SIEM correlation tuning actions are recommended:

1. **Domain-Aware Exception Logic:** If `sender_domain == recipient_domain` and both resolve to the organization's accepted domains, downgrade alert severity to **Low** unless the body matches known lure keywords (as defined in the Sigma rule above). This alone is expected to reduce false positives on this rule by ~60%.

2. **Sender Reputation Cache:** Implement a lookup against Active Directory to confirm both sender and recipient are active employee accounts with no prior security flags. Auto-attach the AD risk score to the alert payload.

3. **Exclude Known Internal Services:** Filter out emails originating from known internal services (e.g., `noreply@`, `alerts@`, `mailer-daemon@`) where the sender is a confirmed system mailbox.

4. **Body Content Analysis Weighting:** Instead of a single keyword match triggering an alert, require a weighted threshold — for example, at least two of the following must be present: (a) suspicious keyword, (b) embedded URL not matching the organization's domain whitelist, (c) urgency language. This reduces noise from emails that happen to contain one benign keyword like "review" alongside an internal link.

5. **Time-Decay Deduplication:** Suppress duplicate alerts for the same sender-recipient pair within a 24-hour window unless the message content differs significantly (e.g., new URLs or attachments are introduced).

6. **Feedback Loop Integration:** Connect analyst verdicts (True Positive / False Positive) back into the SIEM via a structured feedback endpoint. Use this data to retrain the keyword list and threshold weights on a quarterly basis.

**Expected Outcome:** These tuning changes should reduce false-positive volume on internal-to-internal phishing rules by an estimated 55–65%, freeing analyst capacity for higher-fidelity alerts while maintaining coverage against compromised internal accounts.

---

*End of report — Umar Ahmed, SOC Analyst*
