# SOC141: Phishing URL Detected — Compromised Endpoint

**Verdict:** True Positive
**Severity:** Critical
**Date:** 2026-05-23
**Analyst:** Umar Ahmed
**Case ID:** SOC141

---

## 1. Triage & Analysis

### Initial Alert

An endpoint detection alert fired on a workstation that had accessed a known malicious URL. The URL was observed in network telemetry and flagged by the threat intelligence platform.

**Malicious URL:**
```
hxxp://mogagrocol[.]ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io
```

### Analysis

The URL exhibits multiple indicators of a phishing infrastructure:

- **Suspicious domain:** `mogagrocol[.]ru` — a `.ru` TLD domain with no legitimate association with the impersonated brand.
- **Abuse of legitimate software path:** The URI path `/wp-content/plugins/akismet/fv/` mimics a WordPress plugin directory (`akismet`), a common technique to make malicious URLs appear benign at a glance. The `fv` subdirectory is not part of the legitimate Akismet plugin.
- **Email parameter exfiltration:** The query parameter `?email=ellie@letsdefend.io` indicates the attacker is harvesting email addresses, likely for targeted follow-on phishing or credential harvesting.
- **Protocol:** The use of `http://` (unencrypted) rather than `https://` is consistent with hastily deployed phishing infrastructure.

### Endpoint Impact

Upon investigation of the affected endpoint, the following was confirmed:

- The endpoint **downloaded a payload** from the malicious URL: `KBDYAK.exe`.
- `KBDYAK.exe` is a known malicious executable, consistent with a trojan or remote access tool (RAT) payload commonly delivered via phishing campaigns.
- **Only this single endpoint** was observed communicating with the threat infrastructure (`mogagrocol[.]ru`), indicating the phishing email was either targeted or that other recipients did not interact with the link.
- No lateral movement was observed from this endpoint at the time of analysis.

### File Analysis — KBDYAK.exe

| Attribute          | Value                                  |
|--------------------|----------------------------------------|
| File Name          | KBDYAK.exe                             |
| File Type          | PE32 Executable (Windows)              |
| Source URL         | `hxxp://mogagrocol[.]ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io` |
| Delivery Method    | Drive-by download via phishing link    |
| Observed Behavior  | Execution attempted; quarantined post-containment |

---

## 2. Containment

The following containment actions were executed immediately upon confirmation of compromise:

1. **Host Isolation** — The affected endpoint was isolated from the network via EDR, cutting all communication to and from the threat infrastructure. This prevented any potential C2 beaconing or data exfiltration.

2. **Payload Removal** — The malicious file `KBDYAK.exe` was located on the endpoint and removed. The file was quarantined for further forensic analysis.

3. **DNS Sinkhole** — The domain `mogagrocol[.]ru` was added to the internal DNS sinkhole and proxy blocklist to prevent any further access from any endpoint in the environment.

4. **Email Sweep** — A search was conducted across the email gateway for any messages containing the malicious URL or related indicators. No additional recipients were identified, confirming this was an isolated incident.

5. **Endpoint Rebuild** — The affected workstation was reimaged as a precautionary measure to ensure no persistence mechanisms were established.

---

## 3. Artifacts / IOCs

### Network Indicators

| Indicator                                | Type     | Description                                    |
|------------------------------------------|----------|------------------------------------------------|
| `mogagrocol[.]ru`                        | Domain   | C2 / phishing domain                           |
| `hxxp://mogagrocol[.]ru/wp-content/plugins/akismet/fv/index.php` | URL      | Malicious phishing URL (base path) |
| `hxxp://mogagrocol[.]ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io` | URL | Full malicious URL with email parameter |

### Host Indicators

| Indicator      | Type              | Description                          |
|----------------|-------------------|--------------------------------------|
| `KBDYAK.exe`   | File (Malicious)  | Trojan/RAT payload downloaded from C2 |

### Affected Asset

| Attribute   | Value                   |
|-------------|-------------------------|
| Hostname    | `[REDACTED]`            |
| IP Address  | `[REDACTED]`            |
| User        | `ellie@letsdefend.io`   |
| OS          | Windows 10              |

---

## 4. Detection Engineering

### Sigma Rule — Malicious URL Access from Endpoint

This Sigma rule detects when an endpoint process makes a network connection to a known malicious URL or domain, as logged by EDR, proxy, or DNS telemetry.

```yaml
title: Known Malicious URL Accessed from Endpoint
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: >
  Detects network connections from endpoint processes to known malicious URLs or domains
  associated with phishing campaigns and malware delivery. Matches on URL or domain
  observed in threat intelligence feeds.
author: Umar Ahmed
date: 2026-05-23
references:
  - https://github.com/SigmaHQ/sigma
tags:
  - attack.initial_access
  - attack.t1566.002  # Phishing: Spearphishing Link
  - attack.t1204.002  # User Execution: Malicious File
logsource:
  category: proxy
  product: any
detection:
  selection_url:
    - c-uri|contains: '/wp-content/plugins/akismet/fv/index.php'
    - c-uri|contains: 'mogagrocol'
  selection_domain:
    - r-dns|endswith: 'mogagrocol.ru'
    - qname|endswith: 'mogagrocol.ru'
  condition: selection_url or selection_domain
falsepositives:
  - Legitimate security research or threat intelligence platforms accessing the URL for analysis
  - Internal sandbox or detonation environments
level: high
---
# Variant: EDR-based detection for process launching malicious download
title: Suspicious File Download from Known Malicious Domain
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: experimental
description: >
  Detects when a browser or other process downloads an executable file from a known
  malicious domain associated with phishing infrastructure.
author: Umar Ahmed
date: 2026-05-23
tags:
  - attack.initial_access
  - attack.t1566.002
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_process:
    - Image|endswith:
        - '\chrome.exe'
        - '\msedge.exe'
        - '\firefox.exe'
        - '\iexplore.exe'
  selection_url:
    - CommandLine|contains: 'mogagrocol.ru'
  selection_file:
    - TargetFilename|endswith: 'KBDYAK.exe'
  condition: selection_process and selection_url or selection_file
falsepositives:
  - Unlikely; executable downloads from unknown .ru domains are highly suspicious
level: critical
```

### Splunk Query — Proxy & DNS Log Hunt

The following Splunk queries can be used to retroactively hunt for any access to the malicious infrastructure across proxy and DNS logs.

#### Proxy Log Hunt

```spl
index=proxy OR index=web
(url="*mogagrocol.ru*" OR uri="*mogagrocol.ru*" OR dest_host="*mogagrocol.ru*")
| eval url=coalesce(url, uri)
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(url) as urls values(src_ip) as source_ips values(user) as users by dest_host
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
| table dest_host, urls, source_ips, users, first_seen, last_seen, count
```

#### DNS Log Hunt

```spl
index=dns OR index=network
(query="*mogagrocol.ru*" OR dest_host="*mogagrocol.ru*" OR qname="*mogagrocol.ru*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen values(query) as dns_queries values(src_ip) as source_ips values(dest_ip) as resolved_ips by dest_host
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
| table dest_host, dns_queries, source_ips, resolved_ips, first_seen, last_seen, count
```

#### Combined Hunt — Any Communication with Threat Infrastructure

```spl
(index=proxy OR index=web OR index=dns OR index=network OR index=edr)
(mogagrocol.ru OR KBDYAK.exe)
| eval ioc_type=case(
    match(url, "mogagrocol\.ru") OR match(query, "mogagrocol\.ru"), "Network",
    match(process_name, "KBDYAK\.exe") OR match(file_name, "KBDYAK\.exe"), "Host",
    true(), "Unknown"
)
| stats count values(ioc_type) as ioc_types earliest(_time) as first_seen latest(_time) as last_seen by src_ip, dest_host
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
```

---

## Summary

SOC141 was confirmed as a **True Positive** phishing incident. A single endpoint accessed a malicious URL (`hxxp://mogagrocol[.]ru/wp-content/plugins/akismet/fv/index.php?email=ellie@letsdefend.io`) and downloaded the payload `KBDYAK.exe`. The affected host was isolated, the payload was removed, and the domain was blocklisted. No lateral movement or additional affected endpoints were identified. Detection rules and hunt queries have been developed to identify any future access to this threat infrastructure.

---

*Last updated: 2026-05-23 by Umar Ahmed*
