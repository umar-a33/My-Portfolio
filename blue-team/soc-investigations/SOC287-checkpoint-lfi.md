# SOC287: Checkpoint Gateway — CVE-2024-24919 Local File Inclusion

**Verdict:** 🔴 True Positive
**Severity:** Critical
**Analyst:** Umar Ahmed
**Date:** 2026-05-23
**Case ID:** SOC287

---

## 1. Triage & Analysis

### Alert Summary

A network IDS/IPS alert fired on traffic targeting the Checkpoint Security Gateway at `172.16.20.146`, indicating a directory traversal / local file inclusion (LFI) attempt consistent with **CVE-2024-24919**. The source IP `203.160.68.12` is an external address geolocated to China, with no legitimate business relationship to the organization.

### Vulnerability Context — CVE-2024-24919

CVE-2024-24919 is a critical unauthenticated arbitrary file read vulnerability affecting Check Point Quantum Security Gateway and CloudGuard Network Security appliances. The flaw resides in the web administrative interface and allows a remote, unauthenticated attacker to read arbitrary files on the underlying operating system via directory traversal sequences. A CVSS score of **7.5 (High)** was assigned, though the practical impact is critical when leveraged to extract credential files, configuration files, or sensitive system data.

### Affected Asset

| Field | Value |
|---|---|
| **Hostname** | CHK-GW-01 (Checkpoint Security Gateway) |
| **IP Address** | `172.16.20.146` |
| **Vendor** | Check Point |
| **Product** | Quantum Security Gateway / CloudGuard Network Security |
| **Role** | Perimeter firewall / VPN gateway |
| **Exposure** | WAN-facing (administrative interface reachable from internet) |

### Investigation Steps

1. **Alert Review:** The IDS signature for CVE-2024-24919 triggered on an inbound HTTP request to the gateway's web admin interface. The request URI contained a directory traversal payload targeting `/etc/passwd`.

2. **HTTP Transaction Analysis:** Reviewed full packet capture and web proxy logs for the session:

   | Request # | Payload | Response | Status |
   |---|---|---|---|
   | 1 | `GET /../../../etc/passwd` | File contents returned | **HTTP 200** |
   | 2 | `GET /../../../etc/shadow` | Access denied | **HTTP 403** |

   The first request successfully returned the contents of `/etc/passwd` — confirming the LFI vulnerability is exploitable on this gateway. The second request for `/etc/shadow` was blocked (HTTP 403), likely by an intermediary WAF rule or filesystem permission on the gateway OS.

3. **Source IP Enrichment:** The source IP `203.160.68.12` was enriched via threat intelligence platforms:

   | Attribute | Value |
   |---|---|
   | **IP Address** | `203.160.68.12` |
   | **Geolocation** | China |
   | **ASN** | AS4808 (China Unicom Beijing Province Network) |
   | **Threat Reputation** | Flagged on multiple TI feeds as a known scanning/hostile source |
   | **Historical Activity** | Observed conducting vulnerability scanning and exploitation attempts against perimeter infrastructure |

4. **Scope Assessment:** Reviewed all HTTP logs for the gateway over the preceding 72 hours. No prior access from `203.160.68.12` was observed. The two requests above constitute the full extent of the exploitation attempt from this source.

5. **Credential Exposure Assessment:** The successful retrieval of `/etc/passwd` confirms that local user account usernames on the gateway appliance are exposed. While the file does not contain password hashes (which reside in `/etc/shadow`), the enumerated usernames provide an attacker with valid account names for subsequent brute-force or credential-stuffing attacks against the gateway's administrative interface.

### Verdict Justification

This is a **True Positive** incident. The totality of evidence confirms active exploitation:

- Unauthenticated external attacker (`203.160.68.12`, China) sent directory traversal payloads to the Checkpoint gateway
- The first payload (`../../etc/passwd`) returned **HTTP 200** with file contents — confirming successful arbitrary file read
- The vulnerability matches **CVE-2024-24919**, a known critical flaw in Check Point Security Gateway
- No legitimate business justification exists for external access to the gateway's administrative interface

The incident represents an active exploitation attempt against perimeter infrastructure with confirmed partial success (file read achieved).

---

## 2. Containment

The following containment actions were executed immediately upon confirming the True Positive verdict:

1. **Gateway Isolation** — The Checkpoint Security Gateway (`172.16.20.146`) was isolated from the network to prevent further exploitation. Traffic was rerouted through a standby gateway to maintain perimeter security coverage during the incident.

2. **Source IP Blocked** — The IP `203.160.68.12` was added to:
   - Perimeter firewall deny-list (immediate effect)
   - IDS/IPS block rule with high priority
   - Threat Intelligence Platform (TIP) as a confirmed hostile indicator

3. **Forensic Imaging** — The incident was escalated to the digital forensics team for full forensic imaging of the gateway appliance prior to any remediation. This preserves evidence of the exploitation attempt and any potential post-exploitation activity.

4. **Administrative Interface Restricted** — As an interim measure, the web administrative interface was restricted to management-network-only access, removing WAN-facing exposure until patching is complete.

5. **Credential Reset Recommended** — A full credential reset was recommended for all administrative accounts on the Check Point gateway, including:
   - Web admin accounts
   - CLI/SSH accounts
   - API keys and certificates
   - Any shared service accounts with access to the gateway

6. **Lateral Movement Hunt** — A retrospective hunt was initiated across SIEM and network logs to determine whether the attacker leveraged any information obtained from `/etc/passwd` to attempt authentication against the gateway or any other internal systems. *(Results to be documented upon completion.)*

7. **Patch Deployment** — Check Point has released a security hotfix for CVE-2024-24919. Deployment of the patch to the affected gateway was scheduled as a **P1 emergency change** following forensic imaging.

---

## 3. Artifacts / IOCs

### Network Indicators

| Indicator | Type | Description |
|---|---|---|
| `203.160.68.12` | IPv4 | Attacker source IP (China, AS4808 China Unicom) |
| `GET /../../../etc/passwd` | HTTP Request | Directory traversal payload targeting `/etc/passwd` |
| `GET /../../../etc/shadow` | HTTP Request | Directory traversal payload targeting `/etc/shadow` (blocked) |

### Host Indicators

| Indicator | Type | Description |
|---|---|---|
| `172.16.20.146` | IPv4 | Compromised Checkpoint Security Gateway |
| `/etc/passwd` | File | Successfully read via LFI — local usernames exposed |
| `/etc/shadow` | File | Access attempted but blocked (HTTP 403) |

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of CVE-2024-24919 on WAN-facing gateway |
| Discovery | File and Directory Discovery | T1083 | Reading `/etc/passwd` to enumerate local accounts |
| Credential Access | OS Credential Dumping: /etc/passwd and /etc/shadow | T1003.008 | Attempted extraction of credential files via LFI |

### Confidence Assessment

- **Exploitation Attempt:** **High** — Confirmed by IDS alert, HTTP 200 response with file contents, and matching CVE signature.
- **File Read Success:** **High** — `/etc/passwd` contents were returned to the attacker. The extent of data exfiltrated is limited to this single file.
- **Attribution:** **Medium** — Source IP is confirmed hostile and geolocated to China, but the specific threat actor group has not been identified.
- **Ongoing Risk:** **High** — The gateway remains vulnerable until patched. Exposed usernames reduce the attack surface for credential-based follow-up attacks.

---

## 4. Detection Engineering

### Sigma Rule — Directory Traversal Attempt on Network Gateway

The following Sigma rule detects directory traversal attempts against network infrastructure devices (firewalls, gateways, VPN concentrators) as observed in web server, proxy, or IDS/IPS telemetry.

```yaml
title: Directory Traversal Attempt on Network Gateway - CVE-2024-24919
id: d4e5f6a7-b8c9-0123-defa-2345678901bc
status: production
description: >
  Detects directory traversal attempts targeting network gateway and firewall
  appliances, consistent with CVE-2024-24919 exploitation. Matches on common
  traversal patterns (../, ..%2f, %2e%2e/) directed at sensitive system files
  such as /etc/passwd, /etc/shadow, and configuration files. Applicable to
  web server, reverse proxy, WAF, and IDS/IPS telemetry.
author: Umar Ahmed
date: 2026-05-23
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-24919
  - https://support.checkpoint.com/results/sk/sk182146
  - https://attack.mitre.org/techniques/T1190/
tags:
  - attack.initial_access
  - attack.t1190
  - attack.t1083
  - attack.t1003.008
logsource:
  category: web_server
  product: any
detection:
  selection_traversal:
    - cs-uri-query|contains:
        - '../'
        - '..\\'
        - '..%2f'
        - '..%2F'
        - '%2e%2e%2f'
        - '%2e%2e/'
        - '....//'
        - '....\\'
  selection_target:
    - cs-uri-query|contains:
        - '/etc/passwd'
        - '/etc/shadow'
        - '/etc/hosts'
        - '/etc/issue'
        - 'c:\\windows\\'
        - 'c:\\winnt\\'
        - '/proc/self/'
        - 'web.config'
        - '.ssh/id_rsa'
  selection_status:
    - sc-status:
        - 200
        - 201
  filter_internal:
    - src_ip|cidr:
        - '10.0.0.0/8'
        - '172.16.0.0/12'
        - '192.168.0.0/16'
  condition: selection_traversal and selection_target and selection_status and not filter_internal
falsepositives:
  - Legitimate vulnerability scanning by authorized internal security teams (filter these via src_ip allow-listing)
  - Web application firewalls performing automated rule testing
  - Rare cases where internal applications use path parameters that resemble traversal sequences
level: critical
```

**Tuning notes:**
- The `filter_internal` block excludes RFC1918 source IPs to focus on external threats. Adjust CIDR ranges to match your internal address space.
- For environments with authorized vulnerability scanners, add specific scanner IPs to the filter.
- The `selection_status` filter ensures the rule only fires when the server returned a successful response (HTTP 200/201), reducing noise from blocked attempts. Remove this filter if you want to detect all traversal attempts regardless of success.
- Consider adding a correlation condition that triggers on 3+ traversal attempts from the same source within 5 minutes to catch automated exploitation tools.

---

### Splunk Query — HTTP Log Hunt for Directory Traversal

The following Splunk queries hunt across HTTP access logs, proxy logs, and IDS/IPS alerts for directory traversal patterns indicative of CVE-2024-24919 exploitation or similar LFI attacks.

#### Query 1: Directory Traversal Detection — All Gateways

```spl
index=web OR index=proxy OR index=ids OR index=waf
(uri="*../../*" OR uri="*..%2f*" OR uri="*%2e%2e*" OR url="*../../*" OR url="*..%2f*" OR cs-uri="*../../*")
AND (uri="*etc/passwd*" OR uri="*etc/shadow*" OR uri="*etc/hosts*" OR uri="*web.config*" OR uri="*id_rsa*"
     OR url="*etc/passwd*" OR url="*etc/shadow*" OR url="*etc/hosts*")
| eval traversal_pattern=case(
    match(uri, "\.\./"), "dotdot_slash",
    match(uri, "\.\.\\\\"), "dotdot_backslash",
    match(uri, "%2e%2e"), "encoded_dotdot",
    match(uri, "\.\.%2f"), "mixed_encoding",
    true(), "other"
  )
| eval target_file=case(
    match(uri, "etc/passwd"), "/etc/passwd",
    match(uri, "etc/shadow"), "/etc/shadow",
    match(uri, "etc/hosts"), "/etc/hosts",
    match(uri, "web\\.config"), "web.config",
    match(uri, "id_rsa"), "SSH Private Key",
    true(), "Unknown"
  )
| eval is_success=if(sc_status>=200 AND sc_status<300, "SUCCESS", "BLOCKED/FAILED")
| stats count as attempt_count
        values(uri) as uris
        values(sc_status) as response_codes
        values(is_success) as outcomes
        values(traversal_pattern) as patterns_used
        earliest(_time) as first_seen
        latest(_time) as last_seen
      by src_ip, dest_ip, dest_host, target_file
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| eval risk=case(
    is_success="SUCCESS" AND target_file="/etc/shadow", "CRITICAL",
    is_success="SUCCESS" AND target_file="/etc/passwd", "HIGH",
    is_success="SUCCESS", "HIGH",
    attempt_count>=5, "HIGH",
    true(), "MEDIUM"
  )
| sort - attempt_count
| table src_ip, dest_ip, dest_host, target_file, risk, outcomes, patterns_used, uris, response_codes, first_seen, last_seen, attempt_count
```

**Query breakdown:**
- Searches web, proxy, IDS, and WAF indices for directory traversal patterns combined with sensitive file targets.
- Classifies the traversal technique used (plain, encoded, mixed) and the targeted file.
- Evaluates whether the attempt was successful based on HTTP response code.
- Aggregates by source IP, destination, and target file to identify attack scope.
- Assigns a risk rating based on success status and target file sensitivity.

#### Query 2: CVE-2024-24919 Specific Hunt — Check Point Gateway

```spl
index=web OR index=proxy OR index=ids OR index=firewall
(dest_ip="172.16.20.146" OR dest_host="*checkpoint*" OR dest_host="*chk-gw*")
| eval has_traversal=if(match(uri, "\.\./") OR match(uri, "%2e%2e") OR match(uri, "\.\.\\\\"), 1, 0)
| eval has_sensitive_target=if(match(uri, "etc/passwd") OR match(uri, "etc/shadow") OR match(uri, "etc/hosts") OR match(uri, "conf/") OR match(uri, "config"), 1, 0)
| where has_traversal=1 OR has_sensitive_target=1
| eval attack_type=case(
    has_traversal=1 AND has_sensitive_target=1, "LFI_Exploitation",
    has_traversal=1, "Traversal_Attempt",
    has_sensitive_target=1, "Sensitive_File_Access",
    true(), "Other"
  )
| table _time, src_ip, dest_ip, dest_host, method, uri, sc_status, bytes_out, user_agent, attack_type
| sort _time
```

**Query breakdown:**
- Focused hunt on the affected Checkpoint gateway (`172.16.20.146`).
- Flags any request containing directory traversal patterns or sensitive file access.
- Classifies each event by attack type for rapid triage.
- Sorted chronologically to build an exploitation timeline.

#### Query 3: Retrospective Hunt — All External Traversal Attempts (30-Day)

```spl
index=web OR index=proxy OR index=ids earliest=-30d
| where NOT cidr(src_ip, "10.0.0.0/8") AND NOT cidr(src_ip, "172.16.0.0/12") AND NOT cidr(src_ip, "192.168.0.0/16")
| eval has_traversal=if(match(uri, "\.\./") OR match(uri, "%2e%2e") OR match(uri, "\.\.\\\\") OR match(uri, "....//"), 1, 0)
| where has_traversal=1
| eval dest_category=case(
    match(dest_host, "checkpoint") OR match(dest_host, "firewall") OR match(dest_host, "gw-"), "Gateway/Firewall",
    match(dest_host, "vpn"), "VPN Concentrator",
    match(dest_host, "router") OR match(dest_host, "switch"), "Network Infrastructure",
    true(), "Other"
  )
| stats count as attempt_count
        dc(dest_ip) as unique_targets
        values(dest_ip) as target_ips
        values(dest_host) as target_hosts
        values(uri) as traversal_uris
        earliest(_time) as first_seen
        latest(_time) as last_seen
      by src_ip, dest_category
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| eval is_persistent=if(attempt_count >= 5, "persistent_scanner", "opportunistic")
| sort - attempt_count
| table src_ip, dest_category, is_persistent, unique_targets, target_ips, target_hosts, traversal_uris, first_seen, last_seen, attempt_count
```

**Query breakdown:**
- Broad 30-day retrospective hunt for any external directory traversal attempts.
- Excludes internal source IPs to focus on internet-originating threats.
- Categorizes targets by infrastructure type to prioritize gateway/firewall alerts.
- Identifies persistent scanners (5+ attempts) vs. opportunistic probes.
- Useful for identifying whether the CVE-2024-24919 exploitation was a targeted attack or part of a broader scanning campaign.

**Recommended scheduled searches:**
- Query 1: Run every 15 minutes with a 1-hour lookback. Alert on any result with `risk=HIGH` or `risk=CRITICAL`.
- Query 2: Run every 15 minutes with a 1-hour lookback. Alert on any `LFI_Exploitation` classification.
- Query 3: Run daily with a 24-hour lookback. Alert on any `persistent_scanner` results targeting `Gateway/Firewall` infrastructure.

---

## Summary

SOC287 was confirmed as a **True Positive** exploitation attempt against the Checkpoint Security Gateway (`172.16.20.146`). An external attacker (`203.160.68.12`, China, AS4808) exploited CVE-2024-24919 — an unauthenticated local file inclusion vulnerability — to successfully read `/etc/passwd` from the gateway appliance. A subsequent attempt to read `/etc/shadow` was blocked (HTTP 403). The gateway was isolated, the source IP was blocklisted, and the incident was escalated for forensic imaging. A full credential reset was recommended for all gateway administrative accounts, and patch deployment was scheduled as a P1 emergency change. Detection rules and hunt queries have been developed to identify any future exploitation of this vulnerability.

---

*Case status: True Positive — Exploitation confirmed. Gateway isolated. Forensic imaging in progress. Patch deployment pending.*
*Last updated: 2026-05-23 by Umar Ahmed*
