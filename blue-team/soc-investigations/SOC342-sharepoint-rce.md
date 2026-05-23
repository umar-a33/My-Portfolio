# SOC342: SharePoint RCE — CVE-2025-53770 Exploitation Attempt

**Verdict:** 🔴 True Positive
**Severity:** Critical
**Analyst:** Umar Ahmed
**Date:** 2026-05-23
**Case ID:** SOC342

---

## 1. Triage & Analysis

### Alert Summary

A critical alert fired on the SIEM indicating a potential Remote Code Execution (RCE) attempt against the organization's SharePoint server (`SharePoint01`, `172.16.20.17`). The alert was triggered by an anomalous HTTP POST request to `ToolPane.aspx` originating from an external source IP — a pattern consistent with active exploitation of **CVE-2025-53770**, a critical deserialization vulnerability in Microsoft SharePoint Server that allows unauthenticated remote code execution.

### Endpoint Details

| Field | Value |
|---|---|
| **Hostname** | SharePoint01 |
| **IP Address** | `172.16.20.17` |
| **Role** | Microsoft SharePoint Server (on-premises) |
| **OS** | Windows Server 2019 |
| **Attack Vector** | External → Internal (HTTP POST to `ToolPane.aspx`) |
| **CVE** | CVE-2025-53770 |

### Analysis

1. **Initial Exploitation Attempt:** An external IP sent an HTTP POST request to `http://172.16.20.17/_layouts/15/ToolPane.aspx` on the SharePoint server. The request contained a crafted payload in the request body, exploiting the deserialization vulnerability in `ToolPane.aspx` to achieve unauthenticated RCE. This technique is consistent with **CVE-2025-53770**, which targets the `Microsoft.SharePoint.WebControls.ToolPane` class and allows attackers to execute arbitrary code via a crafted `__VIEWSTATE` or similar deserialization payload.

2. **Machine Key Extraction:** Following successful exploitation, the attacker executed a base64-encoded PowerShell command on the SharePoint server. The decoded PowerShell script was designed to **extract the SharePoint machine key** (the `validationKey` and `decryptionKey` from the server's `web.config`). These keys are critical because they allow the attacker to:
   - Forge valid `__VIEWSTATE` payloads
   - Maintain persistent access to the SharePoint server
   - Sign malicious serialized objects that the server will trust

   The PowerShell command (decoded from base64) resembled:
   ```powershell
   [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.SharePoint") | Out-Null;
   $config = [Microsoft.SharePoint.Administration.SPFarm]::Local.Solutions;
   # ... extraction of machineKey validationKey and decryptionKey from web.config
   ```

3. **Payload Compilation via `csc.exe`:** After extracting the machine key, the attacker used the server's `csc.exe` (C# Compiler, located at `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`) to compile a custom .NET payload (`payload.exe`) directly on the SharePoint server. This technique — compiling malware on-target using legitimate system tools — is a form of **Living Off the Land (LOLBin)** that evades traditional file-based detection since no pre-built malicious binary was uploaded. The compiled `payload.exe` was then executed on the server.

4. **VirusTotal Analysis:**
   - **Source IP:** The external source IP was submitted to VirusTotal and flagged by multiple threat intelligence sources as a known malicious scanner/exploitation host.
   - **Payload MD5 (`02b4571470d83163d103112f07f1c434`):** The hash of the compiled `payload.exe` was submitted to VirusTotal and confirmed as malicious, with multiple AV engines detecting it as a trojan/backdoor. The detection ratio exceeded the threshold for a high-confidence positive.

5. **Attack Chain Summary:**

   ```
   External Attacker → HTTP POST to ToolPane.aspx (CVE-2025-53770)
     → Deserialization RCE on SharePoint01
       → Base64-encoded PowerShell extracts machine key
         → csc.exe compiles payload.exe on-target
           → payload.exe executed (persistence / C2 implant)
   ```

### Verdict Justification

This is a **True Positive** incident. The totality of evidence confirms active exploitation of the SharePoint server:

- HTTP POST to `ToolPane.aspx` from an external IP — consistent with CVE-2025-53770 exploitation
- Base64-encoded PowerShell executed on the server to extract the machine key (a known post-exploitation technique for SharePoint)
- `csc.exe` used to compile a custom payload on-target (LOLBin technique)
- VirusTotal confirmed both the source IP and the compiled payload MD5 (`02b4571470d83163d103112f07f1c434`) as malicious
- No legitimate business justification exists for any of the observed activity

The incident represents an active, successful compromise of a critical internal server with confirmed RCE, credential material theft, and custom payload deployment.

---

## 2. Containment

The following containment actions were executed immediately upon confirming the True Positive verdict:

1. **Host Isolation** — SharePoint01 (`172.16.20.17`) was isolated from the network via EDR, severing all inbound and outbound communication. This halted any active C2 session and prevented lateral movement from the compromised server.

2. **Escalation to Tier 2** — The incident was escalated to the Tier 2/Senior IR team for deep forensic analysis, including:
   - Full memory dump and forensic disk image acquisition
   - IIS log analysis for complete request reconstruction
   - Registry and file system timeline analysis
   - Machine key rotation and SharePoint farm integrity assessment

3. **Source IP Blocked** — The external attacker IP was added to:
   - Perimeter firewall deny-list (inbound and outbound)
   - IIS IP restriction rules on SharePoint01
   - EDR threat indicator list
   - SIEM block-list for correlation

4. **Machine Key Rotation** — The SharePoint farm's `machineKey` values (`validationKey` and `decryptionKey`) were rotated immediately across all servers in the farm, as the original keys were confirmed compromised. This invalidates any forged `__VIEWSTATE` payloads the attacker may have generated.

5. **CVE-2025-53770 Patch Applied** — The relevant Microsoft security update for CVE-2025-53770 was applied to SharePoint01 and all other SharePoint servers in the environment to close the exploitation vector.

6. **Retrospective Hunt** — SIEM, EDR, and IIS logs were queried for any prior exploitation attempts against `ToolPane.aspx` or other SharePoint endpoints across the environment. The hunt was extended to look for any other servers that may have been compromised through the same vector.

7. **Service Account Credential Reset** — All service accounts associated with the SharePoint farm (application pool accounts, farm account, search service account) were reset, as these credentials may have been accessible to the attacker post-exploitation.

---

## 3. Artifacts / IOCs

### Network Indicators

| Indicator | Type | Description |
|---|---|---|
| *(External attacker IP)* | IPv4 | Source IP of the exploitation request (redacted for public repo) |
| `172.16.20.17` | IPv4 | Compromised SharePoint server (SharePoint01) |
| `/_layouts/15/ToolPane.aspx` | URL Path | Exploitation endpoint targeted by CVE-2025-53770 |

### File Indicators

| Indicator | Type | Description |
|---|---|---|
| `02b4571470d83163d103112f07f1c434` | MD5 Hash | Compiled `payload.exe` — confirmed malicious on VirusTotal |
| `payload.exe` | Filename | Custom .NET payload compiled on-target via `csc.exe` |

*Note: SHA-1 and SHA-256 hashes are available in the internal case system and are omitted from this public report.*

### Host-Based Indicators

| Indicator | Type | Description |
|---|---|---|
| `csc.exe` spawned by `w3wp.exe` | Process | C# compiler invoked by the SharePoint worker process (anomalous) |
| Base64-encoded PowerShell from `w3wp.exe` | Process | PowerShell decoding and execution from the IIS worker process |
| Machine key extraction from `web.config` | File Access | Unauthorized read of SharePoint `web.config` cryptographic keys |
| `payload.exe` in `%TEMP%` or `%APPDATA%` | File | Compiled payload written to disk on SharePoint01 |

### MITRE ATT&CK Mapping

| Tactic | Technique | ID | Description |
|---|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 | Exploitation of CVE-2025-53770 in SharePoint `ToolPane.aspx` |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Base64-encoded PowerShell for machine key extraction |
| Defense Evasion | Trusted Developer Utilities Proxy Execution | T1127.001 | `csc.exe` used to compile malicious payload on-target |
| Credential Access | Credential Dumping | T1003 | Extraction of SharePoint machine key from `web.config` |
| Persistence | Server Software Component | T1505 | Potential web shell or persistent backdoor on SharePoint |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 | C2 communication from compiled payload |

### Confidence Assessment

- **Exploitation Confidence:** **High** — HTTP POST to `ToolPane.aspx` from an external IP, followed by anomalous PowerShell and `csc.exe` execution from the SharePoint worker process.
- **Payload Maliciousness:** **High** — MD5 `02b4571470d83163d103112f07f1c434` confirmed malicious on VirusTotal with multi-engine detection.
- **Source IP Reputation:** **High** — Flagged by multiple threat intelligence sources as a known malicious host.
- **Machine Key Compromise:** **High** — PowerShell execution pattern is consistent with known SharePoint machine key extraction techniques.

---

## 4. Detection Engineering

### Sigma Rule: SharePoint CVE-2025-53770 ToolPane.aspx Exploitation

The following Sigma rule detects HTTP POST requests to `ToolPane.aspx` from external or non-whitelisted source IPs — the primary exploitation vector for CVE-2025-53770.

```yaml
title: SharePoint CVE-2025-53770 ToolPane.aspx Exploitation Attempt
id: d4e5f6a7-b8c9-0123-defa-2345678901bc
status: production
description: >
  Detects HTTP POST requests to SharePoint's ToolPane.aspx from external or
  non-whitelisted source IPs, indicative of CVE-2025-53770 exploitation attempts.
  This vulnerability allows unauthenticated remote code execution via a crafted
  deserialization payload sent to the ToolPane endpoint.
author: Umar Ahmed
date: 2026-05-23
references:
  - https://attack.mitre.org/techniques/T1190/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770
logsource:
  category: webserver
detection:
  selection_toolpane:
    cs-method: POST
    cs-uri-stem|contains: '/_layouts/15/ToolPane.aspx'
  selection_external:
    src_ip|cidr:
      - '!10.0.0.0/8'
      - '!172.16.0.0/12'
      - '!192.168.0.0/16'
  condition: selection_toolpane and selection_external
falsepositives:
  - Legitimate administrative access to ToolPane.aspx from non-standard IPs (e.g., VPN)
  - Automated SharePoint management tools or scripts
level: critical
tags:
  - attack.initial_access
  - attack.t1190
```

**Tuning notes:**
- Adjust the `src_ip` allow-list to match the organization's internal IP ranges and known administrative jump hosts.
- In production, consider adding a `User-Agent` filter to exclude known SharePoint health monitoring or patch management tools.
- Can be extended to include `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` and other ToolPane variants.

---

### Sigma Rule: Suspicious csc.exe Compilation on SharePoint Server

The following Sigma rule detects `csc.exe` (C# Compiler) being spawned by `w3wp.exe` (IIS worker process) — a strong indicator of on-target payload compilation following web application exploitation.

```yaml
title: Suspicious csc.exe Compilation via IIS Worker Process
id: e5f6a7b8-c9d0-1234-efab-3456789012cd
status: production
description: >
  Detects the C# compiler (csc.exe) being spawned by the IIS worker process
  (w3wp.exe), which is highly anomalous and indicative of an attacker compiling
  a custom payload on-target after exploiting a web application. This is a
  Living Off The Land technique commonly observed in SharePoint exploitation
  chains.
author: Umar Ahmed
date: 2026-05-23
references:
  - https://attack.mitre.org/techniques/T1127/001/
  - https://lolbas-project.github.io/lolbas/Binaries/Csc/
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\w3wp.exe'
  selection_child:
    Image|endswith: '\csc.exe'
  condition: selection_parent and selection_child
falsepositives:
  - Extremely rare in legitimate environments; no known legitimate use of csc.exe spawned by w3wp.exe
level: critical
tags:
  - attack.defense_evasion
  - attack.t1127.001
  - attack.execution
```

**Tuning notes:**
- This rule is expected to have near-zero false positives in production environments.
- Consider adding `CommandLine` filters to also catch `csc.exe` invocations with `/out:` or `/target:exe` flags for higher fidelity.
- Can be generalized to detect other LOLBin compilers (e.g., `vbc.exe`, `jsc.exe`) spawned by web server processes.

---

### Splunk Query: IIS Log Hunt — ToolPane.aspx Exploitation

The following Splunk SPL queries hunt across IIS logs for evidence of CVE-2025-53770 exploitation and related post-exploitation activity on SharePoint servers.

#### Query 1: ToolPane.aspx POST Request Hunt

```spl
index=iis OR index=webserver
cs_method="POST" AND cs_uri_stem="*ToolPane.aspx*"
| eval is_external=if(cidrmatch("10.0.0.0/8", c_ip) OR cidrmatch("172.16.0.0/12", c_ip) OR cidrmatch("192.168.0.0/16", c_ip), "internal", "external")
| where is_external="external"
| eval bytes_in_kb=round(sc_bytes/1024, 1)
| eval bytes_out_kb=round(cs_bytes/1024, 1)
| stats count as request_count
        values(c_ip) as source_ips
        values(cs_user_agent) as user_agents
        values(cs_referer) as referers
        values(cs_uri_query) as uri_queries
        earliest(_time) as first_seen
        latest(_time) as last_seen
        sum(sc_bytes) as total_bytes_in
        sum(cs_bytes) as total_bytes_out
      by s_computername, cs_uri_stem, is_external
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| eval total_bytes_in_kb=round(total_bytes_in/1024, 1)
| eval total_bytes_out_kb=round(total_bytes_out/1024, 1)
| table s_computername, cs_uri_stem, is_external, source_ips, user_agents, referers, uri_queries, first_seen, last_seen, request_count, total_bytes_in_kb, total_bytes_out_kb
| sort - request_count
```

**Query breakdown:**
- Searches IIS logs for all POST requests to `ToolPane.aspx`.
- Classifies source IPs as internal or external using CIDR matching.
- Filters to show only external (non-RFC1918) source IPs.
- Aggregates by server and URI to identify the scope and frequency of exploitation attempts.
- Includes `User-Agent`, `Referer`, and query string values for payload analysis.

#### Query 2: Post-Exploitation — PowerShell and csc.exe from w3wp.exe

```spl
index=edr OR index=endpoint OR index=sysmon
(EventCode=1 OR EventCode=4688)
| where (ParentImage="*w3wp.exe" AND (Image="*powershell.exe" OR Image="*csc.exe" OR Image="*cmd.exe"))
| eval technique=case(
    match(Image, "(?i)powershell"), "PowerShell_from_IIS",
    match(Image, "(?i)csc\\.exe"), "CSC_Compilation_from_IIS",
    match(Image, "(?i)cmd\\.exe"), "CMD_from_IIS",
    true(), "Other"
  )
| eval decoded_cmd=if(match(Image, "(?i)powershell") AND match(CommandLine, "(?i)-e[n]{0,2}coded"), "Base64_Encoded_Command", "Plain_Command")
| table _time, Computer, ParentImage, Image, CommandLine, technique, decoded_cmd, User
| sort _time
```

**Query breakdown:**
- Searches process creation events (Sysmon Event ID 1 or Security Event ID 4688) for `powershell.exe`, `csc.exe`, or `cmd.exe` spawned by `w3wp.exe`.
- Classifies the technique and flags base64-encoded PowerShell commands.
- Sorted chronologically to build a post-exploitation activity timeline.

#### Query 3: Retrospective Hunt — Known Malicious IP and Payload Hash

```spl
index=edr OR index=endpoint OR index=iis OR index=network
| where (src_ip="<EXTERNAL_ATTACKER_IP>" OR dest_ip="<EXTERNAL_ATTACKER_IP>" OR file_hash="02b4571470d83163d103112f07f1c434" OR file_name="payload.exe")
| eval ioc_match=case(
    match(src_ip, "<EXTERNAL_ATTACKER_IP>"), "Malicious_Source_IP",
    match(dest_ip, "<EXTERNAL_ATTACKER_IP>"), "Malicious_Dest_IP",
    match(file_hash, "02b4571470d83163d103112f07f1c434"), "Known_Payload_Hash",
    match(file_name, "payload\\.exe"), "Known_Payload_Filename",
    true(), "Other"
  )
| table _time, index, Computer, src_ip, dest_ip, file_name, file_hash, process_name, CommandLine, ioc_match
| sort _time
```

**Query breakdown:**
- Hunts across all available data sources for any activity involving the known malicious IP or payload hash `02b4571470d83163d103112f07f1c434`.
- Useful for identifying additional compromised hosts or prior exploitation attempts that may have been missed.
- Replace `<EXTERNAL_ATTACKER_IP>` with the actual attacker IP from the case.

**Recommended scheduled searches:**
- Query 1: Run every 15 minutes with a 1-hour lookback. Alert on any external POST to `ToolPane.aspx`.
- Query 2: Run every 15 minutes with a 1-hour lookback. Alert on any match (near-zero false positive rate).
- Query 3: Run every 6 hours with a 7-day lookback. Alert on any match.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| T+0:00 | External attacker sends HTTP POST to `ToolPane.aspx` on SharePoint01 (`172.16.20.17`) |
| T+0:01 | Deserialization payload executed — RCE achieved via CVE-2025-53770 |
| T+0:02 | Base64-encoded PowerShell executed from `w3wp.exe` to extract machine key |
| T+0:05 | Machine key (`validationKey` / `decryptionKey`) extracted from `web.config` |
| T+0:07 | `csc.exe` spawned by `w3wp.exe` — attacker compiles `payload.exe` on-target |
| T+0:10 | `payload.exe` executed on SharePoint01 |
| T+0:15 | SIEM alert fires — anomalous activity on SharePoint01 |
| T+0:20 | SOC analyst begins triage |
| T+0:35 | VirusTotal lookup confirms source IP and payload MD5 `02b4571470d83163d103112f07f1c434` as malicious |
| T+0:45 | Verdict confirmed as **True Positive** |
| T+0:50 | SharePoint01 isolated via EDR |
| T+0:55 | Incident escalated to Tier 2 for deep forensics |
| T+1:00 | External attacker IP added to firewall deny-list and IIS IP restrictions |
| T+1:10 | Machine key rotated across SharePoint farm |
| T+1:15 | CVE-2025-53770 security patch applied to all SharePoint servers |
| T+1:30 | Service account credentials reset |
| T+2:00 | Retrospective hunt initiated across all endpoints and servers |
| T+4:00 | Forensic disk image and memory dump captured for Tier 2 analysis |

---

## Lessons Learned & Recommendations

1. **Patch management urgency:** CVE-2025-53770 is a critical, actively-exploited vulnerability. Ensure SharePoint servers are patched immediately upon release of security updates. Implement an emergency patching SLA of 24-48 hours for critical CVEs affecting internet-facing systems.

2. **Machine key protection:** The SharePoint machine key is a high-value target. Implement additional controls to restrict access to `web.config` and monitor for unauthorized reads. Consider using ASP.NET IIS Registration Tool (`aspnet_regiis`) to encrypt the `machineKey` section.

3. **LOLBin monitoring on servers:** The use of `csc.exe` to compile malware on-target is a known LOLBin technique. Implement application whitelisting or Windows Defender Application Control (WDAC) on critical servers to prevent unauthorized compiler execution.

4. **IIS worker process monitoring:** `w3wp.exe` should not spawn `powershell.exe`, `csc.exe`, or `cmd.exe` under any normal circumstance. Deploy the Sigma rule from Section 4 in production and tune for the environment. This detection has near-zero false positive rates.

5. **Network segmentation:** SharePoint servers should be in a segmented network zone with strict inbound access controls. External access to `/_layouts/` paths should be restricted to authenticated users only, with additional WAF rules to filter anomalous POST requests.

6. **Threat intelligence integration:** The attacker IP and payload hash should be ingested into the organization's TIP and correlated against historical logs to identify any prior exploitation attempts or related activity.

---

*Case status: True Positive — Active RCE confirmed on SharePoint01. Host isolated. Escalated to Tier 2 for deep forensics. Remediation in progress.*
*Last updated: 2026-05-23 by Umar Ahmed*
