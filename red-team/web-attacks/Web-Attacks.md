## 🔴 SOC342: CVE‑2025‑53770 SharePoint RCE
**Verdict:** True Positive

### 1. Triage & Analysis
* **Alert:** Critical alert for `SharePoint01` (`172.16.20.17`) from an external Source IP.
* **Investigation:** Analyzed raw logs and found an HTTP POST request targeting `ToolPane.aspx`. Checked Endpoint Security terminal history and found a base64-encoded PowerShell script designed to extract the machine key configuration.
* **Enrichment:** Process tree analysis revealed the attacker compiled `payload.exe` via `csc.exe`. VirusTotal flagged the Source IP and the payload MD5 hash as highly malicious.

### 2. Containment & Remediation
* **Action:** Immediately isolated the `SharePoint01` endpoint to halt the Remote Code Execution (RCE).
* **Transparency/Client Update:** Documented the full execution chain in the ticket. Escalated to Tier 2 for deep forensics to preserve the triage SLA.

### 3. Artifacts (IOCs)
* **Source IP:** `107.191.58.76`
* **Target URL:** `/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx`
* **Payload Hash:** `02b4571470d83163d103112f07f1c434`

---

## 🔴 SOC287: CVE-2024-24919 Checkpoint Gateway LFI
**Verdict:** True Positive

### 1. Triage & Analysis
* **Alert:** Potential unauthenticated arbitrary file read vulnerability on a Checkpoint Gateway (`172.16.20.146`).
* **Investigation:** Searched the SIEM logs and identified a directory traversal payload (`../../etc/passwd`). The HTTP response code was "200", indicating the attacker successfully retrieved the sensitive file. 
* **Enrichment:** A subsequent attempt to access `/etc/shadow` was blocked (HTTP 403). VirusTotal confirmed the Source IP was an external threat located in China.

### 2. Containment & Remediation
* **Action:** Isolated the compromised Checkpoint Gateway using the Endpoint Security panel.
* **Transparency/Client Update:** Escalated the case to Tier 2 for forensic imaging. Updated the ticket recommending the client apply the latest gateway patch, reset system credentials, and hunt for internal lateral movement.

### 3. Artifacts (IOCs)
* **Source IP:** `203.160.68.12`
* **Target IP:** `172.16.20.146`
* **Payload:** `../../etc/passwd`
