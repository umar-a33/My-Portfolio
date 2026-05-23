# Umar Ahmed — Cybersecurity Portfolio

**SOC Analyst · Cloud Pentester · Red Team Operator**

> *Evidence over conversation. Terminal output or it didn't happen.*

---

## 🔭 Overview

This repo is my working portfolio — real investigations, real terminal logs, real detection rules. I build in both directions: **red team** (offensive) and **blue team** (defensive). The best attackers understand defense, and the best defenders think like attackers.

**Currently:** Phase 2 — AWS Cloud Pentesting (IAM enumeration)

---

## 📁 Structure

```
/red-team/              ← Offensive operations
  web-attacks/          — OWASP Top 10, blind exploitation
  aws-pentesting/       — IAM escalation, Lambda, S3, IMDS
  active-directory/     — Kerberoasting, BloodHound, Impacket
  ai-llm-attacks/       — Prompt injection, RAG exploitation

/blue-team/             ← Defensive operations
  soc-investigations/   — Phishing, malware, incident response
    phishing/           — Email triage, URL analysis, containment
    malware/            — Static/dynamic analysis, IOC extraction
  detection-rules/      — Sigma rules, Splunk queries
    sigma/              — Production-ready Sigma detection rules
    splunk/             — SPL hunt queries

/labs/                  — Lab write-ups and infrastructure
  s3-enumeration/       — AWS Account ID via public S3
  infrastructure/       — Lab architecture manifest
```

## 🔴 SOC Investigations

| ID | Type | Verdict | CVE |
|----|------|---------|-----|
| [SOC120](blue-team/soc-investigations/phishing/SOC120-internal-phishing-false-positive.md) | Phishing (Internal) | 🟢 False Positive | — |
| [SOC140](blue-team/soc-investigations/phishing/SOC140-malicious-phishing-attachment.md) | Phishing (Attachment) | 🔴 True Positive | — |
| [SOC141](blue-team/soc-investigations/phishing/SOC141-phishing-url-compromised-endpoint.md) | Phishing (URL) | 🔴 True Positive | — |
| [SOC104](blue-team/soc-investigations/malware/SOC104-suspicious-winrar-false-positive.md) | Malware (Download) | 🟢 False Positive | — |
| [SOC137](blue-team/soc-investigations/malware/SOC137-malicious-docm-macro.md) | Malware (Macro) | 🔴 True Positive | — |
| [SOC138](blue-team/soc-investigations/malware/SOC138-suspicious-xls-c2-communication.md) | Malware (C2) | 🔴 True Positive | — |
| [SOC342](blue-team/soc-investigations/SOC342-sharepoint-rce.md) | Web Attack (RCE) | 🔴 True Positive | CVE-2025-53770 |
| [SOC287](blue-team/soc-investigations/SOC287-checkpoint-lfi.md) | Network (LFI) | 🔴 True Positive | CVE-2024-24919 |

## 🛡️ Detection Rules

| Rule | Technique | MITRE ATT&CK |
|------|-----------|--------------|
| [Internal Phishing](blue-team/detection-rules/sigma/sigma-internal-phishing-keywords.yml) | Email keyword + sender verification | T1566.001 |
| [Malicious Attachments](blue-team/detection-rules/sigma/sigma-malicious-email-attachments.yml) | Macro-enabled Office docs | T1566.001, T1204.002 |
| [Malicious URL Access](blue-team/detection-rules/sigma/sigma-malicious-url-access.yml) | Proxy/DNS detection | T1189, T1204.001 |
| [Suspicious Downloads](blue-team/detection-rules/sigma/sigma-software-download-allowlist.yml) | Allowlist-filtered download detection | T1189 |
| [Macro → PowerShell](blue-team/detection-rules/sigma/sigma-macro-autoopen-powershell.yml) | AutoOpen spawning PowerShell | T1204.002, T1059.001 |
| [C2 Beaconing](blue-team/detection-rules/sigma/sigma-outbound-c2-beaconing.yml) | Periodic outbound C2 traffic | T1071.001 |
| [SharePoint RCE](blue-team/detection-rules/sigma/sigma-sharepoint-toolpane-rce.yml) | ToolPane.aspx exploitation | T1190 |
| [csc.exe Compile](blue-team/detection-rules/sigma/sigma-sharepoint-csc-compile.yml) | w3wp.exe → csc.exe | T1059.001 |
| [Directory Traversal](blue-team/detection-rules/sigma/sigma-directory-traversal-gateway.yml) | ../ on network gateways | T1190, T1083 |

Each Sigma rule is production-ready and mapped to its corresponding SOC investigation.

---

## 🧠 Workflow

I run a dual-agent setup: **Hermes** (this VPS) for strategy and documentation, **Agent0** (local) for execution. Obsidian vault for knowledge management. GitHub for evidence storage and portfolio.

Every lab session produces terminal output, an Obsidian note, and an artifact in this repo.

---

## 📜 License

MIT — see [LICENSE](LICENSE)

---

*focused. minimal. execution-first.*
