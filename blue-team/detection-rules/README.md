# Detection Rules

Production-ready detection rules mapped to the SOC investigations in this repo. Each rule is linked to its corresponding case file.

## Sigma Rules

| Rule | MITRE ATT&CK | Linked Case |
|------|--------------|-------------|
| [sigma/internal-phishing-keywords.yml](sigma/sigma-internal-phishing-keywords.yml) | T1566.001 | SOC120 |
| [sigma/malicious-email-attachments.yml](sigma/sigma-malicious-email-attachments.yml) | T1566.001, T1204.002 | SOC140 |
| [sigma/malicious-url-access.yml](sigma/sigma-malicious-url-access.yml) | T1189, T1204.001 | SOC141 |
| [sigma/software-download-allowlist.yml](sigma/sigma-software-download-allowlist.yml) | T1189 | SOC104 |
| [sigma/macro-autoopen-powershell.yml](sigma/sigma-macro-autoopen-powershell.yml) | T1204.002, T1059.001 | SOC137 |
| [sigma/outbound-c2-beaconing.yml](sigma/sigma-outbound-c2-beaconing.yml) | T1071.001, T1573 | SOC138 |
| [sigma/sharepoint-toolpane-rce.yml](sigma/sigma-sharepoint-toolpane-rce.yml) | T1190, T1059.001 | SOC342 |
| [sigma/directory-traversal-gateway.yml](sigma/sigma-directory-traversal-gateway.yml) | T1190, T1083 | SOC287 |

## Splunk Queries

See [splunk/](splunk/) directory for corresponding SPL queries referenced in each case file.

## How to Use

1. Convert Sigma rules using [sigmac](https://github.com/SigmaHQ/sigma) or import directly into your SIEM
2. Tune the `filter_*` lists in each rule to match your environment
3. Adjust thresholds based on your baseline — start with higher values and tighten over time
