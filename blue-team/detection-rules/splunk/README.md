# Splunk Queries

Hunt queries referenced by SOC investigations. Each file maps to one or more case files.

## Queries

| File | Purpose | Linked Case |
|------|---------|-------------|
| [internal-phishing-hunt.spl](internal-phishing-hunt.spl) | Hunt for internal phishing patterns | SOC120 |
| [malicious-attachment-hunt.spl](malicious-attachment-hunt.spl) | Hunt for macro-enabled attachments | SOC140, SOC137 |
| [malicious-url-hunt.spl](malicious-url-hunt.spl) | Hunt for malicious URL access | SOC141 |
| [c2-beaconing-hunt.spl](c2-beaconing-hunt.spl) | Hunt for C2 beaconing patterns | SOC138 |
| [sharepoint-rce-hunt.spl](sharepoint-rce-hunt.spl) | Hunt for SharePoint exploitation | SOC342 |
| [directory-traversal-hunt.spl](directory-traversal-hunt.spl) | Hunt for traversal attempts | SOC287 |

## Usage

1. Paste into Splunk Search & Reporting
2. Adjust time range and index names to match your environment
3. Tune thresholds based on your baseline
