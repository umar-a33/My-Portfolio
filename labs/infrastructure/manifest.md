# Offensive Security & AI Red Teaming Lab
## Engineering Manifest & Architecture Topology

**Date Established:** May 2026
**Primary Focus:** Cloud-Native Security, AI Red Teaming, and Automated OSINT Pipeline

---

## 1. Executive Summary
This document outlines the architecture, configuration, and security parameters of a custom dual-node AI automation lab. The environment is deliberately decoupled to distribute processing overhead, maintaining a persistent low-resource cloud gateway for knowledge ingestion while isolating heavy execution and visual browser automation to a sandboxed local desktop workstation.

---

## 2. Global Architecture Matrix

| Component | Cloud Node (VPS) | Local Node (Desktop) |
| :--- | :--- | :--- |
| **Hardware / Tier** | 4GB RAM Allocation (or 2GB + 2GB SSD Swap) | Local Desktop Hardware |
| **Primary AI Engine** | Hermes Agent (Nous Research) | AgentZero (Dockerized) |
| **Interface Layer** | Telegram Gateway (24/7) | Web UI (`localhost:50080`) + `a0` CLI |
| **Execution Focus** | Text parsing, OSINT routing, Context Memory | Multi-threaded scripting, network scanning |
| **Visual Automation** | Headless / Text-only | Browser Use Framework (`localhost:7788`) |
| **API Gateway** | OpenRouter | OpenRouter |

---

## 3. Node 1: The Cloud Command Center (VPS)

### **Core Objective**
To act as a 24/7, highly available gateway for natural language commands, background intelligence gathering, and continuous documentation logging without exposing local desktop hardware.

### **Configuration Details**
* **Operating System:** Ubuntu Linux (Headless)
* **Memory Management:** Configured with a 2GB SSD Swap file (`vm.swappiness=10`) to prevent Out-Of-Memory (OOM) kernel kills during heavy context flushing.
* **Agent Framework:** Hermes Agent running via internal daemon manager (`hermes gateway start`).
* **Memory Architecture:** Relies on structured Markdown parsing (`USER.md` and `MEMORY.md`) to maintain persistent operational context.
* **Data Synchronization:** `Syncthing` running as a background service, strictly mapping `/root/Documents/Obsidian-Vault/` to the localized network mesh.

---

## 4. Node 2: The Execution Sandbox (Desktop)

### **Core Objective**
To provide a secure, resource-dense environment for active offensive security tasks, raw code execution, and visual web application interactions.

### **Configuration Details**
* **Containerization:** AgentZero runs within an isolated Docker network (`sandbox_net`), dropping privileges to prevent host hardware compromise during exploit analysis.
* **Host Connector:** The `a0` CLI bridge maps the desktop terminal to the Docker container, allowing native shell execution.
* **Visual Web Automation:** The open-source `Browser Use` framework is deployed locally, utilizing Playwright and Chromium to visually navigate complex, dynamic web targets (React/Next.js) or bypass standard DOM protections.
* **Local Logging API:** Obsidian Local REST API plugin deployed to allow local tools to cleanly append vulnerability scans, network maps, and project evidence into the vault without raw file manipulation conflicts.
* **Version Control:** The localized `agent-zero-data` directory is tracked via Git.

---

## 5. Security & Operational Security (OpSec) Protocols

1. **API Key Isolation:** A strict `.gitignore` file (`.env`, `*config.json`, `*.key`, `secrets/`) is enforced on the local AgentZero repository to prevent credential leakage.
2. **Third-Party Exposure:** OpenClaw and external Model Context Protocol (MCP) servers are deliberately excluded from this architecture to minimize supply-chain attack surfaces and unvetted remote code execution vectors.
3. **Sandbox Enforcement:** All heavy exploit scripting is restricted to the AgentZero Docker container. The cloud VPS is restricted strictly to text processing and headless network sweeping.
4. **Data Sovereignty:** All core workflows and lab logs are maintained on single-tenant hardware and synchronized via private peer-to-peer mesh (Syncthing). No proprietary data is hosted on managed AI platforms like HermesOS or Browserbase.
