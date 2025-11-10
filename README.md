# <Project Title>

This project showcases hands-on Security Operations (SecOps) skills using Microsoft Sentinel.
It includes detection rules, incident investigations, log samples, and automation scripts used to identify and respond to suspicious activity in a simulated enterprise environment.

## 🎯 Objectives
This project demonstrates real-world SecOps and SIEM capabilities, including:
- Writing custom detection rules
- Building Microsoft Sentinel KQL queries
- Performing incident investigations
- Ingesting and analyzing Windows, Linux, and Sysmon logs
- Designing SecOps architecture diagrams
- Using automation/scripts to enrich detections

## 📁 What’s Inside
- `docs/` – reports, playbooks, baselines, diagrams
- `scripts/` – Python/PowerShell/Bash utilities
- `lab/` – sample logs, datasets, IaC
- `.github/` – issue/PR templates

## 🧪 Lab Setup (Quick Start)
**Host Options**
- Proxmox
- VMware
- Hyper-V
- Docker

**Lab Machines**
- Windows Server 2019
- Ubuntu 22.04
- Kali Linux

**Network**
- pfSense
- Two VLANs:
  - Home
  - Lab

**Cloud (Azure)**
- Microsoft Sentinel
- Log Analytics Workspace
- Microsoft Defender for Cloud
- Azure AD / Entra ID

This entire environment can be recreated with minimal cost using an Azure free trial.
You can recreate this with minimal cost using an Azure trial subscription.

## ▶️ How to Run (Testing & Execution)
**1. Generate test events**
- nmap -A <target>
- Failed login attempts
- Suspicious PowerShell scripts
- Sysmon event generation

**2. Load logs into Sentinel**
- Upload Windows Event Logs
- Sysmon logs
- Linux auth logs
- Custom logs

**3. Run detection rules**
- Open Sentinel → Analytics
- Create custom detection
- Paste your KQL rule
- Set severity + tactics (MITRE ATT&CK)
- Save & run

**4. Trigger & investigate incidents**
- Confirm alerts fire
- Open the “Incidents” blade
- Document the investigation in docs/Incident_Report_TEMPLATE.md



## 📊 Deliverables
✅ Detection rules (KQL)

✅ Incident reports documenting triage & findings

✅ Log samples for reproducible testing

✅ Architecture flow diagram showing log ingestion paths

✅ Screenshots of alerts & incident timelines

## 🧠 What I Learned
- Bullet points of concepts/skills you gained - Write what you learned about KQL, log sources, detection logic.
- How SIEMs ingest & normalize logs
- How to identify suspicious patterns in Windows, Linux, and Sysmon logs
- Writing detection logic using KQL (Kusto Query Language)
- Connecting multiple log sources to Sentinel
- Building alerts that align with MITRE ATT&CK
- Investigating alerts & documenting root cause
- Using Azure’s cloud-native SecOps tools in a real environment

## ✅ Next Steps
- Add 10+ new detection rules (brute force, malware, lateral movement)
- Integrate a SOAR (Logic Apps) workflow for automated response
- Add enrichment scripts to correlate IPs with VirusTotal/AbuseIPDB
- Add more sample logs (Apache, Sysmon v13, Windows DNS logs)
- Build a small threat-hunting workbook with custom dashboards
## ⚖️ License
MIT – see `LICENSE`.
