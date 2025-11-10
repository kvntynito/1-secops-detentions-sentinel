# Rule Name
Detection: Suspicious PowerShell EncodedCommand Usage

# Description
This detection flags PowerShell process executions where the command line contains the "-EncodedCommand" or suspiciously long Base64 strings. Attackers commonly use encoded commands to obfuscate malicious scripts and bypass simple signature-based detections.

# MITRE ATT&CK Mapping
- Technique: Command and Scripting Interpreter: PowerShell
- MITRE ID: T1059.001

# Severity
High (if combined with unusual parent process, network connections, or on sensitive hosts)

# Data Sources
- Windows Sysmon (Process Create events)
- Windows Security/Event Logs (Process creation / 4688 if available with command line)
- PowerShell operational logs (Microsoft-Windows-PowerShell/Operational)
- EDR / Endpoint agent command-line telemetry

# Detection Logic (plain language)
Trigger when Process Name is powershell.exe, pwsh.exe (PowerShell Core), or wmiprvse/regsvr32 launching PowerShell with:
- a literal `-EncodedCommand` arg OR
- a command line arg containing long Base64-like string (many contiguous Base64 chars and padding `=`)

Filter out obvious benign admin automation by whitelisting approved management hosts or signed scripts where possible.

# False Positives
- Legitimate administrative automation that intentionally uses encoded commands.
- Some deployment tools and management scripts use encoded commands during patching/rollouts.

# Response Playbook
1. Enrich alert with parent process, user, host, and first seen time.
2. If host is in production/critical group, isolate network (or at least monitor closely).
3. Pull process tree and command-line. Save process memory/dump if EDR available.
4. Search for subsequent suspicious activity: new user creation, persistence mechanisms, outbound connections.
5. If confirmed malicious — follow incident response plan (contain, eradicate, recover, notify stakeholders).

# Example Detection Queries

## Sigma-style pseudo-rule (conceptual)
title: Suspicious PowerShell EncodedCommand Usage
id: d1a2b3c4-0000-4000-8000-000000000001
status: experimental
description: Detects invocation of PowerShell with -EncodedCommand or long Base64 command lines
detection:
  selection:
    CommandLine|contains:
      - "-EncodedCommand"
  condition: selection

## Splunk SPL (example)
index=winevent OR index=sysmon sourcetype=WinEventLog:Security OR sourcetype=XmlWinEventLog
("powershell.exe" OR "pwsh.exe") AND (CommandLine="*-EncodedCommand*" OR CommandLine="* -e *" OR CommandLine="* -enc *")
| stats count by host, user, CommandLine, ParentImage, _time

## Elastic/KQL-ish (example)
process.name: ("powershell.exe" or "pwsh.exe") and (process.command_line: "*-EncodedCommand*" or process.command_line:/[A-Za-z0-9+/]{80,}=?/)

# Test / Validation Plan (lightweight)
- Create a Windows test VM.
- Run: `powershell.exe -EncodedCommand <base64 of "Write-Output 'test'">`
- Observe logs in Sysmon / PowerShell Operational / SIEM.
- Tune query to reduce noise (whitelist management hosts or known automation).

# Author / Date
Author: <your-name>  
Date: 2025-11-10
