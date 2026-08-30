# Lab 01 — Suspicious PowerShell and Endpoint Execution

## Objective

The purpose of this lab is to learn how Windows process activity can be investigated using endpoint telemetry.

The lab begins with a **benign baseline** using PowerShell and Notepad. PowerShell is used to create a harmless text file and launch `notepad.exe`. This activity is expected and non-malicious.

The goal is to examine the resulting process relationship and understand why process ancestry, command-line information, user context, and follow-on behavior are more useful than looking at a process name by itself.

## Environment

- Windows 11 victim VM
- Kali Linux attacker VM
- VMware Workstation
- Host-only isolated network
- Microsoft Defender enabled
- Sysmon
- System Informer

> CrowdStrike Falcon is not installed in this home lab. Any CrowdStrike mappings in this project are based on documented Falcon capabilities and are kept separate from the telemetry observed in the Windows lab.

## Benign Baseline Activity

Before introducing suspicious PowerShell behavior, I created a normal and predictable process chain to establish a baseline.

PowerShell was used to:

1. Create a harmless text file in the Windows temporary directory.
2. Launch `notepad.exe`.
3. Open the text file in Notepad.

The resulting process relationship was:

```text
powershell.exe
      ↓
notepad.exe
