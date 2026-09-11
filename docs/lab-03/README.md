# Lab 03 — Scheduled Task Persistence: Benign vs Suspicious Execution

## Executive Summary

This lab demonstrates how legitimate Windows Scheduled Tasks can be used for both normal automation and suspicious persistence.

Using a Windows 11 virtual machine with CrowdStrike Falcon, I compared a benign scheduled task that launched Notepad with a more suspicious scheduled task configured to run PowerShell at logon with hidden execution and unusual command-line arguments.

Falcon recorded the scheduled-task registration, process ancestry, and PowerShell execution as endpoint telemetry. No detection was generated because the simulated activity remained harmless, but the telemetry showed how analysts can identify persistence-related behavior through trigger context, process ancestry, and command-line details.

## Objective

The objective of this lab is to understand how Windows Scheduled Tasks can be used as a persistence mechanism and how endpoint telemetry can help distinguish legitimate automation from suspicious execution.

The lab focuses on:

- creating a benign scheduled task baseline;
- observing Task Scheduler-related process ancestry;
- creating a suspicious-looking logon-triggered task;
- reviewing PowerShell command-line context;
- comparing benign and suspicious execution;
- understanding the difference between telemetry and detection.

## Environment

- Windows 11 victim VM
- Kali Linux attacker/test VM
- VMware Workstation
- CrowdStrike Falcon sensor installed and communicating
- Falcon prevention policy configured for controlled detect-only lab observation
- Sysmon available for supplemental validation
