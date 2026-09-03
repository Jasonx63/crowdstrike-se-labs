## Investigation Findings

The Windows endpoint executed a PowerShell command using the `-NoProfile` and `-WindowStyle Hidden` options. The command used `Invoke-WebRequest` to connect to the Kali Linux system at `192.168.36.128` over TCP port `8081`.

Sysmon Event ID 1 captured the creation of the PowerShell process, including the full command line and parent process information.

![PowerShell Process Creation](../../screenshots/lab-02/02-powershell-process-creation-sysmon-event1.png)

Sysmon Event ID 3 captured the outbound network connection initiated by the same PowerShell process.

![PowerShell Network Connection](../../screenshots/lab-02/01-powershell-network-connection-sysmon-event3.png)

The `ProcessGuid` value matched between both events:

`{6db4a906-c9be-6a97-9601-000000000f00}`

This confirmed that the PowerShell process captured in Event ID 1 was the same process responsible for the outbound connection captured in Event ID 3.

## Why This Matters

PowerShell is a legitimate Windows administration tool, but it can also be abused by attackers.

Looking only at the existence of `powershell.exe` provides limited context. Endpoint telemetry makes it possible to investigate how PowerShell was launched, what command it executed, and what network activity resulted from that execution.

In this lab, process creation and network telemetry were correlated to reconstruct the sequence of events rather than viewing each event in isolation.

## MITRE ATT&CK Mapping

### T1059.001 — PowerShell

This scenario maps to MITRE ATT&CK technique **T1059.001 — PowerShell**.

The Windows endpoint executed PowerShell with command-line options including `-NoProfile` and `-WindowStyle Hidden`, then used `Invoke-WebRequest` to initiate an outbound network connection.

PowerShell is a legitimate administrative tool, but attackers can abuse it for execution, scripting, reconnaissance, payload delivery, and other post-compromise activity.

In this lab, Sysmon telemetry was used to capture the PowerShell process creation and correlate it with the resulting network connection.

## How CrowdStrike Falcon Maps to This Scenario

This lab uses Sysmon to demonstrate endpoint telemetry concepts that an EDR platform such as CrowdStrike Falcon is designed to surface and correlate.

### Falcon Insight XDR

Falcon Insight XDR is the primary CrowdStrike capability that maps to this scenario.

The lab demonstrated:

- PowerShell process execution
- Parent-child process relationships
- Full command-line visibility
- Outbound network activity
- Correlation of process and network telemetry

In a Falcon investigation, this type of context helps analysts understand not only that suspicious activity occurred, but also how the process started, what command it executed, and what activity followed.

### Falcon Prevent

Falcon Prevent adds prevention capabilities designed to identify and stop malicious or suspicious behavior.

This lab did not use a CrowdStrike sensor and did not test whether Falcon Prevent would block the command. The PowerShell activity was intentionally benign and was used only to generate telemetry for investigation.

The purpose of this lab is to demonstrate the type of behavioral context an analyst would use when investigating potentially suspicious PowerShell activity.

### Response and Remediation

If investigation confirmed that the endpoint was compromised, CrowdStrike response capabilities such as Real Time Response could be used to assist with remediation.

This creates a simple security workflow:

**Prevent → Detect and Investigate → Respond**
