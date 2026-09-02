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
```
![Sysmon Event ID 1 showing PowerShell launching Notepad](../../screenshots/lab-01/lab-01-01-sysmon-powershell-notepad-process.png)


## Suspicious PowerShell Simulation

After establishing a benign PowerShell baseline, I performed a safe simulation designed to create more suspicious execution context without using malware or destructive behavior.

The command was launched from `cmd.exe`, which then started PowerShell with the following parameters:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- `-Command`

The PowerShell command created a harmless text file and opened it in Notepad.

The resulting process relationship was:

```text
cmd.exe
   ↓
powershell.exe
```

![Sysmon Event ID 1 showing PowerShell launching Notepad](../../screenshots/lab-01/lab-01-02-sysmon-suspicious-powershell-execution.png)

*Safe suspicious PowerShell simulation: Sysmon Event ID 1 records `powershell.exe` launched by `cmd.exe` with `-NoProfile` and `-ExecutionPolicy Bypass`. These parameters do not prove malicious activity, but the parent-child relationship and command-line context provide additional reasons for an analyst to investigate the execution.*

### Follow-On Process Activity

After the suspicious PowerShell process was created, Sysmon recorded the next process in the execution chain: `Notepad.exe`.

The event shows that `powershell.exe` was the parent process responsible for launching Notepad. The `ParentCommandLine` field also preserves the PowerShell command-line context from the previous event, including:

- `-NoProfile`
- `-ExecutionPolicy Bypass`
- the scripted command that created and opened the harmless test file

This allows the individual Sysmon events to be correlated into a larger process sequence rather than analyzed in isolation.

The resulting process chain was:

```text
cmd.exe
   ↓
powershell.exe
   ↓
Notepad.exe
```

#### Sysmon Event ID 1 — PowerShell Launching Notepad

![Sysmon Event ID 1 showing PowerShell launching Notepad](../../screenshots/lab-01/lab-01-03-sysmon-powershell-notepad-follow-on.png).

*Follow-on process activity: Sysmon Event ID 1 records `Notepad.exe` launched by `powershell.exe`. The parent command line preserves the earlier PowerShell execution context, allowing this event to be correlated with the previous `cmd.exe → powershell.exe` process-creation event.*


## MITRE ATT&CK Mapping

| Observed Behavior | Technique | ID | Evidence | Why It Fits |
|---|---|---|---|---|
| PowerShell executed scripted commands and launched a child process | Command and Scripting Interpreter: PowerShell | T1059.001 | Sysmon Event ID 1 showing `powershell.exe`, its command line, parent process, and follow-on `Notepad.exe` execution | PowerShell was used as the command and scripting interpreter to execute the simulated activity |


### Mapping Notes

This mapping is based on the behavior that was actually observed in the lab.

The presence of PowerShell alone does not indicate malicious activity. PowerShell is a legitimate Windows administrative tool. The ATT&CK mapping reflects that PowerShell was used for command execution during the simulation, while the surrounding process ancestry and command-line context provide the information needed for further investigation.


## How CrowdStrike Falcon Maps to This Scenario

> CrowdStrike Falcon was not installed in this home lab. The endpoint evidence shown above was collected using Windows telemetry and Sysmon. The Falcon mappings below are based on documented CrowdStrike capabilities and are not presented as lab-generated Falcon results.

### Detection Opportunity

The lab demonstrated that PowerShell itself is not automatically malicious.

The more useful security context came from:

- the parent process that launched PowerShell;
- the PowerShell command line;
- the arguments used during execution;
- the child process launched by PowerShell;
- the sequence of related process activity.

This type of context helps an analyst distinguish expected administrative activity from behavior that may require additional investigation.

### Falcon Insight XDR

CrowdStrike describes Falcon Insight XDR as providing endpoint detection and response with context-rich detections, investigation capabilities, MITRE ATT&CK mappings, and broader attack visibility.

For behavior like the PowerShell activity demonstrated in this lab, relevant investigation context could include related endpoint activity and the relationships between events that help an analyst understand how execution unfolded.

The value is not simply knowing that `powershell.exe` ran. The value comes from understanding the surrounding behavior and determining whether the activity represents legitimate administration or part of an attack.

### Falcon Prevent

Falcon Prevent is CrowdStrike's endpoint prevention capability.

In a real environment, prevention policies may be used to stop activity that is determined to be malicious or violates configured security controls.

This lab does not demonstrate Falcon prevention because Falcon was not installed, and the PowerShell simulation itself was intentionally harmless.

Therefore, this project does not claim that Falcon Prevent would block this exact command.

### Investigation

The investigation workflow demonstrated in this lab was:

```text
Process created
      ↓
Identify parent process
      ↓
Review command line
      ↓
Identify child process
      ↓
Correlate related activity
      ↓
Determine whether additional investigation is required


## Detection vs Prevention vs Investigation vs Response

### Detection

Detection is the process of identifying activity that may be suspicious or malicious.

In this lab, the PowerShell process itself was not automatically malicious. The more meaningful detection opportunity came from the surrounding context, including the parent process, command-line arguments, and follow-on process activity.

### Prevention

Prevention is the process of stopping malicious activity from successfully executing or causing its intended effect.

This lab did not demonstrate prevention because the PowerShell activity was intentionally harmless and CrowdStrike Falcon was not installed in the environment.

### Investigation

Investigation is the process of determining what happened after activity has been observed or detected.

In this lab, investigation included reviewing:

- the parent process;
- the PowerShell command line;
- the execution arguments;
- the child process;
- the sequence of related Sysmon events.

This context helped reconstruct the process chain:

```text
cmd.exe
   ↓
powershell.exe
   ↓
Notepad.exe
