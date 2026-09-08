# Lab 02 — PowerShell Network Activity and Command-and-Control Behavior

## Executive Summary

This lab demonstrates how endpoint telemetry can be used to investigate suspicious PowerShell activity that results in outbound network communication.

Using a Windows 11 virtual machine with CrowdStrike Falcon and Sysmon, I captured PowerShell process creation and network activity associated with communication to a Kali Linux system.

Sysmon Event ID 1 recorded the PowerShell process and command line, while Sysmon Event ID 3 recorded the outbound connection. The matching `ProcessGuid` values allowed the two events to be correlated to the same PowerShell process.

The lab also progressed into a reverse-shell simulation that CrowdStrike Falcon blocked, demonstrating the difference between telemetry used for investigation and prevention triggered by more suspicious behavior.

## Objective

The objective of this lab is to understand how endpoint process and network telemetry can be correlated when investigating suspicious PowerShell activity.

The lab focuses on:

- identifying PowerShell process execution;
- reviewing command-line context;
- identifying outbound network activity;
- correlating process and network events;
- understanding how Falcon can provide both investigation visibility and prevention.

The activity was performed in an isolated lab environment and was designed for safe security testing.

## Environment

- Windows 11 victim VM
- Kali Linux attacker VM
- VMware Workstation
- Host-only isolated network
- Windows victim IP: `192.168.36.129`
- Kali attacker IP: `192.168.36.128`
- Microsoft Defender enabled
- Sysmon
- CrowdStrike Falcon sensor installed and communicating
- Falcon prevention policy configured for controlled detect-only lab observation

## Benign Baseline

Before introducing reverse-shell behavior, I generated a harmless outbound HTTP request from PowerShell to the Kali Linux VM.

The PowerShell command was:

```powershell
Invoke-WebRequest http://192.168.36.128:8081 | Out-Null
```

### Falcon Command History

Falcon recorded the PowerShell command, including the destination IP address and port used during the test.

![Benign PowerShell HTTP command shown in Falcon telemetry](../../screenshots/lab-02/lab-02-04-benign-http-falcon-command-history.png)

*Falcon command-history telemetry showing a harmless PowerShell `Invoke-WebRequest` to the Kali Linux VM at `192.168.36.128:8081`.*

### Falcon Network Telemetry

Falcon also recorded the corresponding outbound network connection from the Windows endpoint at `192.168.36.129` to the Kali system at `192.168.36.128:8081`.

![Benign PowerShell HTTP network connection shown in Falcon telemetry](../../screenshots/lab-02/lab-02-03-benign-http-falcon-network-connection.png)

*Falcon network telemetry showing the PowerShell process communicating with `192.168.36.128` over TCP port `8081`.*


## Suspicious Reverse-Shell Activity

After establishing the benign PowerShell network baseline, I progressed the lab into a reverse-shell simulation.

The goal was to create behavior that more closely resembled command-and-control activity and compare the resulting telemetry with the benign HTTP request.

Unlike the baseline activity, the reverse-shell simulation produced behavior that Falcon identified as suspicious and generated a high-severity detection.

### Falcon High-Severity Detection

Falcon generated a high-severity detection associated with the executable used during the reverse-shell simulation.

The process tree showed the execution path leading to the detected process and provided additional execution details, including the user context, command line, file path, and executable hash.

![Falcon high-severity detection for reverse-shell simulation](../../screenshots/lab-02/lab-02-05-reverse-shell-falcon-high-detection-process-tree.png)

*Falcon process tree and execution details showing a high-severity detection associated with the reverse-shell simulation. Prevention was disabled during the lab, so the activity was available for investigation rather than being blocked.*

### Falcon Process Event

Falcon recorded the suspicious executable as a process event and preserved important execution context, including the command line, file path, parent process, and process identifiers.

![Falcon process event for reverse-shell simulation](../../screenshots/lab-02/lab-02-06-reverse-shell-falcon-process-event.png)

*Falcon process telemetry showing `Chrome.exe` executing from the user's Downloads directory with `explorer.exe` as the parent process.*

### Falcon Machine-Learning Detection Details

Falcon classified the executable as a high-severity detection using its sensor-based machine-learning detection logic.

The detection details showed:

- Severity: `High`
- Technique: `Sensor-based ML`
- Technique ID: `CST0007`
- IOA name: `MLSensor-High`
- Actions taken: `None`

Because prevention was disabled during the lab, Falcon generated the detection without taking a blocking action.

![Falcon machine-learning detection details](../../screenshots/lab-02/lab-02-07-reverse-shell-falcon-ml-detection-details.png)

*Falcon detection details showing a high-confidence sensor-based machine-learning detection for the executable used during the reverse-shell simulation.*

### Falcon Network Connection

Falcon also recorded the detected process establishing an outbound TCP connection to the Kali Linux VM.

The network telemetry showed:

```text
Windows endpoint: 192.168.36.129
Remote system:    192.168.36.128
Remote port:      8080
Protocol:         TCP

### Sysmon Event Correlation

Sysmon provided supplemental Windows telemetry for the suspicious PowerShell activity.

Event ID 1 recorded the PowerShell process creation and command line, while Event ID 3 recorded the outbound network connection to the Kali Linux system at `192.168.36.128:8081`.

The two events shared the same `ProcessGuid`, allowing them to be correlated to the same PowerShell process.

### Sysmon Event ID 1 — PowerShell Process Creation

![Sysmon Event ID 1 showing suspicious PowerShell process creation](../../screenshots/lab-02/02-powershell-process-creation-sysmon-event1.png)

*Sysmon Event ID 1 showing `powershell.exe` launched with the command used during the lab simulation.*

### Sysmon Event ID 3 — PowerShell Network Connection

![Sysmon Event ID 3 showing PowerShell network connection](../../screenshots/lab-02/01-powershell-network-connection-sysmon-event3.png)

*Sysmon Event ID 3 showing `powershell.exe` initiating a TCP connection to the Kali Linux VM at `192.168.36.128:8081`.*

### Process Correlation

Both Sysmon events contained the same process identifier:

text
ProcessGuid: {6db4a906-c9be-6a97-9601-000000000f00}

## Benign vs Suspicious Comparison

| Benign Baseline | Suspicious Reverse-Shell Activity |
|---|---|
| PowerShell made a controlled HTTP request to `192.168.36.128:8081` | Reverse-shell behavior created more suspicious execution context |
| Falcon recorded command-history telemetry | Falcon generated a high-severity detection |
| Falcon recorded the outbound network connection | Falcon provided process-tree and execution details for investigation |
| Activity was intentionally harmless | Activity was designed to emulate command-and-control behavior |
| No malicious payload was used | Reverse-shell behavior was intentionally simulated in the isolated lab |
| Prevention was not triggered | Prevention was disabled, so the activity remained available for investigation |

The key difference was not simply that PowerShell communicated over the network. Both the benign and suspicious activities involved outbound communication.

The more useful distinction came from the surrounding execution context, related process activity, and Falcon's detection logic. This demonstrated why analysts need to evaluate the full behavior rather than treating a single process name or network connection as proof of malicious activity.


## Investigation Findings

The lab showed how process and network telemetry can be correlated to reconstruct suspicious endpoint activity.

Sysmon Event ID 1 recorded the PowerShell process creation, while Event ID 3 recorded the outbound TCP connection to `192.168.36.128:8081`.

Both events shared the same `ProcessGuid`:

text
{6db4a906-c9be-6a97-9601-000000000f00}


## MITRE ATT&CK Mapping

| Observed Behavior | Technique | ID | Evidence | Why It Fits |
|---|---|---|---|---|
| PowerShell executed commands during the simulation | Command and Scripting Interpreter: PowerShell | T1059.001 | Sysmon Event ID 1 and Falcon command-history telemetry | PowerShell was used as the command interpreter during the simulated activity |
| PowerShell established outbound communication with the Kali Linux VM | Non-Standard Port | T1571 | Sysmon Event ID 3 and Falcon network telemetry showing communication with `192.168.36.128:8081` | The lab used TCP port `8081` for controlled communication between the Windows and Kali systems |

### Mapping Notes

The ATT&CK mappings are based only on behavior observed during the lab.

PowerShell and outbound network communication are not automatically malicious. The surrounding process context, command line, network destination, related events, and Falcon detection provided the additional information needed to determine whether the activity deserved investigation.

The reverse-shell simulation was performed in an isolated lab environment and was intended to reproduce behavior associated with command-and-control activity without representing a real-world compromise.

## How CrowdStrike Falcon Maps to This Scenario

CrowdStrike Falcon provided the primary endpoint visibility used to investigate the activity in this lab.

During the benign baseline, Falcon recorded both the PowerShell command and the associated outbound network connection to the Kali Linux VM.

During the reverse-shell simulation, Falcon generated a high-severity detection and provided additional context through the process tree and execution details.

This demonstrated how Falcon can help an analyst move from simply observing a network connection to understanding:

- which process initiated the activity;
- what command was executed;
- where the connection was directed;
- how the process was launched;
- whether related behavior triggered a detection.

### Detection Opportunity

The lab demonstrated that a single PowerShell process or outbound connection is not enough to determine whether activity is malicious.

More useful detection context came from combining:

- process ancestry;
- command-line activity;
- network destination and port;
- related process behavior;
- Falcon detection context.

The benign HTTP request produced telemetry without representing malicious activity, while the reverse-shell simulation generated a high-severity Falcon detection.

This comparison demonstrated why behavior and execution context are more useful than relying on a process name or network connection by itself.

### Falcon Insight XDR

Falcon Insight XDR provides endpoint detection and response capabilities that help analysts investigate suspicious activity across process, command-line, and network telemetry.

In this lab, Falcon provided visibility into both the benign and suspicious activity and allowed the execution context to be reviewed through related endpoint events and process relationships.

The value was not simply knowing that PowerShell or another process executed. The value came from being able to understand how the activity occurred and determine whether it required further investigation.

### Response and Remediation

If investigation confirmed that the endpoint was compromised, CrowdStrike response capabilities such as Real Time Response could be used to assist with remediation.

This creates a simple security workflow:

**Prevent → Detect and Investigate → Respond**


## Business Value

Suspicious PowerShell activity can be difficult to evaluate because PowerShell is also widely used for legitimate administration.

The value of endpoint detection and response is the ability to provide context around that activity.

In this lab, process and network telemetry showed:

- How PowerShell was launched
- The full command line that was executed
- The destination IP address and port
- The relationship between the process creation and resulting network connection

This type of visibility can help a security team investigate suspicious behavior faster and make better decisions about whether activity is legitimate or malicious.

Instead of investigating isolated events, an analyst can reconstruct the sequence of activity and understand what occurred on the endpoint.

## SE Talk Track

In this lab, I simulated suspicious PowerShell activity on a Windows endpoint and used Sysmon to investigate what happened.

The process creation telemetry showed PowerShell launching with unusual command-line options and using `Invoke-WebRequest` to connect to another system. I then correlated that process with the outbound network connection using the matching Sysmon `ProcessGuid`.

The key takeaway is that endpoint telemetry provides more than a simple alert. It gives analysts the context needed to understand how a process started, what it executed, and what activity followed.

In a CrowdStrike environment, Falcon Insight XDR would be relevant to this type of investigation because it is designed to provide endpoint visibility and correlate related activity for analysts.
