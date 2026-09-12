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

## Benign Baseline

To establish a normal reference point, I created a scheduled task named `Lab03-Benign-Notepad` that launched `notepad.exe`.

The task was configured with a daily trigger and was executed manually for testing.

The goal was to observe how Windows Task Scheduler launches a legitimate application and establish the normal process ancestry before comparing it with a more suspicious persistence mechanism.

### Falcon Task Invocation

Falcon recorded the command used to request execution of the scheduled task:

```text
schtasks /run /tn "Lab03-Benign-Notepad"
```

![Falcon telemetry showing benign scheduled task invocation](../../screenshots/lab-03/lab-03-01-benign-scheduled-task-invocation.png)

*Falcon process telemetry showing `schtasks.exe` invoked from an interactive command prompt to run the benign scheduled task.*

### Falcon Scheduled Task Execution

Falcon also recorded the process created by Windows Task Scheduler.

The resulting process ancestry showed:

```text
wininit.exe
   ↓
services.exe
   ↓
svchost.exe
   ↓
Notepad.exe
```

![Falcon process tree showing benign scheduled task execution](../../screenshots/lab-03/lab-03-02-benign-scheduled-task-execution.png)

*Falcon process tree showing Task Scheduler-related service activity launching `Notepad.exe`, establishing the benign scheduled-task execution baseline.*

The important observation was that `schtasks.exe` did not directly launch Notepad. Instead, the task request was handled through Windows service infrastructure, and `svchost.exe` became the parent process of `Notepad.exe`.

This demonstrated why process ancestry matters when investigating scheduled execution.

## Suspicious Scheduled Task Persistence

For the suspicious persistence simulation, I created a scheduled task configured to run at user logon and launch PowerShell with hidden execution and additional command-line arguments, including `-NoProfile` and `-ExecutionPolicy Bypass`.

For the purpose of the lab, I manually triggered the task instead of logging off and back in, then reviewed the resulting Falcon telemetry to compare the execution context with the benign scheduled task.

### Scheduled Task Registration

Falcon recorded the scheduled task at the time it was registered, before the task was executed.

The telemetry showed the task name, the executable it was configured to launch, the PowerShell arguments, and contextual tactic information related to scheduled-task activity.

This was valuable because it provided visibility into the persistence mechanism before the PowerShell process ever ran.

![Falcon telemetry showing suspicious scheduled task registration](../../screenshots/lab-03/lab-03-03-suspicious-scheduled-task-registration.png)

*Falcon telemetry showing registration of the suspicious scheduled task, including the logon trigger, PowerShell execution, and command-line arguments associated with the persistence mechanism.*

### Suspicious Scheduled Task Process Tree

After the task was triggered, Falcon recorded the resulting execution chain.

The process ancestry showed:

```text
wininit.exe
   ↓
services.exe
   ↓
svchost.exe
   ↓
powershell.exe
```

This differed from the benign task, which used the same Windows service infrastructure but ultimately launched `Notepad.exe`.

The ancestry itself does not prove malicious activity, but when combined with the PowerShell command line and logon trigger, it created a more suspicious execution context.

![Falcon process tree showing suspicious scheduled task execution](../../screenshots/lab-03/lab-03-05-suspicious-scheduled-task-process-tree.png)

*Falcon process tree showing Windows service activity launching `powershell.exe` through the scheduled task.*

### PowerShell Process Event

Falcon also recorded the PowerShell process event and preserved the full command-line context.

The command line included:

- `-NoProfile`
- `-WindowStyle Hidden`
- `-ExecutionPolicy Bypass`
- a harmless command that wrote a timestamp to a local text file

These arguments created a more suspicious execution pattern than the benign Notepad task, even though the action itself remained harmless.

![Falcon process event showing suspicious PowerShell execution](../../screenshots/lab-03/lab-03-04-suspicious-powershell-process-event.png)

*Falcon process telemetry showing `powershell.exe` launched by `svchost.exe` with hidden execution, `-NoProfile`, and `-ExecutionPolicy Bypass` during the scheduled-task persistence simulation.*

### Local Validation

The scheduled task successfully executed and wrote a timestamp to the harmless marker file:

```text
%TEMP%\lab03-persistence.txt
```

This confirmed that the task executed as configured.

![Local validation of suspicious scheduled task execution](../../screenshots/lab-03/lab-03-06-suspicious-task-local-validation.png)

*Local validation confirming the suspicious scheduled task was registered, executed, and successfully wrote a timestamp to the harmless persistence marker file.*

### Detection Result

Falcon did not generate a detection for this activity.

Although the scheduled task created suspicious execution context, the action itself remained harmless. The task launched PowerShell with unusual arguments but ultimately only wrote a timestamp to a local text file.

This demonstrated the difference between suspicious-looking telemetry and activity that is sufficiently malicious to generate a detection.

## Benign vs Suspicious Comparison

| Benign Baseline | Suspicious Scheduled Task |
|---|---|
| Daily scheduled trigger at a specific time | `AtLogOn` trigger configured to run automatically when the user logs in |
| Task launched `notepad.exe` | Task launched `powershell.exe` to execute a scripted command |
| Simple Notepad execution with no unusual arguments | PowerShell used `-NoProfile`, `-WindowStyle Hidden`, and `-ExecutionPolicy Bypass` |
| Falcon recorded expected scheduled-task telemetry | Falcon recorded task registration, unusual command-line arguments, and service-launched PowerShell activity |
| No detection generated | No detection generated |

The key difference was not the use of Task Scheduler by itself. Both tasks used the same legitimate Windows mechanism.

The more important differences were the trigger, launched process, command-line context, and resulting execution behavior. Those details made the suspicious variant more worthy of analyst investigation even though the action itself remained harmless.

## Investigation Findings

The suspicious scheduled-task activity could be reconstructed chronologically using Falcon telemetry.

First, Falcon recorded the scheduled-task registration event. This provided visibility into when the persistence mechanism was created, how it was configured, the executable it would launch, and the associated command-line arguments.

When the task executed, Falcon showed `powershell.exe` being launched through Windows service infrastructure. The process tree provided the execution ancestry, while the process event preserved the full PowerShell command line and other details that could be tied back to the registered task.

The process tree and command-line context were more useful than simply seeing that `powershell.exe` ran. Together, they showed how the task executed and gave the analyst enough context to determine whether the behavior was expected, suspicious, or malicious.

In this lab, the execution looked suspicious but ultimately remained harmless, so Falcon recorded telemetry without generating a detection.

## MITRE ATT&CK Mapping

| Observed Behavior | Technique | ID | Evidence | Why It Fits |
|---|---|---|---|---|
| A Windows Scheduled Task was created with an `AtLogOn` trigger to automatically launch PowerShell | Scheduled Task/Job: Scheduled Task | T1053.005 | Falcon `ScheduledTaskRegisteredV3` telemetry showing the task registration, logon trigger, PowerShell action, and associated arguments | The task used Windows Task Scheduler to establish recurring execution at user logon, which matches the behavior described by T1053.005 |

### Mapping Notes

This mapping is based on the behavior that was actually demonstrated in the lab.

Windows Scheduled Tasks are a legitimate administrative feature and are not inherently malicious. The suspicious context came from the combination of the `AtLogOn` trigger, automatic PowerShell execution, and command-line arguments such as `-WindowStyle Hidden`, `-NoProfile`, and `-ExecutionPolicy Bypass`.

Falcon also associated the scheduled-task telemetry with tactic context related to Execution, Persistence, and Privilege Escalation. This does not prove that malicious privilege escalation occurred during the lab; it provides behavioral context around how scheduled tasks can be abused.

No additional ATT&CK techniques are mapped because the PowerShell command only wrote a harmless timestamp to a local file and did not perform network communication, credential access, payload execution, or destructive activity.

## How CrowdStrike Falcon Maps to This Scenario

CrowdStrike Falcon provided the primary endpoint visibility used to investigate the scheduled-task persistence behavior in this lab.

During the suspicious variant, Falcon recorded the scheduled-task registration event before the task executed. The telemetry exposed the task name, trigger, executable, PowerShell arguments, and related tactic context.

When the task later executed, Falcon also recorded the resulting process ancestry and PowerShell process event.

This allowed the activity to be reconstructed as:

```text
Scheduled task registered
        ↓
AtLogOn trigger configured
        ↓
Windows service infrastructure
        ↓
powershell.exe
        ↓
Harmless timestamp command
```

## Detection vs Prevention vs Investigation vs Response

### Detection

Detection is the process of identifying activity that may be suspicious or malicious.

In this lab, Falcon did not generate a detection for the scheduled-task persistence simulation. Instead, it recorded detailed telemetry showing the task registration, PowerShell command line, process ancestry, and resulting execution.

The absence of a detection did not mean the activity was invisible. Falcon still provided enough context for an analyst to determine that the behavior was unusual and worth investigating.

### Prevention

Prevention is the process of stopping malicious activity from executing or completing its intended effect.

Falcon prevention was intentionally disabled during this lab so the scheduled task could execute and the resulting telemetry could be observed.

Because the PowerShell action only wrote a harmless timestamp to a local file, this lab does not demonstrate Falcon prevention.

### Investigation

Investigation is the process of understanding what happened and determining whether the behavior represents legitimate activity or a security threat.

In this lab, investigation included reviewing:

- the scheduled-task registration event;
- the `AtLogOn` trigger;
- the PowerShell execution arguments;
- the process tree;
- the `svchost.exe → powershell.exe` relationship;
- the resulting timestamp file.

Together, these details allowed the scheduled-task activity to be reconstructed from creation through execution.

### Response

Response is the action taken after suspicious or malicious activity has been confirmed.

If this behavior were confirmed as malicious in a real environment, an analyst could investigate related activity, remove the persistence mechanism, terminate malicious processes, isolate the affected endpoint, and search for similar behavior elsewhere.

This lab focused on visibility and investigation rather than active response.

## Business Value

This lab demonstrated how suspicious persistence can create an investigation challenge for a security team, especially when a scheduled task contains unusual triggers, PowerShell execution, and suspicious-looking command-line arguments.

Falcon made the activity easier to investigate by providing visibility into the scheduled-task registration before the task executed. This allowed the persistence mechanism, trigger, executable, and command-line arguments to be reviewed before the resulting PowerShell process ran.

After execution, Falcon also provided the process tree and full process telemetry needed to understand how the task executed and what it actually did.

From an operational perspective, this type of centralized endpoint context can reduce the amount of manual correlation required across tools such as Sysmon, Event Viewer, or process-monitoring utilities.

For a security team, that can support:

- faster triage;
- earlier investigation of persistence mechanisms;
- less time spent switching between separate tools;
- more informed decisions about whether suspicious activity requires escalation.

For security leadership, the value is improved analyst efficiency and faster understanding of endpoint behavior, allowing the team to spend more time responding to meaningful risks instead of manually reconstructing routine activity.

## SE Talk Track

"In this lab, I investigated a suspicious scheduled task that used behavior associated with MITRE ATT&CK T1053.005 — Scheduled Task/Job: Scheduled Task.

Falcon gave me visibility into the task registration, logon trigger, PowerShell command line, and resulting process ancestry, which allowed me to reconstruct the activity from creation through execution.

The behavior looked suspicious because of the persistence mechanism and PowerShell arguments, but the investigation showed that the task ultimately performed a harmless action.

The customer value is faster investigation with relevant endpoint context available in one platform, helping analysts determine whether activity is expected, suspicious, or malicious without manually reconstructing the event across multiple tools."


## Limitations

This lab was designed as a controlled persistence simulation and does not represent a real compromise or production attack.

Key limitations include:

- The scheduled task performed only a harmless timestamp-writing action.
- No malware, credential theft, lateral movement, destructive behavior, or external command-and-control activity was used.
- Falcon recorded the activity as telemetry but did not generate a detection.
- Prevention was intentionally disabled so the execution could be observed and investigated.
- The task was manually triggered for testing instead of waiting for an actual logon event.
- The lab demonstrated one persistence technique and does not represent every way scheduled tasks can be abused.
- Falcon tactic context associated with the task does not prove that every listed tactic, such as Privilege Escalation, actually occurred in this lab.

## What I Learned

This lab taught me how powerful and flexible Windows Scheduled Tasks can be. They are useful for legitimate administration and automation, but that same functionality can also be abused for persistence. A scheduled task configured to run automatically at logon can continue executing without obvious user interaction, which makes understanding the trigger, action, and execution context important during an investigation.

I also learned more about the difference between Falcon telemetry and a Falcon detection. In this lab, prevention was disabled, but detection capability was still available. Falcon did not generate a detection because the scheduled task ultimately performed a harmless action. Even without a detection, Falcon recorded the task registration, trigger, command-line arguments, process ancestry, and resulting PowerShell execution.

The biggest lesson was that suspicious behavior does not automatically mean malicious behavior. Falcon provided enough context to investigate the activity from creation through execution and determine what the scheduled task actually did. In a real investigation, that visibility could help an analyst decide whether the activity should be allowed, removed, contained, or escalated for further response.

