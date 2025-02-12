# **PersistencePatrol - Scheduled Tasks (schtasks.exe) Monitoring Script**

## **Overview**
This script monitors the Windows Security event log for the creation of **schtasks.exe** processes. It specifically checks whether the command executed by schtasks.exe contains the **"/create"** or **"/change"** parameters, which may indicate an attempt to schedule or modify a task. By doing so, the script helps identify when a process (including potential malware) is trying to establish persistence on the system.

---

## **What is schtasks.exe?**
`schtasks.exe` is a built-in Windows command-line utility that allows users to schedule, modify, and manage tasks that run automatically. It is often used by system administrators to execute scripts, run updates, or perform maintenance at predefined intervals.

### **Common Uses of schtasks.exe:**
- Automating system tasks (e.g., backups, updates, and maintenance scripts)
- Running scripts at system startup or login
- Managing scheduled jobs remotely

---
&nbsp; 


## **How Malware Uses schtasks.exe for Persistence**
Cybercriminals and malware authors commonly abuse `schtasks.exe` to establish **persistence**, ensuring that their malicious payloads are executed automatically, even after a system restart.

Adversaries sometimes exploit scheduled tasks to connect to external domains and download arbitrary binaries on a set or recurring schedule.

Malware and threat actors frequently use Windows shell scripting tools such as CMD, PowerShell, Wscript, and Cscript to repeatedly execute their malicious scripts, while also taking advantage of other commonly abused LOLBAS.

Additionally, adversaries also attempt to disguise malicious scheduled tasks as legitimate processes like 'svchost.exe', 'lsass.exe', and others to evade detection.


### **Malware Persistence via schtasks.exe**
1. **Creating a Malicious Scheduled Task**
   - Example: A malware sample may execute the following command to ensure it runs every time the user logs in:
     ```sh
     schtasks /create /tn "Malware_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"
     ```
   - This creates a scheduled task named **"Malware_OnStartup"**, which executes the calc.exe.

2. **Modifying an Existing Scheduled Task**
   - Malware can also modify an existing legitimate scheduled task to execute its payload instead:
     ```sh
     schtasks /change /tn "Microsoft\Windows\Defrag\ScheduledDefrag" /tr "C:\malware.exe"
     ```
   - This replaces a trusted system task with a malicious executable.

3. **Disguising Malicious Tasks**
   - Attackers may use misleading task names or hide tasks within legitimate Windows paths to avoid detection.

By monitoring `schtasks.exe` usage, we can detect suspicious task creation and modification attempts that may indicate an active attack.

&nbsp; 

---

## **How This Script Helps Detect Malicious Activity**
This script continuously monitors **Windows Event Logs** for **process creation events (Event ID 4688)** related to `schtasks.exe`. It specifically looks for the `"/create"` or `"/change"` parameters in the executed command, as these indicate potential persistence attempts. 

### **How It Works:**
1. **Monitors Process Creation Logs**
   - It reads Windows Security Event Logs to identify when a process is started.
2. **Filters for schtasks.exe**
   - The script checks if the newly created process is `schtasks.exe`.
3. **Detects Persistence Attempts**
   - It scans the command-line arguments for the **"/create"** or **"/change"** keywords.
4. **Alerts the User**
   - If a suspicious task creation or modification is detected, the script can log the event or trigger an alert.

&nbsp; 

## **Running the Script**

### **Prerequisites:**
Enable moniroting of Process creation in Windows Event Logs:
```
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
```
Enable 'Command Line' data in Process Auditing.
```
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```
&nbsp; 
### **Example Detection Output:**
If the script detects a suspicious scheduled task creation, it may log output similar to:
```
[ALERT] POTENTIALLY MALIOUS SCHEDULED TASK CREATED
         PID :: 20100
                Process Name :: C:\Windows\System32\schtasks.exe
                Parent PID :: 16092
                Parent Process Name :: C:\Windows\System32\cmd.exe
                Command :: schtasks  /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
```


---

## **Conclusion**
By monitoring **schtasks.exe**, this script helps detect malicious persistence mechanisms used by attackers. This proactive approach provides visibility into potential threats operating on the system.

🔹 **If you notice unexpected task creation, investigate immediately!** It may indicate malware attempting to maintain persistence on the system.

---

## **Improvements to be made**
- **Monitor Schduled task creation also via event ID 4698** (e.g., email or log forwarding to SIEM)
- **Monitor Additional Persistence Methods** beyond schtasks.exe

This script serves as an example tool in identifying malware trying to achieve persistance using Windows Scheduled Tasks. 🚀

