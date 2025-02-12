import win32evtlog
import win32evtlogutil
import win32con
import time
from datetime import datetime


# Define the Event ID for process creation
PROCESS_CREATION_EVENT_ID = 4688

def date2sec(evt_date):

    '''

    This function converts dates with format
    '12/23/99 15:54:09' to seconds since 1970.

    '''
    date_format = "%a %b %d %H:%M:%S %Y"
    date_obj = datetime.strptime(evt_date, date_format)
    seconds_since_epoch = int(date_obj.timestamp())
    return seconds_since_epoch



def monitorProcess(server, logType, flags):

    persistenceProcess = ["schtasks.exe", "taskeng.exe", "at.exe",]
    Suskeywords = ["create","change", # SUSPICIOUS COMMANDS
                   "\\InstallUtil.exe","taskschd.dll","\\RUNDLL32.EXE","\\msiexec.exe","\\RegSvcs.exe","\\MSHTA.EXE","\\CMD.Exe","\\PowerShell.EXE","\\cscript.exe","\\CONTROL.EXE","\\RegAsm.exe","\\REGSVR32.EXE","\\wscript.exe","\\Microsoft.Workflow.Compiler.exe","\\MSBuild.exe","\\msxsl.exe","\\atbroker.exe","\\audiodg.exe","\\bcdedit.exe","\\bitsadmin.exe","\\certreq.exe","\\certutil.exe","\\cmstp.exe","\\conhost.exe","\\consent.exe","\\csrss.exe","\\dashost.exe","\\defrag.exe","\\dfrgui.exe","\\dism.exe","\\dllhost.exe","\\dllhst3g.exe","\\dwm.exe","\\eventvwr.exe","\\logonui.exe","\\LsaIso.exe","\\lsass.exe","\\lsm.exe","\\ntoskrnl.exe","\\powershell_ise.exe","\\pwsh.exe","\\runonce.exe","\\RuntimeBroker.exe","\\schtasks.exe","\\services.exe","\\sihost.exe","\\smartscreen.exe","\\smss.exe","\\spoolsv.exe","\\svchost.exe","\\taskhost.exe","\\Taskmgr.exe","\\userinit.exe","\\wininit.exe","\\winlogon.exe","\\winver.exe","\\wlanext.exe","\\wscript.exe","\\wsl.exe","\\wsmprovhost.exe", # LEGITIMATE PROCESSES - MAY BE USED TO MASQUERADE
                   ":\\ProgramData\\",":\\Temp\\",":\\Tmp\\",":\\Users\\Public\\",":\\Windows\\Temp\\","\\AppData\\","%AppData%","%Temp%","%tmp%","C:\\$WINDOWS.~BT\\","C:\\$WinREAgent\\","C:\\Windows\\SoftwareDistribution\\","C:\\Windows\\System32\\","C:\\Windows\\SystemTemp\\","C:\\Windows\\SysWOW64\\","C:\\Windows\\uus\\","C:\\Windows\\WinSxS\\","\\Desktop\\",  # SUSPICIOUS LOCATIONS                
                   "https://","http://"] # SUSPICIOUS NETWORK CONNECTIONS

    # OPENING AND READING THE EVENTLOG TO FIND THE LATEST EVENT. 
    logHandle = win32evtlog.OpenEventLog(server, logType)
    print("Initializing...")
    while True:
            try:
                events = win32evtlog.ReadEventLog(logHandle, flags, 0)
                break
            except:
                print("Unable to read Event Log. Trying again.")
                time.sleep(2)

    for index,event in enumerate(events):
        if index == 0:
            eventTime = event.TimeGenerated.Format()
            print(eventTime)
            LatestTime = date2sec(eventTime)
            break
    time.sleep(2)
    
    print("Monitoring Scheduled Tasks...")

    while True:
        logHandle = win32evtlog.OpenEventLog(server, logType)
        while True:
            try:
                events = win32evtlog.ReadEventLog(logHandle, flags, 0)
                break
            except:
                print("Unable to read Event Log. Trying again.")
                time.sleep(2)


        for index, event in enumerate(events):

            if index == 0:
                newLatestTime = date2sec(event.TimeGenerated.Format())
    
            eventTime = date2sec(event.TimeGenerated.Format())
            
            if eventTime > LatestTime: # TARGETING ONLY NEWLY CREATED EVENTS. 
                if event.EventID == PROCESS_CREATION_EVENT_ID:
                    if hasattr(event, 'StringInserts'):
                        if any(process in event.StringInserts[5] for process in persistenceProcess):
                            print()
                            if any(word.lower() in event.StringInserts[8].lower() for word in Suskeywords):
                                print("[ALERT] POTENTIALLY MALIOUS SCHEDULED TASK CREATED")
                            else:
                                print("SCHTASKS.EXE EXECUTION DETECTED.")
                            print("\t PID ::",int(event.StringInserts[4], 16))
                            print("\t\tProcess Name ::", event.StringInserts[5])
                            print("\t\tParent PID ::", int(event.StringInserts[7], 16))
                            print("\t\tParent Process Name ::", event.StringInserts[13])
                            print("\t\tCommand ::", event.StringInserts[8])

        LatestTime = newLatestTime
        time.sleep(0.5)


def main():

    # GETTING READY TO READ EVENT LOG
    server = None  # LOCAL MACHINE
    logType = "Security"
    flags = win32evtlog.EVENTLOG_SEQUENTIAL_READ | win32evtlog.EVENTLOG_BACKWARDS_READ

    monitorProcess(server, logType, flags)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nMonitoring Stopped.")
        print("Bye")