# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Rashwani/Threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Search the DeviceFileEvents table for any file that had the string “tor” in it and discovered what looks like the user “Yamen” downloaded a Tor installer. Did something that resulted in many tor-related files being copied to the desktop and the creation of the file called “tor/shoppinglist.txt” on the desktop. These events began at: 2026-03-30T18:56:25.1023698Z


**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "yamen-vm"
| where InitiatingProcessAccountName == "yamen"
| where FileName contains "tor"
|where Timestamp >= datetime(2026-03-30T18:56:25.1023698Z)
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, account = InitiatingProcessAccountName
|order by Timestamp desc

```
<img width="1726" height="803" alt="image" src="https://github.com/user-attachments/assets/20b7e528-9265-430a-9093-d9f6278a324f" />


---

### 2. Searched the `DeviceProcessEvents` Table

Search the DeviceProcessEvents table for any ProcessCommandLline that contains the string”tor-browser-windows-x86_64-portable-15.0.8” . based on the logs returned. At 3:00 PM on March 30, 2026, on the machine “yamen-vm,” a user named yamen quietly launched a Tor Browser installer from their Downloads folder, executing the command tor-browser-windows-x86_64-portable-15.0.8.exe /S to run it in silent mode with no visible prompts.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "yamen-vm"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8"
| project Timestamp, DeviceName, AccountName,   ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc 

```
<img width="1740" height="638" alt="image" src="https://github.com/user-attachments/assets/ff13b2c9-1567-4757-bafc-4f958ac2ccdb" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Search the DeviceProcessEvents table for any indication that user "Yamen" actually opened up the Tor browser. It was evident that they did open it at: 2026-03-30T19:01:33.7347398Z. There were several other instances of Firefox.exe, Tor, as well as Tor.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "yamen-vm"
| where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe","start-tor-browser.exe","torbrowser-launcher.exe")
| project Timestamp, DeviceName, AccountName,   ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc

```
<img width="1692" height="790" alt="image" src="https://github.com/user-attachments/assets/4347d9fc-1dc2-46eb-936e-bf13e2b072cd" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication that Tor Browser was used to establish a connection by using any of the known Tor ports. At  At 3:02 PM on March 30, 2026, the user “yamen” on the machine “yamen-vm,” the user yamen executed tor.exe from the path c:\users\yamen\desktop\tor browser\browser\torbrowser\tor\tor.exe, successfully connecting to a remote server at IP 195.218.16.136 over port 9001, and accessing the defanged URL hxxps://www[.]renujtiyp3eaczi3g6z5[.]com/. There were few other connections to sites on ports 443.


**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName =="yamen-vm"
| where  InitiatingProcessFileName in ( "tor.exe", "firefox")
| where RemotePort in ("9001","9030","9050","9051","9150","9151", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 

```
<img width="1697" height="785" alt="image" src="https://github.com/user-attachments/assets/f810ecf3-7fd2-4d45-846e-184969bbdd52" />


---

## Chronological Event Timeline 

1. File Download - TOR Installer
Timestamp: 2026-03-30 14:56:25 - 14:56:28
Event: User "yamen" downloaded the TOR Browser installer tor-browser-windows-x86_64-portable-15.0.8.exe to the Downloads folder.
Action: File download detected and completed.
File Path: C:\Users\yamen\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe
SHA256: 9e944e98ccb25186b9fd851938648d18ea2d65d77fd758383c5605abac9f1d04

2. Process Execution - TOR Browser Installation
Timestamp: 2026-03-30 15:00:38
Event: User "yamen" executed the TOR installer in silent mode, initiating a background (no prompt) installation.
Action: Process creation detected.
Command: tor-browser-windows-x86_64-portable-15.0.8.exe /S
File Path: C:\Users\yamen\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe


3. File Creation - TOR Browser Extraction
Timestamp: 2026-03-30 15:00:50 - 15:00:55
Event: TOR Browser files were extracted to the Desktop directory, including core binaries and shortcut files.
Action: Multiple file creation events detected.
File Path: C:\Users\yamen\Desktop\Tor Browser\
Key Files: tor.exe, firefox.exe, Tor Browser.lnk, license files

4. Process Execution - TOR Browser Launch
Timestamp: 2026-03-30 15:01:33
Event: User "yamen" launched the TOR Browser, spawning the main firefox.exe process from the Desktop installation path.
Action: Process creation detected.
File Path: C:\Users\yamen\Desktop\Tor Browser\Browser\firefox.exe

5. Process Execution - TOR Service Initialization
Timestamp: 2026-03-30 15:01:36
Event: tor.exe was executed with full configuration, establishing local proxy and control ports required for TOR communication.
Action: Process creation and service initialization detected.
Process: tor.exe
Details:
SOCKS Proxy: 127.0.0.1:9150
Control Port: 127.0.0.1:9151
File Path: C:\Users\yamen\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

6. Network Connections - TOR Network Activity
Timestamp: 2026-03-30 15:01:40 - 15:02:59
Event: tor.exe established multiple outbound connections to external TOR relay nodes over ports 443 and 9001.
Action: Multiple successful connections detected.
Process: tor.exe
Connections:
77.48.28.193:443
23.111.179.98:443
64.65.63.88:443
185.107.57.66:443
195.218.16.136:9001 → hxxps://www[.]renujtiyp3eaczi3g6z5[.]com
64.65.62.38:443
Note: Obfuscated domains and port usage are consistent with TOR relay infrastructure.


7. Process Activity - TOR Browser Usage
Timestamp: 2026-03-30 15:01:35 - 15:15:08
Event: TOR Browser spawned 18+ child firefox.exe processes (content, GPU, RDD, utility), indicating active browsing activity.
Action: Multiple process creations detected.

8. File Creation - Browser Interaction Artifact
Timestamp: 2026-03-30 15:09:07
Event: formhistory.sqlite was created within the browser profile, indicating that the user interacted with a web form during the TOR session.
Action: File creation detected.
File Path: C:\Users\yamen\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\


9. File Creation - TOR Shopping List
Timestamp: 2026-03-30 15:18:26
Event: User "yamen" created and accessed a file named tor-shopping-list.txt, with a corresponding shortcut in the Windows Recent folder.
Action: File creation and execution detected.
File Path: C:\Users\yamen\Documents\tor-shopping-list.txt
SHA256: 41f273f6dc6cadbefa2ac5067f80eeff495ed07c9b1397369f946ecf03db4e11



---

## Summary

On March 30, 2026, between 2:56 PM and 3:18 PM, the user "yamen" on endpoint "yamen-vm" downloaded and silently installed Tor Browser (v15.0.8) to their Desktop, launched it, and established encrypted connections to multiple Tor relay nodes on ports 443 and 9001. The user actively browsed for approximately 14 minutes, interacted with at least one web form, and then created a file called tor-shopping-list.txt in their Documents folder. The silent installation method, use of the Tor anonymity network, obfuscated relay domains, and the creation of a "shopping list" file collectively warrant further investigation into the file's contents and the user's intent.


---

## Response Taken

TOR usage was confirmed on the endpoint “yamen-vm”. By the user “yamen”.  The device was isolated and the user's direct manager was notified.


---
