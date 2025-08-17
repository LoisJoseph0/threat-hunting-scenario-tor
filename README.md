# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/LoisJoseph0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user "labuser" downloaded a tor installer, did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor-shopping-txt.txt” on the desktop at 2025-08-17T11:44:46.5752926Z. These events began at: 2025-08-17T11:12:37.1176132Z

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "lois-test-vm-md"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-08-17T11:12:37.1176132Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName

```
<img width="1345" height="597" alt="image" src="https://github.com/user-attachments/assets/01255393-a193-4859-9761-c3db98bc015d" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.5.exe”. Based on the logs returned, at 2025-08-17T11:13:04.3024319Z,  user: labuser  on the lois-test-vm-md device executed the file tor-browser-windows-x86_64-portable-14.5.5.exe from their Downloads folder, using a command that triggered a silent installation, creating a new process (Tor Browser installer) at the recorded timestamp.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "lois-test-vm-md"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1482" height="518" alt="image" src="https://github.com/user-attachments/assets/64ca248a-1c45-43b0-b357-983cb253bb69" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “labuser” actually opened the tor browser. There was evidence that they did open it at: 2025-08-17T11:18:01.6324397Z there were several other instances of firefox.exe (Tor) as well as for.exe spawned afterwards

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "lois-test-vm-md"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| order by Timestamp desc
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine

```
<img width="1497" height="642" alt="image" src="https://github.com/user-attachments/assets/f1d885e4-abd3-4563-ba6a-0bf655fcf625" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At 2025-08-17T11:18:18.720529Z, the user labuser on device lois-test-vm-md successfully made a network connection from tor.exe (located in the Tor Browser folder) to the remote IP address 2.56.176.89 over port 9001. There were a couple other connections to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "lois-test-vm-md"
| where InitiatingProcessAccountName == "labuser"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc

```
<img width="1512" height="652" alt="image" src="https://github.com/user-attachments/assets/20b4c52a-ac90-4e10-b187-c70bf72410e4" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-17T11:12:37.1176132Z`
- **Event:** The user "labuser" had the Tor installer tor-browser-windows-x86_64-portable-14.5.5.exe present in Downloads (rename observed, consistent with a recent download).
- **Action:** File rename detected (post-download handling).
- **File Path:** `C:\Users\Labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-17T11:17:09Z`
- **Event:** The user "labuser" executed the Tor installer in silent mode, initiating an unattended installation.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\Labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-17T11:18:01.6324397Z`
- **Event:** The user "labuser" opened Tor Browser; firefox.exe and subsequent Tor-related processes (tor.exe) were spawned, indicating a successful launch.
- **Action:** Process creation of Tor Browser–related executables detected.
- **File Path:** `C:\Users\Labuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-17T11:18:18.720529Z`
- **Event:** A network connection to IP 2.56.176.89 on port 9001 by user "labuser" was established using tor.exe, confirming Tor network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-17T17:50:04Z – Connected again to 2.56.176.89 on port 9001 using tor.exe.`.
  - `(Within the same session window) Connections observed to 54.36.205.38:9001, 149.50.13.221:443, 185.174.135.11:443, and local 127.0.0.1:9150 (SOCKS).`.
- **Event:** Additional Tor network connections were established, indicating continued Tor use by "labuser".
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-17T11:44:46.5752926Z`
- **Event:** The user "labuser" created a file named tor-shopping-txt.txt on the desktop, appearing during the Tor session.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Labuser\Desktop\tor-shopping-txt.txt`

---

## Summary

On Aug 17, 2025 (07:12–13:50 ET), user labuser on lois-test-vm-md downloaded and executed the Tor Browser installer with the /S (silent) switch, which unpacked Tor components and created a desktop shortcut; shortly after, Tor Browser (firefox.exe) and tor.exe ran and established Tor relay connections (e.g., 2.56.176.89:9001 and others), and a desktop file named tor-shopping-txt.txt appeared. Taken together—silent installation, immediate Tor connectivity, and a “shopping” note—this sequence likely indicates the user was deliberately setting up Tor to browse and possibly research or plan purchases anonymously (on privacy-focused or hidden services), aiming to minimize visibility/monitoring. No direct evidence of data exfiltration was observed in the reviewed windows; activity centers on establishing private/anonymous browsing via Tor.


---

## Response Taken

TOR usage was confirmed on endpoint lois-test-vm-md by the user labuser The device was isolated and the user's direct manager was notified.


---
