<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/LeoSun58/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
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

Searched for any file that had the string "tor" in it and discovered what looks like the user "kerestel" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-09-30T19:34:41.341423Z`. These events began at `2026-09-30T20:29:25.5370513Z`.

**Query used to locate events:**

```kql
 DeviceFileEvents
| where FileName contains "tor" 
| where DeviceName contains "EDR-Lab-Keres"
| where InitiatingProcessAccountName == "kerestel"
| where Timestamp >= datetime('2026-09-30T20:29:25.5370513Z')
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName, ParentFile = InitiatingProcessParentFileName

```
<img width="1562" height="469" alt="Screenshot 2026-10-05 at 4 00 01 PM" src="https://github.com/user-attachments/assets/2a26ab92-3833-4650-a352-c953fb77f33d" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows". Based on the logs returned, at `2026-09-30T20:32:11.764655Z`, an employee on the "EDR-Lab-Keres" device ran the file `tor-browser-windows-x86_64-portable-15.0.20.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName contains "EDR-Lab-Keres"
| where ProcessCommandLine contains "tor-browser-windows"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, ProcessCreationTime, InitiatingProcessCommandLine, InitiatingProcessFileName

```
<img width="1627" height="108" alt="Screenshot 2026-10-05 at 4 09 52 PM" src="https://github.com/user-attachments/assets/b9c1caff-8a99-4c6b-88d3-12204c81ff76" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "kerestel" actually opened the TOR browser. There was evidence that they did open it at `2026-09-30T20:33:16.2681622Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName contains "EDR-Lab-Keres"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe")
| order by TimeGenerated desc 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName

```
<img width="1625" height="468" alt="Screenshot 2026-10-06 at 10 36 48 AM" src="https://github.com/user-attachments/assets/c0a5cb76-6605-4fa7-abd0-94c78a230675" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-09-30T20:33:35.463045Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `216.197.207.49` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\kerestel\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a few other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName contains "EDR-Lab-Keres"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("firefox.exe", "tor.exe")
| where RemotePort in ("9001", "9030", "9040", "9050", "9150", "80", "443")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, LocalIP, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by TimeGenerated desc
```
<img width="1432" height="354" alt="Screenshot 2026-10-06 at 10 40 01 AM" src="https://github.com/user-attachments/assets/28eb9bcf-90fd-4380-b2ce-36be4530caf2" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-09-30T20:29:25.5370513Z`
- **Event:** The user "kerestel" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.20.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\Kerestel\Downloads\tor-browser-windows-x86_64-portable-15.0.20.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-09-30T20:32:11.764655Z`
- **Event:** The user "kerestel" executed the file `tor-browser-windows-x86_64-portable-15.0.20.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.20.exe /S`
- **File Path:** `C:\Users\Kerestel\Downloads\tor-browser-windows-x86_64-portable-15.0.20.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-09-30T20:33:16.2681622Z`
- **Event:** User "kerestel" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\Kerestel\Desktop\Tor Browser\Browser\firefox.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-09-30T20:33:35.463045Z`
- **Event:** A network connection to IP `216.197.207.49` on port `9001` by user "kerestel" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\kerestel\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-09-30T20:33:37.6187466Z` - Connected to `162.251.116.26` on port `443`.
  - `2026-10-01T01:36:30.197321Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-10-01T01:41:10.3492051Z`
- **Event:** The user "kerestel" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\Kerestel\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.lnk`

---

## Summary

The user "kerestel" on the "EDR-Lab-Keres" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `EDR-Lab-Keres` by the user `kerestel`. The device was isolated, and the user's direct manager was notified.

---
