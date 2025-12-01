# 📘 Assisted Lab – Configuring Centralized Logging & Searching Logs with Regex
**CompTIA CySA+ | Structureality Inc. | Windows Event Forwarding (WEF) & Linux Log Analysis**  
**Author:** Asad Khan  

---

## 📑 Table of Contents
- [Overview](#overview)  
- [Scenario](#scenario)  
- [Objectives](#objectives)  
- [Lab Environment](#lab-environment)  
- [Part 1 — Configure DC10 as the Collector](#-part-1--configure-dc10-as-the-collector)  
- [Part 2 — Configure MS10 as the Logging Source](#-part-2--configure-ms10-as-the-logging-source)  
- [Part 3 — Create Event Subscription on DC10](#-part-3--create-event-subscription-on-dc10)  
- [Verification (Forwarded Events)](#-verification)  
- [Centralized Logging – Key Takeaways](#-centralized-logging--key-takeaways)  
- [Searching Logs with Regex (LAMP)](#-assisted-lab--searching-logs-with-regex)  
- [Regex – Key Takeaways](#-key-takeaways)  
- [Screenshot Placeholders](#-screenshot-placeholders)  

---

## Overview
This combined lab demonstrates:

- How to configure **centralized logging** in a Windows domain using Windows Event Forwarding (WEF)  
- How to **search and extract useful data from logs** on Linux using `grep` and **regular expressions (regex)**  

You will configure:

- A **Windows log collector** and **log source**  
- A **collector-initiated subscription** to forward logs  

Then you will:

- Enable logging on Linux  
- Use regex to extract **IPv4 addresses** from kernel logs  
- Count and highlight suspicious IP addresses  

---

## Scenario
As a cybersecurity analyst at **Structureality Inc.**, you must:

- Aggregate logs centrally for auditing, correlation, and incident response  
- Be able to mine logs for **Indicators of Compromise (IoCs)**, including IPs and patterns of activity  

In this lab:

- **DC10** acts as the **log collector**  
- **MS10** is the **log source**  
- **LAMP** is used for **log parsing and regex** practice  

---

## Objectives
This lab supports **CompTIA CySA+** objectives:

- **1.1** — Explain the importance of system and network architecture concepts in security operations  
- **1.2** — Analyze indicators of potentially malicious activity  
- **1.3** — Use tools and techniques to determine malicious activity  

---

## Lab Environment
| Host | OS / Role |
|------|-----------|
| **DC10** | Windows Server 2019 (Collector) |
| **MS10** | Windows Server 2016 (Source) |
| **LAMP** | Ubuntu Server (Regex + grep activities) |

---

# 🛠 Part 1 — Configure DC10 as the Collector

### Step 1: Update GPO to allow WinRM listener access
Run PowerShell as **Administrator** on **DC10**:

```powershell
Import-Module GroupPolicy

$gpo = Get-GPO -Name "cc-domain-default"

$winrmRegKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service"

Set-GPRegistryValue -Name $gpo.DisplayName -Key $winrmRegKey -ValueName "IPv4Filter" -Type String -Value "*"

gpupdate /force
```

✔ Changes WinRM listener from **deny-all** (empty) to **allow-all** (`*`).

---

### Step 2: Configure Windows Event Collector (WEC)

```powershell
wecutil qc
```

When prompted:

- `This service startup mode will be changed to Delay-Start. Would you like to proceed (Y- yes or N- no)?`  
  → Enter **Y**

✔ DC10 is now configured as a **Windows Event Collector**.  
✔ Service set to **Delayed Start**.

---

# 🖥 Part 2 — Configure MS10 as the Logging Source

### Step 1: Restart MS10  
Restart MS10 to ensure it is fully registered in the domain.  
Log back in as **Structureality\jaime**.

---

### Step 2: Enable firewall rules for remote log management

Run PowerShell as **Administrator** on **MS10**:

```powershell
Set-NetFirewallRule -DisplayGroup "Remote Event Log Management" -Enabled True -Profile Domain
Set-NetFirewallRule -DisplayGroup "Remote Event Monitor" -Enabled True -Profile Domain
```

✔ Enables the correct firewall groups for Windows remote event logging.

---

### Step 3: Verify WinRM Configuration

```powershell
winrm quickconfig
```

Expected:

```text
WinRM service is already running on this machine.
WinRM is already set up for remote management on this computer.
```

If not configured, follow prompts to start and configure WinRM.

---

### Step 4: Add Collector (DC10) to Event Log Readers Group

On **MS10**:

1. Right-click **Start** → **Computer Management**  
2. Navigate: `System Tools → Local Users and Groups → Groups`  
3. Double-click **Event Log Readers**  
4. Click **Add…**  
5. Click **Object Types…** → enable **Computers** → OK  
6. In object names, enter: `DC10` → OK  
7. Confirm `structureality\DC10` is listed as a member → OK  

✔ DC10 now has permission to read event logs from MS10 remotely.

---

### Step 5: Restart MS10 Again  
Reboot MS10.  
Log in as **jaime** again and leave the system running.  

---

# 📡 Part 3 — Create Event Subscription on DC10

### Step 1: Open Event Viewer

On **DC10**:

- Open **Event Viewer**  
- In the left pane, select **Subscriptions**  
- In the right pane, click **Create Subscription…**

Fill in:

- **Subscription Name:** `Logs from MS10`  
- **Destination Log:** `Forwarded Events`  
- **Subscription Type:** **Collector initiated**

---

### Step 2: Add MS10 as a Source Computer

1. Click **Select Computers…**  
2. Click **Add Domain Computers…**  
3. Enter: `MS10` → OK  
4. Click **Test**  

Expected:  
✔ `Connectivity test succeeded`

Click **OK** to close.

---

### Step 3: Configure Event Filters

Click **Select Events…** and set:

- **Logged:** Last 24 hours  
- **Event Level:** Check all:
  - Critical  
  - Warning  
  - Verbose  
  - Error  
  - Information  
- **By log:**  
  - Select **Windows Logs** and include:
    - Application  
    - Security  
    - Setup  
    - System  
    - Forwarded Events  

Click **OK**, then **OK** again to save the subscription.

You should now see:

```text
Logs from MS10 — Active
```

---

# 🔍 Verification

### Step 1: View Forwarded Events on DC10

In **Event Viewer** on DC10:

- Navigate: `Windows Logs → Forwarded Events`

If empty:

- Wait 1–5 minutes  
- Click **Refresh**  

As events are collected from MS10, this log will populate.

---

### Step 2: Confirm Source Computer

Open any event in **Forwarded Events** and check:

- **Computer:** field  

✔ Correct value:  
`MS10.ad.structureality.com`

---

# 🧠 Centralized Logging – Key Takeaways

- **Windows Event Forwarding (WEF)** enables centralized log collection.  
- **Collector-initiated** subscriptions poll source systems for logs.  
- WinRM, firewall rules, and **Event Log Readers** group membership must be configured correctly.  
- Centralizing logs improves:
  - Detection  
  - Correlation  
  - Forensics  
  - Long-term storage and compliance  

---

# 🧪 Assisted Lab – Searching Logs with Regex  
**CompTIA CySA+ | Structureality Inc. | Log Analysis & Regex Techniques**  

---

## 📑 Overview
In this portion of the lab, you use **grep** with **Perl-compatible regular expressions (PCRE)** to:

- Search large Linux log files  
- Extract all IPv4 addresses from `/var/log/kern.log`  
- Count occurrences of specific IP addresses  
- Highlight suspicious entries  

This simulates hunting for IoCs in raw log data.

---

## 🖥 Environment (LAMP)

| Host | Role | Notes |
|------|------|-------|
| **LAMP** | Ubuntu Server | Log analysis + regex |
| **/var/log/kern.log** | Kernel log | Contains iptables-related network events |

---

# 🔧 Step 1 — Enable Network Logging on LAMP

```bash
sudo su
iptables -A INPUT -j LOG
iptables -S > /home/lamp/filter-list.txt
```

✔ Network logging is now active.  
✔ Log file: `/var/log/kern.log`

---

# 📂 Step 2 — Explore the Log Directory

```bash
cd /var/log
ls -l
less kern.log
```

Navigation controls in `less`:

- **Spacebar** → Next page  
- **b** → Previous page  
- **↑ / ↓** → Scroll line-by-line  
- **q** → Quit  

Observation: The log is long and dense; manual inspection is inefficient.

---

# 🔍 Step 3 — Basic grep and Regex

### Find single digits
```bash
grep -oP '[0-9]' kern.log
```

- `-o` → output only the match  
- `-P` → PCRE (Perl-compatible regex)  

**Quiz answer:** For lowercase English letters, the correct regex is:  
✔ `[a-z]`

---

### Find multi-digit sequences
```bash
grep -oP '[0-9]*' kern.log
```

This returns numbers of various lengths but still not full IPv4 addresses.

---

### Find numbers ending with a dot
```bash
grep -oP '[0-9]*\.' kern.log
```

Note:

- `.` in regex means “any character”  
- To match a literal dot, escape it: `\.`  

---

# 🌐 Step 4 — Extract IPv4 Addresses Using Regex

### First attempt — Any digit groups
```bash
grep -oP '\d+\.\d+\.\d+\.\d+' kern.log
```

- `\d` → any digit  
- `+` → one or more  

This pattern can still match unrealistic values like `9999.12345.1.1`.

---

### Second attempt — Octets limited to 1–3 digits
```bash
grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' kern.log
```

- `{1,3}` → match between 1 and 3 digits  

---

### Optimized pattern using repetition
```bash
grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log
```

This is concise and easier to re-use.

✔ Result: Clean list of IPv4-style addresses.

---

### Save IPv4s to a file
```bash
grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log > ipaddresses.txt
```

### View with paging
```bash
grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log | less
```

---

### Pattern Match Quiz

With the regex:  
`(\d{1,3}\.){3}\d{1,3}`

These WILL match:

- ✔ `172.16.0.1`  
- ✔ `127.0.0.1`  

These will NOT match (incorrect structure):

- ✖ `172.160.1` (only 3 octets)  
- ✖ `127.0.0.0.1` (5 octets)  
- ✖ `1273.3012.1234.122` (octets too large / 4+ digits)  
- ✖ `42.0` (2 octets)

---

# 🧮 Step 5 — Count IPv4 Occurrences

### Count total IPv4 matches
```bash
grep -oP '(\d{1,3}\.){3}\d{1,3}' kern.log | wc -l
```

- `wc -l` → Counts the number of lines (i.e., matches).

---

### Count a specific IP (example: 172.16.0.254)

```bash
grep 172.16.0.254 kern.log | wc -l
```

Returns:  
- The total number of times this IP appears in `kern.log`.

---

### View log entries for a specific IP with highlighting

```bash
grep 172.16.0.254 kern.log --color
```

- `--color` highlights matches directly in the log output.

---

# 🧠 Key Takeaways

## Centralized Logging
- WEF allows domain systems to send logs to a central collector (DC10).  
- Proper configuration requires:
  - WinRM  
  - Firewall rules  
  - Event Log Readers permissions  
  - Event Viewer subscriptions  
- Centralized logging improves detection, incident response, and compliance.

## Regex Log Searching
- `grep -oP` with regex is powerful for extracting patterns from large logs.  
- IPv4 addresses can be matched with:
  - `(\d{1,3}\.){3}\d{1,3}`  
- Counting and highlighting specific IPs helps identify:
  - Repeated connections  
  - Potential scanning  
  - Suspicious activity for deeper investigation  

Together, centralized logging and regex-driven search form a strong foundation for **practical threat hunting** and **log-based analysis**.


# 📸 Screenshot Placeholders

https://imgur.com/a/KUhDG3r 

---

