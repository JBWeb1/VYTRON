# VYTRON

A reference guide to common types of cybersecurity software and well-known tools in each category.

## Endpoint Protection (Antivirus / EDR)

Protects individual devices against malware, ransomware, and suspicious activity.

- **Microsoft Defender**: built into Windows, with enterprise EDR available
- **CrowdStrike Falcon**: cloud-based endpoint detection and response
- **SentinelOne**: AI-driven endpoint protection and automated response
- **Bitdefender**: consumer and business antivirus
- **Malwarebytes**: malware removal and real-time protection

## Firewalls and Network Security

Filters and monitors traffic that enters and leaves a network.

- **pfSense / OPNsense**: open-source firewall and router platforms
- **Palo Alto Networks**: next-generation firewalls
- **Fortinet FortiGate**: firewalls with integrated threat protection
- **Cisco Secure Firewall**: enterprise network security
- **Windows Defender Firewall**: built-in host firewall

## Password Managers

Stores and generates strong, unique credentials.

- **Bitwarden**: open-source and cross-platform
- **1Password**: personal and team vaults
- **KeePassXC**: offline, local password database
- **Dashlane**: password manager with breach monitoring

## VPN and Secure Access

Encrypts connections and secures remote access.

- **WireGuard**: modern, lightweight VPN protocol
- **OpenVPN**: widely used open-source VPN
- **Tailscale**: zero-config mesh VPN built on WireGuard
- **Mullvad / Proton VPN**: privacy-focused consumer VPNs

## SIEM and Log Monitoring

Collects and analyzes security events across systems.

- **Splunk**: log analysis and SIEM platform
- **Microsoft Sentinel**: cloud-native SIEM
- **Elastic Security**: SIEM built on the Elastic Stack
- **Wazuh**: open-source security monitoring and XDR

## Vulnerability Scanning

Finds weaknesses and missing patches before attackers do.

- **Nessus**: widely used vulnerability scanner
- **OpenVAS / Greenbone**: open-source vulnerability scanning
- **Qualys**: cloud-based vulnerability management
- **Nmap**: network discovery and port scanning

## Penetration Testing (Authorized Use Only)

Tests defenses by simulating attacks, with permission.

- **Kali Linux**: security testing distribution
- **Metasploit**: exploitation framework
- **Burp Suite**: web application security testing
- **Wireshark**: network packet analysis

## Email Security and Backup

Guards against phishing and protects data from loss or ransomware.

- **Proofpoint / Mimecast**: email filtering and phishing protection
- **Veeam**: backup and recovery
- **Acronis Cyber Protect**: backup with integrated anti-malware
- **Backblaze**: cloud backup

## Wired (LAN) Network Monitoring for Businesses

Watches traffic across the wired business network to detect hacking attempts and data theft.

### How it connects

```
Internet ── Router/Firewall ── Network Switch ── Office PCs, servers, printers
                                    │
                          (mirror port or TAP)
                                    │
                          Monitoring computer
                          (IDS / NDR software)
```

- **Mirror port (SPAN)**: a managed switch copies all traffic to one port, where the monitoring computer is plugged in
- **Network TAP**: a small hardware device placed inline on a cable that copies traffic without slowing the network

### Free / open-source tools

| Tool | What it does |
|---|---|
| **Security Onion** | All-in-one platform (Suricata, Zeek and a dashboard), the best place to start |
| **Suricata** | Detects and can block known attacks and malware traffic |
| **Zeek** | Logs every connection for investigating who talked to what |
| **Snort** | Classic intrusion detection system (IDS) |
| **Wazuh** | Monitors the computers themselves and combines their logs with network alerts |
| **ntopng** | Shows how much data each device sends and where, which helps spot data theft |

### Commercial tools

- **Darktrace**: uses AI to learn normal activity and flag unusual behavior
- **Vectra AI / ExtraHop Reveal(x) / Cisco Secure Network Analytics**: network detection and response (NDR)
- **Firewalls with IPS** (Fortinet, Palo Alto, Sophos): block attacks at the internet connection

### Stopping data theft

- **Data Loss Prevention (DLP)** tools (Microsoft Purview, Forcepoint, Endpoint Protector) block confidential files from leaving by email, USB or uploads
- Set up alerts for large uploads to unknown sites (ntopng, Zeek)
- Separate the network into zones (VLANs) so guest Wi-Fi and cameras can't reach business servers

### Simple starting plan

1. Get a managed switch or a network TAP
2. Install Security Onion on a spare PC with two network ports
3. Plug one port into the mirror port or TAP, and use the other for management
4. Review alerts weekly, or forward them to email

> Only monitor networks your business owns, and tell employees about the monitoring in your IT policy. Many places legally require this notice.

## Basic Security Checklist

1. Keep the OS and software updated
2. Use a password manager and enable multi-factor authentication
3. Run endpoint protection on every device
4. Keep a firewall enabled
5. Back up important data (3-2-1 rule: 3 copies, 2 media types, 1 offsite)
6. Learn to recognize phishing emails
