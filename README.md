# Awesome APT[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of Advanced Persistent Threat (APT) frameworks, tools, resources, software, and tutorials. This list aims to help security researchers, threat hunters, and defenders find everything related to APT attacks and defense in one place.

## Contributing

Please take a quick look at the [contribution](https://github.com/ADA-XiaoYao/awesome-APT/blob/main/CONTRIBUTING.md) first.
If you know a tool that isn't present here, feel free to open a pull request.

## Why?

It takes time to build up a collection of tools used in APT research and remember them all. This repo helps to keep all these scattered tools in one place.
## Contents

- **[Awesome APT](#awesome-apt)**
  - [Attack Simulation](#attack-simulation)
    - [Initial Access](#initial-access)
    - [Persistence](#persistence)
    - [Lateral Movement](#lateral-movement)
    - [Command & Control](#command--control)
    - [Data Exfiltration](#data-exfiltration)
  - [Defense & Detection](#defense--detection)
    - [Threat Hunting](#threat-hunting)
    - [Behavioral Analysis](#behavioral-analysis)
    - [Network Analysis](#network-analysis)
    - [Memory Forensics](#memory-forensics)
    - [Malware Analysis](#malware-analysis)
    - [Endpoint Detection & Response](#endpoint-detection--response)
    - [Threat Intelligence Platforms](#threat-intelligence-platforms)
- [Resources](#resources)
  - [Operating Systems](#operating-systems)
  - [Starter Packs](#starter-packs)
  - [Tutorials & Courses](#tutorials--courses)
  - [Lab Environments](#lab-environments)
  - [Websites & Blogs](#websites--blogs)
  - [Wikis & Knowledge Bases](#wikis--knowledge-bases)
  - [Analysis Reports](#analysis-reports)
---

## Attack Simulation

### Frameworks & Platforms

- [MITRE ATT&CK Navigator](https://attack.mitre.org/resources/attack-navigator/) – Visualize and plan ATT&CK matrices.
- [CALDERA](https://github.com/mitre/caldera) – Automated adversary emulation system by MITRE.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) – ATT&CK-based test cases.
- [Cobalt Strike](https://www.cobaltstrike.com/) – Commercial adversary emulation platform.
- [Sliver](https://github.com/BishopFox/sliver) – Open-source red team C2 and implants.
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) – Exploit and post-exploitation framework.
- [Red Team Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit) – Collection of red team tools.
- [Red Hunt Labs APT Simulator](https://github.com/redhuntlabs/APTSimulator) – Windows APT activity simulator.
- [AttackIQ](https://www.attackiq.com/) – Commercial adversary emulation platform.
- [SafeBreach](https://www.safebreach.com/) – Continuous breach validation platform.
- [Picus Security](https://www.picussecurity.com/) – Threat-based security validation.
- [ThreatQ](https://www.threatq.com/) – Threat intelligence integrated simulation platform.

---

### Initial Access

- [Gophish](https://github.com/gophish/gophish) – Open-source phishing toolkit.
- [King Phisher](https://github.com/securestate/king-phisher) – Phishing campaign tool.
- [Social-Engineer Toolkit](https://github.com/trustedsec/social-engineer-toolkit) – Social engineering attack framework.
- [ReelPhish](https://github.com/fireeye/ReelPhish) – Real-time two-factor phishing tool.
- [Evilginx2](https://github.com/kgretzky/evilginx2) – Reverse proxy phishing framework.
- [MailSniper](https://github.com/dafthack/MailSniper) – Email reconnaissance and phishing tool.
- [Phishery](https://github.com/ryhanson/phishery) – Simple phishing credential harvester.
- [Modlishka](https://github.com/drk1wi/Modlishka) – Advanced reverse proxy phishing tool.

---

### Persistence

- [Impacket](https://github.com/fortra/impacket) – Network protocol toolkit often used for credential access and persistence.
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) – PowerShell post-exploitation modules.
- [SharPersist](https://github.com/mandiant/SharPersist) – Windows persistence toolkit.
- [WMIExec](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py) – WMI-based execution and persistence.
- [DLL Hijacking](https://attack.mitre.org/techniques/T1574/) – DLL search order hijacking reference.
- [Startup Folder Persistence](https://attack.mitre.org/techniques/T1547/001/) – Startup folder persistence technique.
- [Scheduled Tasks](https://attack.mitre.org/techniques/T1053/) – Scheduled task persistence reference.
- [Service Registry Persistence](https://attack.mitre.org/techniques/T1543/) – Windows service persistence.

---

### Lateral Movement

- [CrackMapExec](https://github.com/Porchetta-Industries/CrackMapExec) – Swiss army knife for Windows network environments.
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) – Active Directory relationship and attack path analysis.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) – Credential extraction and privilege escalation tool.
- [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) – Execute processes on remote Windows systems.
- [Impacket SMBExec](https://github.com/fortra/impacket) – Remote command execution over SMB.
- [Responder](https://github.com/lgandx/Responder) – LLMNR/NBT-NS poisoning and credential capture.
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) – Active Directory reconnaissance framework.
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) – Data collector for BloodHound.
- [Rubeus](https://github.com/GhostPack/Rubeus) – Kerberos abuse and ticket manipulation.
- [Kerbrute](https://github.com/ropnop/kerbrute) – Kerberos brute force and enumeration tool.

---

### Command & Control

- [Covenant](https://github.com/cobbr/Covenant) – .NET based C2 framework.
- [Havoc](https://github.com/HavocFramework/Havoc) – Modern and modular post-exploitation framework.
- [Merlin](https://github.com/Ne0nd0g/merlin) – HTTP/2 based cross-platform C2.
- [PoshC2](https://github.com/nettitude/PoshC2) – PowerShell and Python command and control framework.
- [Mythic](https://github.com/its-a-feature/Mythic) – Collaborative red teaming platform.
- [DeimosC2](https://github.com/DeimosC2/DeimosC2) – Modular cross-platform C2.
- [TrevorC2](https://github.com/trustedsec/trevorc2) – Legitimate website based C2 channel.
- [QuasarRAT](https://github.com/quasar/Quasar) – Remote administration and C2 tool.
- [AsyncRAT](https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp) – Open-source remote access tool.
- [Sliver](https://github.com/BishopFox/sliver) – Cross-platform implant and C2 framework.

---

### Data Exfiltration

- [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) – Data exfiltration over DNS queries.
- [DET](https://github.com/sensepost/DET) – Data exfiltration toolkit.
- [Cloakify](https://github.com/TryCatchHCF/Cloakify) – Transform data into harmless looking text.
- [Egress-Assess](https://github.com/FortyNorthSecurity/Egress-Assess) – Test outbound data paths.
- [Iodine](https://github.com/yarrick/iodine) – IP over DNS tunneling.
- [DNScat2](https://github.com/iagox86/dnscat2) – Encrypted DNS command and control tunnel.
- [Ptunnel](https://github.com/utoni/ptunnel-ng) – ICMP tunneling tool.
- [Rclone](https://github.com/rclone/rclone) – Cloud storage synchronization and transfer.
- [Exfil](https://github.com/moloch--/exfil) – File exfiltration over multiple channels.
- [Dropzone](https://github.com/Arno0x/Dropzone) – Covert file transfer utility.

---

## Defense & Detection

### Threat Hunting

- [MISP](https://github.com/MISP/MISP) – Open threat intelligence sharing platform.
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) – Cyber threat intelligence management.
- [YARA](https://github.com/VirusTotal/yara) – Pattern matching for malware detection.
- [Sigma](https://github.com/SigmaHQ/sigma) – Generic signature format for SIEM systems.
- [Cortex](https://github.com/TheHive-Project/Cortex) – Observable analysis and response engine.
- [TheHive](https://github.com/TheHive-Project/TheHive) – Security incident response platform.
- [ThreatHunter Playbook](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook) – Threat hunting methodology and analytics.
- [Maltego CE](https://www.maltego.com/) – Link analysis and OSINT platform.
- [Security Onion](https://github.com/Security-Onion-Solutions/securityonion) – Threat hunting and network monitoring distro.
- [GRR Rapid Response](https://github.com/google/grr) – Remote live forensics framework.

---

### Behavioral Analysis

- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) – System activity monitoring for Windows.
- [Osquery](https://github.com/osquery/osquery) – SQL-powered operating system instrumentation.
- [Velociraptor](https://github.com/Velocidex/velociraptor) – Advanced digital forensics and incident response.
- [GRR Rapid Response](https://github.com/google/grr) – Remote live forensics platform.
- [Elastic Endpoint](https://www.elastic.co/security/endpoint-security) – Endpoint detection and prevention.
- [Wazuh](https://github.com/wazuh/wazuh) – Open-source security monitoring and EDR.
- [OSSEC](https://github.com/ossec/ossec-hids) – Host-based intrusion detection system.
- [Falco](https://github.com/falcosecurity/falco) – Runtime security for containers and cloud.
- [Sysdig Secure](https://sysdig.com/) – Container runtime security monitoring.
- [Redline](https://fireeye.market/apps/211364) – Endpoint memory and behavioral analysis tool.

---

### Network Analysis

- [Zeek](https://github.com/zeek/zeek) – Network security monitoring platform.
- [Suricata](https://github.com/OISF/suricata) – High-performance IDS/IPS engine.
- [Wireshark](https://github.com/wireshark/wireshark) – Network protocol analyzer.
- [Snort](https://github.com/snort3/snort3) – Open-source intrusion detection system.
- [Arkime](https://github.com/arkime/arkime) – Large-scale packet capture and search.
- [ntopng](https://github.com/ntop/ntopng) – Network traffic analysis and monitoring.
- [NetworkMiner](https://www.netresec.com/?page=NetworkMiner) – Network forensic analysis tool.
- [Brim](https://github.com/brimdata/brim) – Desktop network traffic analysis.
- [tcpdump](https://www.tcpdump.org/) – Command-line packet analyzer.
- [Corelight](https://corelight.com/) – Enterprise Zeek-based network detection.

---

### Memory Forensics

- [Volatility](https://github.com/volatilityfoundation/volatility) – Advanced memory forensics framework.
- [Volatility3](https://github.com/volatilityfoundation/volatility3) – Modern memory analysis platform.
- [Rekall](https://github.com/google/rekall) – Memory forensic framework.
- [WinPmem](https://github.com/Velocidex/WinPmem) – Windows memory acquisition.
- [LiME](https://github.com/504ensicsLabs/LiME) – Linux memory extractor.
- [Redline](https://fireeye.market/apps/211364) – Memory analysis and threat detection.
- [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) – Malware memory analysis.
- [DumpIt](https://www.comae.com/dumpit/) – Memory acquisition utility.
- [Belkasoft RAM Capturer](https://belkasoft.com/ram-capturer) – Live RAM capture tool.
- [Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/) – Free memory capture utility.

---

### Malware Analysis

- [Ghidra](https://github.com/NationalSecurityAgency/ghidra) – Software reverse engineering suite.
- [IDA Free](https://hex-rays.com/ida-free/) – Interactive disassembler and debugger.
- [Cutter](https://github.com/rizinorg/cutter) – GUI reverse engineering platform.
- [Radare2](https://github.com/radareorg/radare2) – Reverse engineering framework.
- [Cuckoo Sandbox](https://github.com/cuckoosandbox/cuckoo) – Automated malware analysis.
- [CAPE Sandbox](https://github.com/kevoreilly/CAPEv2) – Malware configuration extraction.
- [Any.Run](https://any.run/) – Interactive online malware sandbox.
- [Hybrid Analysis](https://www.hybrid-analysis.com/) – Online malware analysis platform.
- [PE-sieve](https://github.com/hasherezade/pe-sieve) – Detect injected malware in processes.
- [x64dbg](https://github.com/x64dbg/x64dbg) – Open-source Windows debugger.

---

### Endpoint Detection & Response

- [Wazuh](https://github.com/wazuh/wazuh) – Open-source SIEM and EDR platform.
- [Elastic Security](https://github.com/elastic/security) – Open-source endpoint and SIEM.
- [OSQuery Fleet](https://github.com/fleetdm/fleet) – Device fleet monitoring and endpoint visibility.
- [CrowdStrike Falcon](https://www.crowdstrike.com/) – Cloud-native endpoint protection.
- [Microsoft Defender for Endpoint](https://www.microsoft.com/security/business/endpoint-security) – Enterprise endpoint security.
- [SentinelOne](https://www.sentinelone.com/) – Autonomous AI endpoint protection.
- [Sophos Intercept X](https://www.sophos.com/) – Advanced endpoint defense.
- [Bitdefender GravityZone](https://www.bitdefender.com/) – Endpoint protection platform.
- [Trend Micro Apex One](https://www.trendmicro.com/) – Endpoint detection and response.
- [Kaspersky Endpoint Security](https://www.kaspersky.com/) – Enterprise endpoint protection.

---

### Threat Intelligence Platforms

- [MISP](https://github.com/MISP/MISP) – Open threat intelligence sharing platform.
- [OpenCTI](https://github.com/OpenCTI-Platform/opencti) – Cyber threat intelligence management.
- [ThreatConnect](https://threatconnect.com/) – Threat intelligence operations platform.
- [Anomali](https://www.anomali.com/) – Threat intelligence and analytics.
- [Recorded Future](https://www.recordedfuture.com/) – Real-time threat intelligence.
- [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/) – Threat intelligence sharing.
- [AlienVault OTX](https://otx.alienvault.com/) – Open threat intelligence community.
- [VirusTotal Intelligence](https://www.virustotal.com/) – Malware intelligence and analysis.
- [GreyNoise](https://www.greynoise.io/) – Internet background noise intelligence.
- [MalwareBazaar](https://bazaar.abuse.ch/) – Malware sample sharing platform.

---

## Resources

### Operating Systems

- [Kali Linux](https://www.kali.org/) – Penetration testing and security auditing distribution.
- [Parrot Security OS](https://parrotsec.org/) – Security-focused GNU/Linux distribution.
- [BlackArch](https://blackarch.org/) – Arch Linux based penetration testing distro.
- [REMnux](https://remnux.org/) – Linux toolkit for reverse engineering and malware analysis.
- [Flare VM](https://github.com/mandiant/flare-vm) – Windows malware analysis environment.
- [SIFT Workstation](https://www.sans.org/tools/sift-workstation/) – Digital forensics and incident response distro.
- [Tsurugi Linux](https://tsurugi-linux.org/) – DFIR and OSINT focused Linux distribution.
- [CAINE](https://www.caine-live.net/) – Computer Aided Investigative Environment.
- [BackBox](https://www.backbox.org/) – Ubuntu-based security distribution.
- [Security Onion](https://securityonionsolutions.com/) – Network security monitoring OS.

---

### Starter Packs

- [APT Simulator](https://github.com/NextronSystems/APTSimulator) – Windows batch script simulating APT activities.
- [Red Team Automation](https://github.com/endgameinc/RTA) – Scripts to simulate attacker techniques.
- [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) – C# adversary simulation tool.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) – Portable atomic security tests.
- [Invoke-AtomicRedTeam](https://github.com/redcanaryco/invoke-atomicredteam) – PowerShell runner for Atomic tests.
- [DetectionLab](https://github.com/clong/DetectionLab) – Prebuilt blue team lab environment.
- [Threat Hunter Playbook Labs](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook) – Hunting lab scenarios.
- [Security Blue Team Toolkit](https://github.com/securityblueprint/tools) – Defensive security tool collection.
- [Red Team Field Manual](https://github.com/infosecn1nja/Red-Teaming-Toolkit) – Red team reference toolkit.
- [Blue Team Handbook Tools](https://github.com/0x4D31/awesome-threat-detection) – Blue team tool references.

---

### Tutorials & Courses

- [MITRE ATT&CK Training](https://attack.mitre.org/resources/training/) – Official ATT&CK learning resources.
- [Cybrary](https://www.cybrary.it/) – Security training platform.
- [SANS SEC565](https://www.sans.org/cyber-security-courses/red-team-exercises-adversary-emulation/) – Red team adversary emulation course.
- [SANS SEC504](https://www.sans.org/cyber-security-courses/hacker-techniques-incident-handling/) – Incident handling course.
- [Coursera Cybersecurity](https://www.coursera.org/browse/information-technology/cybersecurity) – University security courses.
- [edX Cybersecurity](https://www.edx.org/learn/cybersecurity) – Academic cybersecurity programs.
- [OpenSecurityTraining](https://opensecuritytraining.info/) – Free low-level security training.
- [PentesterLab](https://pentesterlab.com/) – Hands-on penetration testing labs.
- [Hack The Box Academy](https://academy.hackthebox.com/) – Structured security training.
- [TryHackMe](https://tryhackme.com/) – Beginner-friendly security learning platform.

---

### Lab Environments

- [DetectionLab](https://github.com/clong/DetectionLab) – Vagrant based security lab.
- [Security Onion Lab](https://securityonionsolutions.com/) – Blue team monitoring lab.
- [AD Security Lab](https://github.com/Orange-Cyberdefense/GOAD) – Active Directory attack/defense lab.
- [Modern Windows Attacks Lab](https://github.com/chvancooten/maldev-for-dummies) – Windows attack scenarios.
- [Purple Team Lab](https://github.com/WaterExecution/vulnerable-AD) – Attack and detection lab.
- [Malware Traffic Analysis Lab](https://www.malware-traffic-analysis.net/) – Packet analysis exercises.
- [Red Team Toolkit Lab](https://github.com/infosecn1nja/Red-Teaming-Toolkit) – Offensive lab tools.
- [Blue Team Labs Online](https://blueteamlabs.online/) – DFIR and detection practice.
- [RangeForce Community Edition](https://www.rangeforce.com/) – Security training simulator.
- [CyberDefenders](https://cyberdefenders.org/) – Blue team challenge labs.

---

### Websites & Blogs

- [MITRE ATT&CK](https://attack.mitre.org/) – Adversary tactics and techniques knowledge base.
- [Mandiant Threat Intelligence](https://www.mandiant.com/resources) – APT reports and research.
- [CrowdStrike Blog](https://www.crowdstrike.com/blog/) – Threat intelligence articles.
- [Kaspersky Securelist](https://securelist.com/) – Malware and APT analysis.
- [The DFIR Report](https://thedfirreport.com/) – Incident response case studies.
- [Red Canary Blog](https://redcanary.com/blog/) – Threat detection research.
- [FireEye Blog](https://www.fireeye.com/blog.html) – Advanced threat research.
- [Unit 42](https://unit42.paloaltonetworks.com/) – Palo Alto threat intelligence.
- [Talos Intelligence](https://blog.talosintelligence.com/) – Cisco threat research.
- [BleepingComputer](https://www.bleepingcomputer.com/) – Security news and incident coverage.

---

### Wikis & Knowledge Bases

- [APT Notes](https://github.com/aptnotes/data) – Collection of public APT reports.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) – Malware encyclopedia.
- [Threat Actor Encyclopedia](https://attack.mitre.org/groups/) – Adversary group database.
- [VirusTotal](https://www.virustotal.com/) – Malware scanning and intelligence.
- [Hybrid Analysis](https://www.hybrid-analysis.com/) – Malware behavior database.
- [Exploit Database](https://www.exploit-db.com/) – Public exploit archive.
- [CVE Details](https://www.cvedetails.com/) – Vulnerability database.
- [NVD](https://nvd.nist.gov/) – National vulnerability database.
- [OWASP](https://owasp.org/) – Web security knowledge base.
- [Security Wiki](https://www.securitywiki.org/) – General security knowledge.

---

### Analysis Reports

- [APT Reports Archive](https://github.com/aptnotes/data) – Aggregated APT reports.
- [ThreatMiner](https://www.threatminer.org/) – Threat intelligence search engine.
- [AlienVault OTX](https://otx.alienvault.com/) – Open threat intelligence community.
- [Recorded Future Insights](https://www.recordedfuture.com/research/) – Threat intelligence reports.
- [IBM X-Force Reports](https://www.ibm.com/security/xforce) – Security intelligence index.
- [Google Threat Analysis Group](https://blog.google/threat-analysis-group/) – State-sponsored threat research.
- [Microsoft Security Blog](https://www.microsoft.com/security/blog/) – Incident and threat research.
- [Secureworks CTU](https://www.secureworks.com/research) – Counter threat research.
- [ESET Research](https://www.welivesecurity.com/) – Malware and APT studies.
- [Check Point Research](https://research.checkpoint.com/) – Threat intelligence publications.

## LICENSE

CC0
