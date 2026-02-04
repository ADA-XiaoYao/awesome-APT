# Awesome APT[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of Advanced Persistent Threat (APT) frameworks, tools, resources, software, and tutorials. This list aims to help security researchers, threat hunters, and defenders find everything related to APT attacks and defense in one place.

## Contributing

Please take a quick look at the [contribution guidelines](https://github.com/ADA-XiaoYao/awesome-APTCONTRIBUTING.md) first.  

If you know a tool that isn't present here, feel free to open a pull request.

## Why?

It takes time to build up a collection of tools used in APT research and remember them all. This repo helps to keep all these scattered tools in one place.

## Contents

- **Awesome APT**
  - Attack Simulation
    - Initial Access
    - Persistence
    - Lateral Movement
    - Command & Control
    - Data Exfiltration
  - Defense & Detection
    - Threat Hunting
    - Behavioral Analysis
    - Network Analysis
    - Memory Forensics
    - Malware Analysis
    - Endpoint Detection & Response
    - Threat Intelligence Platforms
- Resources
  - Operating Systems
  - Starter Packs
  - Tutorials & Courses
  - Lab Environments
  - Websites & Blogs
  - Wikis & Knowledge Bases
  - Analysis Reports

---

## Attack Simulation

Tools and frameworks for simulating APT attack chains

- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) - Web-based tool for navigating and planning with the ATT&CK matrix.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Library of tests mapped to ATT&CK techniques.
- [Caldera](https://github.com/mitre/caldera) - Automated adversary emulation platform by MITRE.
- [Cobalt Strike](https://www.cobaltstrike.com/) - Commercial red team and APT simulation platform.
- [Empire](https://github.com/BC-SECURITY/Empire) - Post-exploitation framework with PowerShell, Python, and C# agents.
- [Metasploit Framework](https://www.metasploit.com/) - Penetration testing and exploit development framework.
- [Sliver](https://github.com/BishopFox/sliver) - Cross-platform red team framework.

### Initial Access

- [Gophish](https://getgophish.com/) - Open-source phishing toolkit.
- [King Phisher](https://github.com/securestate/king-phisher) - Phishing campaign toolkit.
- [Social-Engineer Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) - Social engineering attack tools.
- [ReelPhish](https://github.com/ryhanson/ReelPhish) - Real-time two-factor phishing tool.
- [GoFetch](https://github.com/ActiveDirectoryAttackToolbox/GoFetch) - Automates attack techniques in Active Directory.

### Persistence

- [Impacket](https://github.com/SecureAuthCorp/impacket) - Python classes for network protocols, credential theft, persistence.
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - PowerShell post-exploitation modules.
- [SharPersist](https://github.com/SharPersist/SharPersist) - Windows persistence toolkit (C#).
- [WMI Backdoor](https://github.com/joelittlejohn/wmi-exec) - WMI-based persistence backdoor.
- [PoshC2](https://github.com/nettitude/PoshC2) - PowerShell and Python C2 framework with persistence.

### Lateral Movement

- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - Swiss army knife for Windows environments.
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Active Directory relationship analysis and attack path discovery.
- [Mimikatz](https://github.com/gentilkiwi/mimikatz) - Extract credentials and keys from Windows systems.
- [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec) - Execute processes on remote systems.
- [Lateral Movement Toolkit (LMT)](https://github.com/ActiveDirectoryAttackToolbox/LateralMovementToolkit) - Collection of tools for lateral movement.

### Command & Control

- [Covenant](https://github.com/cobbr/Covenant) - .NET-based C2 framework.
- [DeimosC2](https://github.com/ThakeeNathees/deimosC2) - Modular cross-platform C2 framework.
- [Merlin](https://github.com/Ne0nd0g/merlin) - Cross-platform HTTP/2 C2.
- [PoshC2](https://github.com/nettitude/PoshC2) - PowerShell and Python-based C2 framework.
- [Havoc](https://github.com/LOKI-Attack/Havoc) - Modern malleable post-exploitation framework.

### Data Exfiltration

- [DNSExfiltrator](https://github.com/sensepost/dnsexfiltrator) - Exfiltrate data over DNS.
- [Cloakify](https://github.com/feross/Cloakify) - Transform data into innocuous text.
- [Egress-Assess](https://github.com/ActiveDirectoryAttackToolbox/Egress-Assess) - Test egress data paths.
- [DET](https://github.com/DetectionLab/DET) - Data Exfiltration Toolkit.
- [TrevorC2](https://github.com/mandiant/TrevorC2) - Legitimate website-based C2 for bypassing restrictions.

---

## Defense & Detection

### Threat Hunting

- [MISP](https://www.misp-project.org/) - Threat intelligence sharing platform.
- [OpenCTI](https://www.opencti.io/) - Open-source threat intelligence platform.
- [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook) - Threat hunting playbooks and detection rules.
- [YARA](https://virustotal.github.io/yara/) - Pattern matching tool for identifying malware.
- [Sigma](https://github.com/SigmaHQ/sigma) - Generic signature format for SIEM systems.
- [Cortex](https://www.cortex-ml.org/) - Observable analysis and active response engine.

### Behavioral Analysis

- [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System activity monitoring for Windows.
- [Osquery](https://osquery.io/) - SQL-powered OS instrumentation and analytics.
- [GRR Rapid Response](https://github.com/google/grr) - Remote live forensics.
- [Velociraptor](https://velociraptor.app/) - Advanced digital forensics & incident response.
- [Elastic Endpoint Security](https://www.elastic.co/endpoint-security) - Endpoint prevention, detection, and response.

### Network Analysis

- [Zeek](https://zeek.org/) - Network security monitor.
- [Suricata](https://suricata-ids.org/) - Network IDS/IPS/NSM engine.
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer.
- [Moloch](https://molo.ch/) - Large-scale packet capture & indexing.
- [Snort](https://www.snort.org/) - Open-source network intrusion detection.

### Memory Forensics

- [Volatility](https://www.volatilityfoundation.org/) - Memory forensics framework.
- [Rekall](http://www.rekall-forensic.com/) - Memory forensic framework.
- [WinPmem](https://github.com/Velocidex/WinPmem) - Windows memory acquisition.
- [LiME](https://github.com/504ensicsLabs/LiME) - Linux memory extractor.
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Memory analysis for threat hunting.

### Malware Analysis

- [Ghidra](https://ghidra-sre.org/) - Software reverse engineering suite.
- [IDA Pro](https://www.hex-rays.com/products/ida/) - Interactive disassembler & debugger.
- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Automated malware analysis.
- [CAPE Sandbox](https://github.com/ctxis/CAPE) - Malware configuration & payload extraction.
- [PE-sieve](https://github.com/hasherezade/pe-sieve) - Scans running processes for malware traces.
- [Malwarebytes](https://www.malwarebytes.com/) - Endpoint anti-malware software.

### Endpoint Detection & Response

- [Wazuh](https://wazuh.com/) - Open-source security monitoring.
- [Elastic Security](https://www.elastic.co/security) - Open-source SIEM & endpoint security.
- [OSSEC](https://www.ossec.net/) - Host-based intrusion detection system.
- [CrowdStrike Falcon](https://www.crowdstrike.com/) - Cloud-native endpoint protection.
- [Microsoft Defender for Endpoint](https://www.microsoft.com/en-us/security/business/threat-protection/microsoft-defender-endpoint) - Enterprise endpoint security.

### Threat Intelligence Platforms

- [MISP](https://www.misp-project.org/) - Open-source threat intelligence platform.
- [OpenCTI](https://www.opencti.io/) - Open-source platform for threat intelligence.
- [ThreatConnect](https://threatconnect.com/) - Threat intelligence platform.
- [Anomali](https://www.anomali.com/) - Threat intelligence & security operations platform.
- [Recorded Future](https://www.recordedfuture.com/) - Threat intelligence platform.

---

## Resources

### Operating Systems

- [Kali Linux](https://www.kali.org/) - Penetration testing and security research.
- [Parrot Security OS](https://www.parrotsec.org/) - Security Linux distro.
- [REMnux](https://remnux.org/) - Linux toolkit for reverse-engineering malware.
- [Flare VM](https://www.fireeye.com/services/freeware/flare-vm.html) - Windows malware analysis environment.
- [SIFT Workstation](https://digital-forensics.sans.org/community/downloads) - Forensics & incident response.

### Starter Packs

- [APT Simulator](https://github.com/your-repo/APT-Simulator) - Windows batch scripts to simulate APT activities.
- [Red Team Automation (RTA)](https://github.com/mandiant/RTA) - Scripts to detect malicious actions.
- [PurpleSharp](https://github.com/microsoft/purplesharp) - C# adversary simulation tool.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Portable tests for security controls.

### Tutorials & Courses

- [MITRE ATT&CK Training](https://attack.mitre.org/resources/training/) - Official ATT&CK training.
- [Cybrary APT Courses](https://www.cybrary.it) - APT courses and training.
- [SANS SEC565](https://www.sans.org/cyber-security-courses/red-team-exercises-adversary-emulation/) - Red Team exercises.
- [Pluralsight](https://www.pluralsight.com/) - APT learning paths.
- [Coursera](https://www.coursera.org/) - APT courses from universities.

### Lab Environments

- [Detection Lab](https://github.com/clong/DetectionLab) - Vagrant & Packer scripts for security lab.
- [Threat Hunter Playbook Labs](https://github.com/OTRF/ThreatHunter-Playbook) - Threat hunting labs.
- [AD Security Lab](https://github.com/ADSecurityLab/AD-Security-Lab) - Active Directory security lab.
- [Modern Windows Attacks Lab](https://github.com/RedTeamTools/ModernWindowsLab) - Windows attack & defense lab.
- [Red Team Toolkit Lab](https://github.com/RedTeamTools/RedTeamLab) - Red team lab setup.

### Websites & Blogs

- [MITRE ATT&CK](https://attack.mitre.org/) - Knowledge base of adversary tactics.
- [FireEye Threat Research](https://www.fireeye.com/blog/threat-research.html) - APT research and reports.
- [CrowdStrike Threat Intelligence](https://www.crowdstrike.com/resources/) - Threat intelligence.
- [Kaspersky Threat Intelligence](https://ics.kaspersky.com/) - APT reports & research.
- [Mandiant Threat Intelligence](https://www.mandiant.com/resources) - APT insights & reports.

### Wikis & Knowledge Bases

- [APT Notes](https://github.com/ytisf/AptNotes) - Public APT reports collection.
- [APT Groups and Operations](https://github.com/ytisf/AptGroups) - Spreadsheet tracking APT groups.
- [Threat Actor Encyclopedia](https://threat-actors.github.io/) - Database of threat actors.
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/) - Rapid malware identification.
- [VirusTotal Intelligence](https://www.virustotal.com/) - Malware intelligence and hunting.

### Analysis Reports

- [APT Reports Archive](https://www.fireeye.com/enterprise/threat-research.html) - Collection of APT reports.
- [Threat Miner](https://www.threatminer.org/) - Threat intelligence portal.
- [AlienVault OTX](https://otx.alienvault.com/) - Open threat intelligence community.
- [ThreatConnect Report Library](https://threatconnect.com/) - APT analysis & reports.
- [Recorded Future Insights](https://www.recordedfuture.com/) - Threat intelligence insights.

## LICENSE

CC0
