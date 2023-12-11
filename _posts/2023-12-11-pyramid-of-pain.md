---
title: Pyramid of Pain
date: 2023-12-11 11:21:00 -0500
categories: [Notes, SOC Level 1]
tags: [pyramid of pain, defense frameworks, notes] # TAG names should always be lowercase
---

The [Pyramid of Pain](https://www.eccouncil.org/cybersecurity-exchange/threat-intelligence/pyramid-pain-threat-detection/) is a conceptual model for understanding cybersecurity threats that organizes IOCs into six different levels. It is used to improve the effectiveness of CTI (Cyber Threat Intelligence), threat hunting and incident response exercises.

## Hash Values (Trivial)

- A hash value is a numeric value of a fixed length that uniquely identifies data
- Examples include MD5, SHA-1, SHA-2
- Security professionals use hash values to gain insight into a specific malware sample, malicious/suspicious file and to uniquely identify and reference the malicious artifact
- Online tools like [VirusTotal](https://www.virustotal.com/) and [Metadefender Cloud - OPSWAT](https://metadefender.opswat.com/) can be used to perform hash lookups 

![pop-virustotal](/assets/img/pop-virustotal.png)
_Example VirusTotal Results_


![pop-opswat](/assets/img/pop-opswat.png)
_MetaDefender Cloud - OPSWAT_

It is really easy to spot a malicious file if we have the hash, however, as an attacker, modifying the file by even a single bit is trivial, which would produce an entirely different hash value. Therefore using file hashes as the IOC (indicators of compromise can become difficult.)

## IP Address (Easy)

- An IP address is used to identify any device connected to a network
- knowledge of the IP address an adversary uses can be valuable as we can block, drop or deny inbound requests from IP addresses on a firewall
- One way an adversary can make it challenging to successfully carry out IP blocking is by using **Fast Flux**
- The concept of Fast Flux is to have multiple IP addresses associated with a domain name, which is constantly changing

> Fast Flux is a DNS technique used by botnets to hide phishing, web proxying malware delivery and malware communication activities behind compromised hosts acting as proxies. The purpose is to make the communication between malware and its C2 server hard to discover.

## Domain Names (Simple)

- Domain names can be thought as simply mapping an IP address to a string of text
- Domain names can contain a domain and a top-level domain (evilcorp.com) or a sub-domain followed by a domain and a top-level domain(tryhackme.evilcorp.com)
- Domain names are a little more pain for attackers to change as they would likely need to purchase the domain, register it and modify DNS records


![pop-punycode](/assets/img/pop-punycode.png)
_Example Punycode Attack_

This is an example of a Punycode attack where the attacker converts words that cannot be written in ASCII, into a Unicode ASCII encoding.

Attackers usually hide malicious domains under **URL Shorteners**. Here are some examples of URL shortening services used by attackers:

- bit.ly
- goo.gl
- ow.ly
- s.id
- smarturl.it
- tiny.pl
- tinyurl.com
- x.co

you can see the actual website of the shortened link by appending "+" to the end of the link

### Viewing Connections in Any.run

Any.run is a sandboxing service that executes malware samples and allows us to review any connections such as HTTP requests, DNS requests or processes communicating with an IP address.

![pop-http-request](/assets/img/pop-http-requests.png)
_AnyRun Results Showing HTTP Requests_

![pop-connections](/assets/img/pop-connections.png)
_AnyRun Results Showing Connections_

![pop-dns-requests](/assets/img/pop-dns-requests.png)
_AnyRun Results Showing DNS Requests_

## Host Artifacts (Annoying)

Host artifacts are the traces or observables that attackers leave on the system and include:

- Registry values
- Suspicious process execution
- Attack patterns or IOCs
- Files dropped by malicious apps
- Anything exclusive to the current threat

![pop-suspicious-process](/assets/img/pop-suspicious-process.png)
_Suspicious process execution from Word_

![pop-suspicious-events](/assets/img/pop-suspicious-events.png)
_Suspicious events followed by opening a malicious application_

![pop-suspicious-modified-files](/assets/img/pop-modified-files.png)
_Files modified/dropped by a malicious actor_

## Network Artifacts (Annoying)

A network artifact can be a user-agent string, C2 information or URI patterns followed by the HTTP POST requests.

Network artifacts can be detected in Wireshark PCAPs by using a network protocol analyzer such as [TShark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html) or an IDS such as [Snort](https://www.snort.org/).

![pop-suspicious-strings](/assets/img/pop-suspicious-strings.png)
_HTTP requests containing suspicious strings_

## Tools (Challenging)

- At this stage the attacker would most likely give up trying to break into your network. 
- Antivirus signatures, detection rules and YARA rules can be great defense weapons to use against attackers.
- [MalwareBazaar](https://bazaar.abuse.ch/) and [Malshare](https://malshare.com/) are good resources with access to samples, malicious feeds and YARA results.
- [SOC Prime Threat Detection Marketplace](https://tdm.socprime.com/) is a great platform, where security professionals share their detection rules.
- Fuzzy hashing helps you to perform similarity analysis - match two files with minor differences based on the fuzzy hash values. [SSDeep](https://ssdeep-project.github.io/ssdeep/index.html)

## TTPs (Tough)

TTPs stands for Tactics, Techniques & Procedures, This includes the whole [MITRE ATT&CK Matrix](https://attack.mitre.org/).
If you can detect and respond to the TTPs quickly, you leave the adversaries almost no chance to fight back. For, example if you could detect a [Pass-the-Hash](https://www.beyondtrust.com/resources/glossary/pass-the-hash-pth-attack) attack and remediate it, you would be able to find the compromised host very quickly and stop the lateral movement inside your network.