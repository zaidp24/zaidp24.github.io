---
title: Junior Security Analyst Intro
date: 2023-12-11 11:21:00 -0500
categories: [Notes, SOC Level 1]
tags: [soc, responsibilties, notes] # TAG names should always be lowercase
---

## A Career as a Junior Security Analyst

Junior Security Analyst or Tier 1 SOC Analyst responsibilities:

- Monitor and investigate alerts
- Configure and manage security tools
- Develop and implement basic IDS (Intrusion Detection System) signatures
- Participate in SOC working groups and meetings
- Create tickets and escalate the security incidents to the Tier 2 and Team Lead if needed

Required qualifications:

- 0-2 years of experience with Security Operations
- Basic understanding of Networking OSI or TCP/IP model, Operating Systems, Web applications
- Scripting/programming is a plus

Desired certification:

- CompTIA Security+

![soc-tiers](/assets/img/soc-tiers.png)
_SOC Three-tier Model_

***

## Security Operations Center (SOC)

- Core function of a SOC is to investigate, monitor, prevent and respond to threats

>[McAfee's definition of a SOC](https://www.trellix.com/security-awareness/operations/what-is-soc/) is as follows: "Security operations teams are charged with monitoring and protecting many assets, such as intellectual property, personnel data, business systems, and brand integrity"

![soc-responsibilities](/assets/img/soc-responsibilities.png)
_Responsibilities of the SOC_

### Preparation and Prevention

- Stay informed of the current cyber security threats (Twitter and Feedly)
- Detect and hunt threats, work on a security roadmap, be ready for 'worst-case' scenarios
- Prevention methods include gathering intel data on latest threats, threat actors and their [TTPs (Tactics, Techniques, and Procedures)](https://www.optiv.com/explore-optiv-insights/blog/tactics-techniques-and-procedures-ttps-within-cyber-threat-intelligence)
- Maintaining firewall signatures, patching vulnerabilities in existing systems, block/white-listing applications, emails addresses and IPs

### Monitoring and Investigation

- Uses SIEM (Security information and event management) and [EDR (Endpoint Detection and Response)](https://www.trellix.com/security-awareness/endpoint/what-is-endpoint-detection-and-response/) tools to monitor suspicious activities
- Perform triaging for ongoing alerts by exploring and understanding how a certain attack works and preventing bad things from happening
- Analysts find answers by drilling down ton the data logs and alerts in combination with open-source tools

### Response

- After investigation, the SOC team coordinates and takes action on the compromised hosts
- Isolating hosts from the network, terminating malicious processes, deleting files etc.
