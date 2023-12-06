---
title: Bruteforce Write-up (Blue Team Labs Online)
date: 2023-12-05 13:51:00 -0500
categories: [Write-ups, Blue Team Labs Online]
tags: [incident response, bruteforce attack, rdp, event viewer, log analysis] # TAG names should always be lowercase
---

![login-bruteforce](/assets/img/bruteforce-logo.png){: width="400"}

## Overview

The following is a write-up for the [Bruteforce](https://blueteamlabs.online/home/challenge/bruteforce-16629bf9a2) challenge on [Blue Team Labs Online](https://blueteamlabs.online/). The scenario is as follows:

**_Can you analyze logs from an attempted RDP bruteforce attack?_**
**_One of our system administrators identified a large number of Audit Failure events in the Windows Security Event log._**
**_There are a number of different ways to approach the analysis of these logs! Consider the suggested tools, but there are many others out there!_**

---

## Solution

Download and extract the given zip file using the password `BTLO`. After extracting the zip file we see a log file in .txt, .csv and .evtx formats as well as a readme file.

![bruteforce-challenge-files](/assets/img/bruteforce-files.png)
_Extracted Files from the Challenge_

### Q1. How many Audit Failure events are there? (Format: Count of Events)

To find the number of Audit Failure events we can open the `BTLO_Bruteforce_Challenge.csv` file and hit `CTRL + F` to perform a search.
Enter `Audit Failure` in the search box and click _Find All_.

![audit-failure-search](/assets/img/audit-failure-search.png)
_Search results for 'Audit Failures'_

**_Answer: 3103_**

### Q2. What is the username of the local account that is being targeted? (Format: Username)

Looking through the csv file, we can see that the 'audit failure' event details show a common Account Name.

![event-account-name](/assets/img/event-account-name.png)
_Account Name for Audit Failure Events_

**_Answer: administrator_**

### Q3. What is the failure reason related to the Audit Failure Logs? (Format: String)

Once again, looking at the details for 'Audit Failure' events shows us the failure reason.

![event-failure-reason](/assets/img/event-failure-reason.png)
_'Audit Failure' event displaying reason for failure_

**_Answer: Unkown user name or bad password._**

### Q4. What is the Windows Event ID associated with these logon failures? (Format: ID)

All entries in the log file will have an 'Event ID' field. 'Audit Failure' events will have the following event id:

![audit-failure-eventid](/assets/img/audit-failure-eventid.png)
_Event ID for 'Audit Failure'_

**_Answer: 4625_**

### Q5. What is the source IP conducting this attack? (Format: X.X.X.X)

The event details contain a 'Source Network Address' field that displays the ip address of the machine initiating the RDP connection.

![event-source-ip](/assets/img/event-source-ip.png)
_Event details displaying Source Network Address_

**_Answer: 113.161.192.227_**

### Q6. What country is this IP address associated with? (Format: Country)

To find the country associated with this IP address we can utilize [VirusTotal](https://www.virustotal.com/gui/home) and search for the IP address.

> VirusTotal is an online service that analyzes suspicious files and URLs to detect types of malware and malicious content using antivirus engines and website scanners.
{: .prompt-info }

![virustotal-ip-country](/assets/img/virustotal-ip-country.png)
_VirusTotal Results_

***Answer: Vietnam***

### Q7. What is the range of source ports that were used by the attacker to make these login requests? (LowestPort-HighestPort)

The event details contain a 'Source Port' field that displays the port that the machine intiating the RDP connection used. 

![event-lower-source-port](/assets/img/event-lower-source-port.png)
![event-higher-source-port](/assets/img/event-higher-source-port.png)
_Event Details showing the lowest and highest source port_

***Answer: 49162-65534***
