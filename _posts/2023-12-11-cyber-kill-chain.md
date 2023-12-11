---
title: Cyber Kill Chain
date: 2023-12-11 11:21:00 -0500
categories: [Notes, SOC Level 1]
tags: [cyber kill chain, defense frameworks, notes] # TAG names should always be lowercase
---

## Introduction

![cyber-kill-chain](/assets/img/cyber-kill-chain.png)
_Cyber Kill Chain Phases_

The term **kill chain** is a military concept related to the structure of an attack.

Thanks to Lockheed Martin, a global security and aerospace company, that established the Cyber Kill Chain® framework for the cybersecurity industry in 2011 based on the military concept.

The framework defines the steps used by adversaries or malicious actors in cyberspace.

The Cyber Kill Chain will help you understand and protect against ransomware attacks, security breaches as well as Advanced Persistent Threats (APTs).

We will be exploring the following attack phases:

- Reconnaissance
- Weaponization
- Delivery
- Exploitation
- Installation
- Command & Control
- Actions on Objectives

## Reconnaissance

**Reconnaissance** is discovering and collecting information on the system and the victim.

**OSINT** (Open-Source Intelligence) also falls under reconnaissance. OSINT is the first step an attacker needs to complete to carry out the further phases of an attack.

>OSINT is the act of gathering and analyzing publicly available data for intelligence purposes.

**Email harvesting** is the process of obtaining email addresses from public, paid, or free services. An attacker can use email-address harvesting for a **phishing attack**

> Phishing is a type of social-engineering attack used to steal sensitive data, including login credentials and credit card numbers).

The following is a list of tools available for reconnaissance purposes:

- [theHarvester](https://github.com/laramies/theHarvester) - other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources
- [Hunter.io](https://hunter.io/) - this is  an email hunting tool that will let you obtain contact information associated with the domain
- [OSINT Framework](https://osintframework.com/) - OSINT Framework provides the collection of OSINT tools based on various categories

## Weaponization

**Malware** is a program or software that is designed to damage, disrupt, or gain unauthorized access to a computer.

An **exploit** is a program or a code that takes advantage of the vulnerability or flaw in the application or system.

A **payload** is a malicious code that the attacker runs on the system.

Examples of weaponization could be:

- Creating an infected Microsoft Office document containing a malicious macro or VBA script
- Creating a sophisticated worm and implanting it on a USB drive

## Delivery

The delivery phase is when an attacker chooses the method for transmitting the payload or malware.

Examples could include:

- Sending a phishing email to the victim
- Distributing infected USB drives
- Watering hole attack

> A watering hole attack is a targeted attack designed to aim at a specific group of people by compromising the website they visit often.

## Exploitation

The exploitation phase is when an attacker gains access to a system by exploiting a vulnerability. This vulnerability could be a software, system, or server-based vulnerability.

These are examples of how an attacker carries out exploitation:

- The victim triggers the exploit by opening the email attachment or clicking on a malicious link.
- Using a zero-day exploit.
- Exploit software, hardware, or even human vulnerabilities. 
- An attacker triggers the exploit for server-based vulnerabilities.

## Installation

The installation phase includes installing a persistent backdoor in order to regain access after the initial exploit.

>A backdoor allows an attacker to regain access to a system after the initial exploit

Persistence can be achieved through:

- Installing a web shell on the web server
- Installing a backdoor on the victim's machine
- Creating of modifying Windows services
- Adding the entry to the "run keys" for the malicious payload in the registry

## Command and Control

The C2 (Command and Control) phase is about opening a channel through the malware that allows the attacker to remotely control and manipulate the victim machine. This is also known as **C&C** or **C2 Beaconing**.

Most common C2 channels used by adversaries nowadays:

- HTTP on port 80 and HTTPS on port 443, to blend with legitimate traffic
- DNS on port 53, also known as DNS tunneling

## Actions on Objectives (Exfiltration)

This phase is when the attacker can finally achieve their goals which could include the following:

- Collect user credentials
- Perform privilege escalation
- Internal reconnaissance
- Lateral movement
- Collect and exfiltrate sensitive data
- Deleting backups and shadow copies
- Overwrite or corrupt data
