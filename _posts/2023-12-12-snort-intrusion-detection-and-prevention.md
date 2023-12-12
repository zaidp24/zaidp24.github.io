---
title: Snort - Intrusion Detection and Prevention
date: 2023-12-12 17:37:00 -0500
categories: [Notes, SOC Level 1]
tags: [snort, ids/ips, intrusion detection, intrusion prevention, notes] # TAG names should always be lowercase
---

## Introduction

**SNORT** is an open-source, rule-based Network Intrusion Detection and Prevention System **(NIDS/NIPS)**.

![snort](/assets/img/snort.png){: width="400"}

## Intrusion Detection System (IDS)

IDS is a passive monitoring solution for detecting possible malicious activities/patterns, abnormal incidents, and policy violations. It is responsible for generating alerts for each suspicious event.

Two main types of IDS systems:

- Network Intrusion Detection System (NIDS) - monitors traffic flow from various areas of the network
- Host-based Intrusion Detection System (HIDS) - monitors traffic flow from a single endpoint device

## Intrusion Prevention Systems

IPS is an active protecting solution for preventing possible malicious activities, patterns, abnormal incidents, and policy violations. It is responsible for stopping/preventing/terminating the suspicious event as soon as the detection is performed.

Four main types of IPS systems:

- **Network Intrusion Prevention System (NIPS)** - NIPS monitors the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet.
- **Behaviour-based Intrusion Prevention System (Network Behaviour Analysis - NBA)** - Behaviour-based systems monitor the traffic flow from various areas of the network. The aim is to protect the traffic on the entire subnet.
- **Wireless Intrusion Prevention System (WIPS)** - WIPS monitors the traffic flow from of wireless network. The aim is to protect the wireless traffic and stop possible attacks launched from there.
- **Host-based Intrusion Prevention System (HIPS)** - HIPS actively protects the traffic flow from a single endpoint device.

> Behaviour based systems require a training period (also known as "baselining") to learn the normal traffic and differentiate the malicious traffic and threats.
{: .prompt-info }

There are three main detection and prevention techniques used in IDS and IPS solutions:

| **Technique**  |  **Approach** |
|:----------:|:----------|
|**Signature-Based**|This technique relies on rules that identify the specific patterns of the known malicious behaviour. This model helps detect known threats.|
|**Behaviour-Based**|This technique identifies new threats with new patterns that pass through signatures. The model compares the known/normal with unknown/abnormal behaviours. This model helps detect previously unknown or new threats.|
|**Policy-Based**|This technique compares detected activities with system configuration and security policies. This model helps detect policy violations.|

## Snort

Capabilities of Snort:

- Live traffic analysis
- Attack and probe detection
- Packet logging
- Protocol analysis
- Real-time alerting
- Modules & plugins
- Pre-processors
- Cross-platform support (Linux & Windows)

Snort use models:

- **Sniffer Mode** - Read IP packets
- **Packet Logger Mode** - Log all IP packets
- **NIDS and NIPS Modes** - Log/drop the packets are deemed malicious

## First Interaction with Snort

The following command `snort -V` will show you the instance version for snort

```shell
ubuntu@ubuntu:~$ snort -V

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149) 
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.9.1 (with TPACKET_V3)
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.11
```

**-T** is used for testing configuration
**-c** is used to specify the configuration file (snort.conf)

```shell
ubuntu@ubuntu:~$ sudo snort -c /etc/snort/snort.conf -T
Running in Test mode

        --== Initializing Snort ==--
Initializing Output Plugins!
Initializing Preprocessors!
Initializing Plug-ins!
Parsing Rules file "/etc/snort/snort.conf"
PortVar 'HTTP_PORTS' defined :  [ 80:81 311 383 591 593 901 1220 1414 1741 1830 2301 2381 2809 3037 3128 3702 4343 4848 5250 6988 7000:7001 7144:7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180:8181 8243 8280 8300 8800 8888 8899 9000 9060 9080 9090:9091 9443 9999 11371 34443:34444 41080 50002 55555 ]
PortVar 'SHELLCODE_PORTS' defined :  [ 0:79 81:65535 ]
PortVar 'ORACLE_PORTS' defined :  [ 1024:65535 ]
PortVar 'SSH_PORTS' defined :  [ 22 ]
PortVar 'FTP_PORTS' defined :  [ 21 2100 3535 ]
PortVar 'SIP_PORTS' defined :  [ 5060:5061 5600 ]

...
```


|  **Parameter**   |                                **Description**                                                 |
|--------------|--------------------------------------------------------------------------------------------|
|**-V / --version**|This parameter provides information about your instance version.|
|**-c**|Identifying the configuration file|
|**-T**|Snort's self-test parameter, you can test your setup with this parameter.|
|-**q**            |Quiet mode prevents snort from displaying the default banner and initial information about your setup.|

## Sniffer Mode

![snort-sniffer-mode](/assets/img/snort-sniffer-mode.png){: width="500"}
_Snort Sniffer Mode_

Snort sniffer mode parameters:

| **Parameter**  | **Description**  |
|---|---|
|**-v**|Verbose. Display the TCP/IP output in the console.|
|**-d**|Display the packet data (payload).|
|**-e**|Display the link-layer (TCP/IP/UDP/ICMP) headers.|
|-**X**|Display the full packet details in HEX.|
|-**i**|This parameter helps to define a specific network interface to listen/sniff. Once you have multiple interfaces, you can choose a specific interface to sniff.|

snort sniffing mode using interface eth0

```shell
sudo snort -v -i eth0
```

## Packet Logger Mode

![snort-packet-logger-mode](/assets/img/snort-packet-logger-mode.png)
_Snort Packet Logger Mode_

Snort packet logger parameters:

|**Parameter**|**Description**|
|---|---|
|**-l**|Logger mode, target **log and alert** output directory. Default output folder is **/var/log/snort**<br><br>The default action is to dump as tcpdump format in **/var/log/snort**|
|**-K ASCII**|Log packets in ASCII format.|
|**-r**|Reading option, read the dumped logs in Snort.|
|**-n**|Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.|

Starting snort in packet logger mode:

```shell
sudo snort -dev -l .
```

```shell
sudo snort -dev -K ASCII -l .
```

Reading snort logs:

```shell
sudo snort -r snort.log.1638459842
```

Only output the first 10 packets:

```shell
sudo snort -dvr logname.log -n 10
```

Others:

- `sudo snort -r logname.log -X`
- `sudo snort -r logname.log icmp`
- `sudo snort -r logname.log tcp`
- `sudo snort -r logname.log 'udp and port 53'`

## IDS/IPS Mode

![snort-idps-mode](/assets/img/snort-idps-mode.png){: width="500"}
_Snort IDS/IPS Mode_

NIDS mode parameters are explained in the table below;

|**Parameter**|**Description**|
|---|---|
|**-c**|Defining the configuration file.|
|**-T**|Testing the configuration file.|
|**-N**|Disable logging.|
|**-D**|Background mode.|
|**-A**|Alert modes:  <br><br>**full:** Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.<br>**fast:**  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers.<br>**console**: Provides fast style alerts on the console screen.<br>**cmg:** CMG style, basic header details with payload in hex and text format.<br>**none:** Disabling alerting.|

Rule to detect ICMP traffic:

`alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)`

Other examples used:

To start the snort instance and test the config file: `sudo snort -c /etc/snort/snort.conf -T`.

Start the Snort instance and disable logging by running the following command: `sudo snort -c /etc/snort/snort.conf -N`.

Start the Snort instance in background mode with the following command: `sudo snort -c /etc/snort/snort.conf -D`.

Start the Snort instance in **console** alert mode (-A console ) with the following command `sudo snort -c /etc/snort/snort.conf -A console`.

Start the Snort instance in cmg alert mode (-A cmg ) with the following command `sudo snort -c /etc/snort/snort.conf -A cmg`.

Start the Snort instance in fast alert mode (-A fast ) with the following command `sudo snort -c /etc/snort/snort.conf -A fast`.

Start the Snort instance in full alert mode (-A full ) with the following command `sudo snort -c /etc/snort/snort.conf -A full`.

Start the Snort instance in none alert mode (-A none) with the following command `sudo snort -c /etc/snort/snort.conf -A none`.

## PCAP Investigation Mode

![snort-pcap](/assets/img/snort-pcap.png)
_Snort PCAP Investigation Mode_

PCAP mode parameters are explained in the table below;  

|**Parameter**|**Description**|
|---|---|
|**-r / --pcap-single=**|Read a single pcap.|
|**--pcap-list=""**|Read pcaps provided in command (space separated).|
|**--pcap-show**|Show pcap name on console during processing.|

You can still test the default reading option with pcap by using the following command `snort -r icmp-test.pcap`.

## Snort Rule Structure

![snort-rule-structure](/assets/img/snort-rule-structure.png){: width="500"}

The primary structure of a snort rule is shown below:

![snort-rule-diagram](/assets/img/snort-rule-diagram.png)
_Snort Rule Structure Diagram_

Snort actions:

- alert - generate an alert and log the packet
- log
- drop - block and log the packet
- reject - block the packet, log it and terminate the packet session

Example parameters:

|   |   |
|---|---|
|IP Filtering|alert icmp 192.168.1.56 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each ICMP packet originating from the 192.168.1.56 IP address.|
|Filter an IP range|alert icmp 192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each ICMP packet originating from the 192.168.1.0/24 subnet.|
|Filter multiple IP ranges|alert icmp [192.168.1.0/24, 10.1.1.0/24] any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each ICMP packet originating from the 192.168.1.0/24 and 10.1.1.0/24 subnets.|
|Exclude IP addresses/ranges|"negation operator" is used for excluding specific addresses and ports. Negation operator is indicated with "!"<br><br>alert icmp !192.168.1.0/24 any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each ICMP packet not originating from the 192.168.1.0/24 subnet.|
|Port Filtering|alert tcp !192.168.1.0/24 21 <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet originating from port 21.|
|Exclude a specific port|alert tcp !192.168.1.0/24 !21 <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet not originating from port 21.|
|Filter a port range (Type 1)|alert tcp !192.168.1.0/24 1:1024 <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet originating from ports between 1-1024.|
|Filter a port range (Type 2)|alert icmp any :1024 <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet originating from ports less than or equal to 1024.|
|Filter a port range (Type 3)|alert icmp any 1024: <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet originating from a source port higher than or equal to 1024.|
|Filter a port range (Type 4)|alert icmp any 80,1024: <> any any (msg: "ICMP Packet Found"; sid: 100001; rev:1;)<br><br>This rule will create alerts for each TCP packet originating from a source port 80 and higher than or equal to 1024.|

- **->** Source to destination flow.
- **<>** Bidirectional flow

> there is no '<-' operator in snort

There are three main rule options in Snort;  

- General Rule Options - Fundamental rule options for Snort. 
- Payload Rule Options - Rule options that help to investigate the payload data. These options are helpful to detect specific payload patterns.
- Non-Payload Rule Options - Rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

**General Rule Options**

|   |   |
|---|---|
|Msg|The message field is a basic prompt and quick identifier of the rule. Once the rule is triggered, the message filed will appear in the console or log. Usually, the message part is a one-liner that summarises the event.|
|Sid|Snort rule IDs (SID) come with a pre-defined scope, and each rule must have a SID in a proper format. There are three different scopes for SIDs shown below.<br><br>- <100: Reserved rules<br>- 100-999,999: Rules came with the build.<br>- >=1,000,000: Rules created by user.<br><br>Briefly, the rules we will create should have sid greater than 100.000.000. Another important point is; SIDs should not overlap, and each id must be unique.|
|Reference|Each rule can have additional information or reference to explain the purpose of the rule or threat pattern. That could be a Common Vulnerabilities and Exposures (CVE) id or external information. Having references for the rules will always help analysts during the alert and incident investigation.|
|Rev|Snort rules can be modified and updated for performance and efficiency issues. Rev option help analysts to have the revision information of each rule. Therefore, it will be easy to understand rule improvements. Each rule has its unique rev number, and there is no auto-backup feature on the rule history. Analysts should keep the rule history themselves. Rev option is only an indicator of how many times the rule had revisions.<br><br>alert icmp any any <> any any (msg: "ICMP Packet Found"; sid: 100001; reference:cve,CVE-XXXX; rev:1;)|

**Payload Detection Rule Options**

|   |   |
|---|---|
|Content|Payload data. It matches specific payload data by ASCII, HEX or both. It is possible to use this option multiple times in a single rule. However, the more you create specific pattern match features, the more it takes time to investigate a packet.<br><br>Following rules will create an alert for each HTTP packet containing the keyword "GET". This rule option is case sensitive!<br><br>- ASCII mode - alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; sid: 100001; rev:1;)<br>- HEX mode - alert tcp any any <> any 80  (msg: "GET Request Found"; content:"\|47 45 54\|"; sid: 100001; rev:1;)|
|Nocase|Disabling case sensitivity. Used for enhancing the content searches.<br><br>alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; nocase; sid: 100001; rev:1;)|
|Fast_pattern|Prioritise content search to speed up the payload search operation. By default, Snort uses the biggest content and evaluates it against the rules. "fast_pattern" option helps you select the initial packet match with the specific value for further investigation. This option always works case insensitive and can be used once per rule. Note that this option is required when using multiple "content" options. <br><br>The following rule has two content options, and the fast_pattern option tells to snort to use the first content option (in this case, "GET") for the initial packet match.  <br><br>alert tcp any any <> any 80  (msg: "GET Request Found"; content:"GET"; fast_pattern; content:"www";  sid:100001; rev:1;)|

**Non-Payload Detection Rule Options**

There are rule options that focus on non-payload data. These options will help create specific patterns and identify network issues.

|   |   |
|---|---|
|ID|Filtering the IP id field.<br><br>alert tcp any any <> any any (msg: "ID TEST"; id:123456; sid: 100001; rev:1;)|
|Flags|Filtering the TCP flags.<br><br>- F - FIN<br>- S - SYN<br>- R - RST<br>- P - PSH<br>- A - ACK<br>- U - URG<br><br>alert tcp any any <> any any (msg: "FLAG TEST"; flags:S;  sid: 100001; rev:1;)|
|Dsize|Filtering the packet payload size.<br><br>- dsize:min<>max;<br>- dsize:>100<br>- dsize:<100<br><br>alert ip any any <> any any (msg: "SEQ TEST"; dsize:100<>300;  sid: 100001; rev:1;)|
|Sameip|Filtering the source and destination IP addresses for duplication.<br><br>alert ip any any <> any any (msg: "SAME-IP TEST";  sameip; sid: 100001; rev:1;)|

Remember, once you create a rule, it is a local rule and should be in your "local.rules" file located under `/etc/snort/rules/local.rules`

### Example Snort Rules

Write a rule to filter **IP ID "35369"**

`alert icmp any any <> any any (msg: "IP ID 35369 FOUND"; id:35369; sid:1000001; rev:1;)`

Create a rule to filter packets with Syn flag

`alert tcp any any <> any any (msg: "TCP SYN PACKET FOUND"; flags:S; sid:1000002; rev:1;)`

Write a rule to filter packets with Push-Ack flags

`alert tcp any any <> any any (msg: "TCP PUSH-ACK PKT FOUND"; flags:P,A; sid:1000003; rev:1;)`

write a rule to filter tcp packets with the same source and destination IP

`alert tcp any any <> any any (msg: "SAME SRC & DST FOUND"; sameip; sid:1000004; rev:1;)`

**Main** Components of Snort

- **Packet Decoder -** Packet collector component of Snort. It collects and prepares the packets for pre-processing. 
- **Pre-processors -** A component that arranges and modifies the packets for the detection engine.
- **Detection Engine -** The primary component that process, dissect and analyse the packets by applying the rules. 
- Logging and Alerting - Log and alert generation component.
- Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component.

**There are three types of rules available for snort**

- Community Rules - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
- Registered Rules - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
- Subscriber Rules (Paid) - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).

## Snort.conf file

**Navigate to the "Step #1: Set the network variables." section.**

This section manages the scope of the detection and rule paths.  

|**TAG NAME**|**INFO**|**EXAMPLE**|
|---|---|---|
|HOME_NET|That is where we are protecting.|'any' OR '192.168.1.1/24'|
|EXTERNAL_NET|This field is the external network, so we need to keep it as 'any' or '!$HOME_NET'.|'any' OR '!$HOME_NET'|
|RULE_PATH|Hardcoded rule path.|/etc/snort/rules|
|SO_RULE_PATH|_These rules come with registered and subscriber rules._|$RULE_PATH/so_rules|
|PREPROC_RULE_PATH|_These rules come with registered and subscriber rules._|$RULE_PATH/plugin_rules|

**Navigate to the "Step #2: Configure the decoder." section.**  

In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.

|**TAG NAME**|**INFO**|**EXAMPLE**|
|---|---|---|
|**#config daq:**|IPS mode selection.|afpacket|
|**#config daq_mode:**|Activating the inline mode|inline|
|**#config logdir:**|Hardcoded default log path.|/var/logs/snort|

There are six DAQ modules available in Snort;

- **Pcap:** Default mode, known as Sniffer mode.
- **Afpacket:** Inline mode, known as IPS mode.
- **Ipq:** Inline mode on Linux by using Netfilter. It replaces the snort_inline patch.  
- **Nfq:** Inline mode on Linux.
- **Ipfw:** Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.  
- **Dump:** Testing mode of inline and normalization.

**Navigate to the "Step #6: Configure output plugins" section.**

This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently. 

**Navigate to the "Step #7: Customise your ruleset" section.**  

|   |   |   |
|---|---|---|
|**TAG NAME**|**INFO**|**EXAMPLE**|
|**# site specific rules**|Hardcoded local and user-generated rules path.|include $RULE_PATH/local.rules|
|**#include $RULE_PATH/**|Hardcoded default/downloaded rules path.|include $RULE_PATH/rulename|
