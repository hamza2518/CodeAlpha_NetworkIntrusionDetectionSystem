# CodeAlpha Network Intrusion Detection System

## Overview

This project implements a Network Intrusion Detection System (NIDS) using Suricata 8.0.7 on Windows.

## Objectives

- Monitor network traffic
- Configure IDS detection rules
- Generate alerts for suspicious traffic
- Record and analyze IDS events
- Implement an incident-response workflow
- Visualize detected alerts

## Technologies

- Suricata 8.0.7
- Npcap
- Python 3.12
- PowerShell
- Matplotlib
- Emerging Threats Open rules
- Git / GitHub

## Detection Rule

The project includes a custom ICMP detection rule:

```text
alert icmp $HOME_NET any -> any any (msg:"CODEALPHA - ICMP Echo Request Detected"; itype:8; sid:1000001; rev:1;)
Test Result

A controlled ICMP test was performed from the local host to the local gateway.

Source       : 192.168.1.8
Destination  : 192.168.1.1
Protocol     : ICMP
Alerts       : 5
SID          : 1000001

The alerts were recorded in:

eve.json
fast.log
Incident Response

The PowerShell response script:

response/Invoke-NIDSResponse.ps1

reads Suricata EVE JSON alert events and records matching incidents in:

response/incident_response.log

The workflow records the source, destination, signature, SID, timestamp, and recommended analyst action.

Visualization

The Python dashboard:

visualization/generate_dashboard.py

reads Suricata alert events and generates:

visualization/alert_summary.png

The demonstrated test produced 5 alerts.

Configuration

Suricata configuration was successfully validated using:

suricata.exe -T -c suricata.yaml

Live packet capture was performed through the Wi-Fi interface using Npcap.

Project Structure
CodeAlpha_NetworkIntrusionDetectionSystem/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── config/
│   ├── suricata.yaml
│   └── threshold.config
│
├── rules/
│   └── custom.rules
│
├── response/
│   ├── Invoke-NIDSResponse.ps1
│   └── incident_response.log
│
├── visualization/
│   ├── generate_dashboard.py
│   └── alert_summary.png
│
└── docs/
    └── screenshots/
Safety

Testing was performed against the user's own local lab/network traffic. No third-party systems were intentionally targeted.

Author

Hamza Bashir

Cyber Security Student
