# README.md

# OTX-Sec
License: AGPL-3.0-only

Open-Source Antivirus & Threat Intelligence Platform

Created by **Anorial**

OTX-Sec is an open-source antivirus and threat intelligence platform focused on Linux systems.

The goal of OTX-Sec is to combine traditional malware detection techniques with modern threat intelligence from multiple providers including:

* AlienVault OTX
* VirusTotal
* MalwareBazaar
* URLHaus

OTX-Sec is designed to be transparent, privacy-respecting and community-driven.

This project is licensed under the GNU Affero General Public License v3 (AGPLv3) and is intended to remain open source permanently.

---

# Current Status

Version:

0.1.1-alpha

State:

Early Alpha

OTX-Sec is already capable of:

* Monitoring files
* Monitoring processes
* Monitoring network activity
* Performing threat intelligence lookups
* Running static analysis
* Running native OTXv2 scan checks
* Generating incidents
* Displaying findings through a graphical interface

The software is still experimental and should not be used as the only security solution protecting production systems.

---

# Features

## Threat Intelligence

Supported Providers:

* AlienVault OTX
* VirusTotal
* MalwareBazaar
* URLHaus

Supported Indicators:

* SHA256 hashes
* IP addresses
* Domains
* URLs

---

## Detection

Current Detection Methods:

* Native OTXv2 detection engine
* SHA256 hashing
* Threat intelligence lookups
* Static file analysis
* Entropy analysis
* Suspicious string detection
* Native suspicious pattern analysis

---

## Monitoring

Available Monitors:

* File Scan Agent
* Process Monitor
* Network Monitor
* Persistence Monitor
* Integrity Checker
* Audit Exporter

---

## Incident Handling

* Event Collection
* Incident Engine
* Risk Scoring
* Human Readable Summaries
* JSON Export
* Quarantine Support

---

## Graphical Interface

OTX-Sec currently includes:

* Event Overview
* Incident Overview
* Threat Intelligence Settings
* Process Monitoring View
* Network Monitoring View
* Static Analysis Results
* Native Engine Results

---

# Project Structure

```text
otx-sec/
├── app/
├── config/
├── db/
├── docs/
├── engines/
├── integrations/
├── monitors/
├── packaging/
├── rules/
├── tests/
├── tools/
└── exports/
```

Directory Overview:

app/

* GUI
* Backend bridge

engines/

* Threat engine
* Risk engine
* Incident engine
* Static analysis engine
* Native OTXv2 engine

integrations/

* OTX
* VirusTotal
* MalwareBazaar
* URLHaus

monitors/

* Network monitor
* Process monitor
* Persistence monitor
* Audit monitor

tools/

* Agent
* Baseline generation
* Integrity checking
* Database writing
* Log importing

---

# Installation

Clone repository:

```bash
git clone https://github.com/AnorialTheReal/otx-sec.git
cd otx-sec
```

Create virtual environment:

```bash
python -m venv venv
source venv/bin/activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

Copy configuration:

```bash
cp config/settings.example.json config/settings.json
```

Start GUI:

```bash
python app/frontend.py
```

---

# Threat Engine CLI

Hash Lookup:

```bash
python -m engines.threat_engine hash <sha256>
```

IP Lookup:

```bash
python -m engines.threat_engine ip 8.8.8.8
```

Domain Lookup:

```bash
python -m engines.threat_engine domain example.com
```

URL Lookup:

```bash
python -m engines.threat_engine url http://example.com/
```

---

# Static Analysis

Example:

```bash
python -m engines.static_analysis /bin/ls
```

Features:

* File Type Detection
* Entropy Calculation
* Packed Binary Detection
* Suspicious String Detection

---

# Native OTXv2 Engine

OTXv2 uses its own native detection logic.

Example:

```bash
python tools/agent.py --scan /bin/ls
```

OTXv2 does not require external antivirus engines for native detection.

---

# Security Principles

OTX-Sec follows these principles:

* Open Source First
* User Control
* Local First
* No Hidden Telemetry
* No Hardcoded API Keys
* No Hardcoded Usernames
* Transparent Detection Logic
* Defensive Security Only

---

# License

GNU Affero General Public License v3.0 (AGPLv3)

The project will remain open source.

All modified hosted versions must also provide source code according to the AGPLv3 license.

---

# Contributing

Everyone is welcome.

You can contribute by:

* Testing
* Reporting bugs
* Improving documentation
* Improving native OTXv2 detection rules
* Improving threat intelligence integrations
* Writing Rust modules
* Writing C/C++ modules
* Writing Go modules
* Reviewing code

---

# Development Hours

| Contributor | Hours |
| ----------- | ----- |
| Anorial     | 68    |

Add your name and hours when contributing.

---

# Disclaimer

OTX-Sec is experimental software.

False positives and false negatives are possible.

Always verify detections before deleting or quarantining files.

**Made with passion by the Anorial.**

---

## 0.1.1-alpha Focus

OTX-Sec 0.1.1-alpha is focused on improving the Linux scanner, native detection logic, YARA rule layer and threat intelligence workflow.

Current 0.1.1-alpha improvements include:

* Linux-first native scanner improvements
* Linux reverse shell detection
* Linux cron persistence detection
* Linux downloader behavior detection
* LD_PRELOAD hijack indicators
* Improved YARA rule layer
* Improved native engine report details
* Single-file scan mode
* Daemon mode improvements
* English-only user-facing recommendations

Windows support is not the current focus of 0.1.1-alpha.

