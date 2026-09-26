# Python Brute Force Detection & Authentication Correlation

## Overview

This project demonstrates a Python-based authentication log analysis tool designed for SOC investigation and detection engineering practice.

The tool analyzes authentication events and identifies suspicious login patterns such as:

* Repeated failed authentication attempts
* Multiple failures within a defined time window
* Successful login following multiple failed attempts
* Source IP and username correlation
* Authentication event timeline analysis

The project simulates a basic SOC detection workflow using Python and CSV authentication logs.

## Detection Logic

### 1. Failed Login Counting

The script counts failed authentication attempts by:

* Source IP
* Username
* IP + Username combination

### 2. Time-Window Detection

The script identifies repeated authentication failures within a configurable time window.

Example rule:

```text
5 or more failed attempts
within 60 seconds
```

### 3. Brute Force → Successful Login Correlation

The script correlates successful authentication with previous failures from the same source IP and username.

Example:

```text
10:01:05  FAILED
10:01:15  FAILED
10:01:25  FAILED
10:01:35  FAILED
10:01:45  FAILED
10:01:50  SUCCESS
```

The tool generates an alert when the configured threshold is reached.

## Example Alert

```text
🚨 BRUTE FORCE -> SUCCESS

IP: 192.168.1.50
User: admin
Failed attempts: 5
Successful login: 2026-09-25 10:01:50
Failures occurred within 60 seconds before success.
```

## Technologies

* Python
* CSV
* Dictionaries
* Sets
* `datetime`
* Authentication log analysis
* Event correlation
* SOC detection logic

## Python Concepts Demonstrated

* CSV parsing with `csv.DictReader`
* Dictionary-based aggregation
* Tuple keys
* Lists
* Sets
* `datetime.strptime()`
* Timestamp comparison
* Sliding/time-window style correlation
* Conditional detection logic
* Functions and modular code

## SOC Skills Demonstrated

* Authentication log analysis
* Brute-force detection
* Event correlation
* Detection-rule development
* Timeline analysis
* Alert generation
* Security investigation fundamentals

## Future Improvements

Planned enhancements:

* Password spraying detection
* Distributed brute-force detection
* Alert enrichment
* JSON alert generation
* CSV alert export
* REST API integration
* Splunk integration
* Microsoft Sentinel integration
* Automated investigation workflow

## Disclaimer

This project is created for cybersecurity learning, detection engineering practice, and authorized lab environments. The log data used in this repository is synthetic.
