# AI Security Log Copilot

> An Edge AI-powered security log analysis and incident investigation assistant for Linux servers.

## 1. Project Overview

Modern Linux servers continuously generate large amounts of security-related logs from services such as SSH, web servers, firewalls, and system services. Although these logs contain valuable information about potential cyberattacks, manually reviewing thousands of log entries is time-consuming and requires cybersecurity expertise.

**AI Security Log Copilot** is a local AI-powered security monitoring and investigation assistant designed to help system administrators detect, understand, and investigate suspicious activities on Linux servers.

The system combines a deterministic **Threat Detection Engine** with a local **AI Security Copilot**.

The Detection Engine identifies suspicious activities from system and application logs, while the AI Copilot correlates related security events, explains potential attacks, constructs attack timelines, and provides actionable remediation recommendations.

The core design principle is:

> **Detection should be reliable and explainable; AI should assist investigation and decision-making.**

Therefore, the AI model is not responsible for directly deciding whether individual log entries represent attacks. Instead, deterministic detection mechanisms first generate structured security events, which are subsequently analyzed by the AI Copilot.

---

## 2. Problem Statement

Linux servers may generate thousands or millions of log entries every day.

Examples include:

- SSH authentication logs
- Nginx access logs
- Firewall logs
- Network connection logs
- System and service logs

Potential attacks are often hidden among large amounts of legitimate activity.

For example, an account compromise may produce a sequence such as:

```text
19:20  Multiple failed SSH authentication attempts
19:21  Successful SSH authentication
19:22  sudo command executed
19:23  Suspicious system activity
```

Each individual event may not provide enough information to determine what happened.

Traditional log monitoring systems can detect predefined patterns and generate alerts, but administrators still need to manually:

1. Review large numbers of alerts and raw logs.
2. Identify relationships between events.
3. Reconstruct attack timelines.
4. Understand the potential security impact.
5. Determine appropriate remediation steps.
6. Produce incident reports.

These tasks can be difficult for small organizations or teams without dedicated Security Operations Center (SOC) personnel.

AI Security Log Copilot aims to reduce this investigation workload.

---

## 3. Proposed Solution

The proposed system continuously collects security-related logs from a Linux server and transforms them into structured events.

These events pass through a threat detection engine that identifies suspicious behavior using deterministic rules, statistical analysis, and event correlation.

Detected security events are then provided to a local AI model.

The AI Security Copilot performs higher-level analysis such as:

- explaining detected threats;
- correlating events across different log sources;
- reconstructing attack timelines;
- answering natural-language security questions;
- generating incident reports;
- recommending remediation actions.

The overall pipeline is:

```text
Linux Server
     |
     v
Log Collection
     |
     v
Log Parser
     |
     v
Normalized Log Events
     |
     v
Threat Detection Engine
     |
     v
Security Alerts
     |
     v
AI Security Copilot
     |
     v
Incidents / Explanations / Recommendations
     |
     v
Web Dashboard
```

---

## 4. Target Environment

The initial version of AI Security Log Copilot focuses on monitoring a single Linux server.

The monitored server may provide services such as:

```text
Linux Server
├── SSH
├── Nginx
├── Web Applications
└── System Services
```

The initial supported data sources include:

| Data Source             | Purpose                             |
| ----------------------- | ----------------------------------- |
| SSH authentication logs | Detect authentication attacks       |
| Nginx access logs       | Detect suspicious web requests      |
| Firewall / network logs | Detect reconnaissance activities    |
| System logs             | Provide additional incident context |

The project intentionally focuses on attacks that leave observable evidence in server logs.

It does not attempt to detect every possible cybersecurity attack.

---

## 5. Threat Detection Requirements

The MVP will initially support five categories of suspicious activity.

### 5.1 SSH Brute-Force Attack

Detect repeated failed SSH authentication attempts originating from the same source within a short period.

Example:

```text
Failed password for root from 10.0.0.8
Failed password for root from 10.0.0.8
Failed password for root from 10.0.0.8
...
```

Possible detection logic:

```text
Same source IP
      +
Multiple failed authentication attempts
      +
Short time window
      |
      v
SSH Brute-Force Alert
```

Example output:

```text
Threat: SSH Brute Force
Severity: HIGH
Source: 10.0.0.8
Attempts: 42
Time Window: 60 seconds
```

---

### 5.2 Suspicious Login / Possible Account Compromise

Identify successful authentication that occurs shortly after repeated failed attempts from the same source.

Example:

```text
20 failed authentication attempts
             |
             v
Successful authentication
             |
             v
Possible Account Compromise
```

This demonstrates event correlation rather than simple single-log pattern matching.

The system must distinguish between:

- authentication attempts;
- suspicious authentication behavior;
- confirmed compromise.

A successful login following repeated failures should therefore be reported as a **possible account compromise**, rather than automatically claiming that the account has been compromised.

---

### 5.3 Port Scanning / Network Reconnaissance

Detect a host attempting to connect to a large number of destination ports within a short period.

Example:

```text
10.0.0.5 -> port 22
10.0.0.5 -> port 23
10.0.0.5 -> port 80
10.0.0.5 -> port 443
10.0.0.5 -> port 3306
...
```

Possible detection logic:

```text
Same source IP
      +
Many destination ports
      +
Short time interval
      |
      v
Possible Port Scan
```

---

### 5.4 Web Enumeration

Detect automated attempts to discover sensitive files, administrative interfaces, development artifacts, or commonly exposed services.

Example requests may include:

```text
GET /.env
GET /.git/config
GET /wp-admin
GET /phpmyadmin
GET /admin
GET /backup.zip
```

Detection may consider:

- suspicious paths;
- unusually high request frequency;
- large numbers of HTTP 404 responses;
- repeated requests from the same source.

Example alert:

```text
Threat: Web Enumeration
Source: 10.0.0.12

Suspicious Requests:
- /.env
- /.git/config
- /phpmyadmin
- /backup.zip
```

---

### 5.5 Web Attack Attempts

Identify requests containing patterns commonly associated with web attacks.

The initial implementation focuses on:

- SQL injection attempts;
- Cross-Site Scripting (XSS) attempts.

Example SQL injection payload:

```text
?id=1' OR '1'='1
```

Example XSS payload:

```text
?q=<script>alert(1)</script>
```

The system must distinguish between an **attack attempt** and a **successful exploitation**.

Detecting a suspicious request does not prove that the target application was successfully compromised.

---

## 6. Detection Summary

| Threat             | Primary Data Source     | Detection Method               |
| ------------------ | ----------------------- | ------------------------------ |
| SSH Brute Force    | SSH logs                | Threshold / time-window rules  |
| Suspicious Login   | SSH logs                | Event correlation              |
| Port Scan          | Firewall / network logs | Statistical / behavioral rules |
| Web Enumeration    | Nginx logs              | Pattern + behavioral analysis  |
| SQLi / XSS Attempt | Nginx logs              | Request pattern analysis       |

The Detection Engine is intentionally separated from the AI component.

Its responsibility is:

> **Determine which observable activities satisfy defined suspicious behavior patterns.**

---

## 7. Role of the AI Security Copilot

The AI component operates after suspicious events have been detected.

Its primary responsibility is not detection, but **investigation and explanation**.

The responsibilities are divided as follows:

```text
Detection Engine
      |
      | Detect
      | "What suspicious activity occurred?"
      |
      v
AI Security Copilot
      |
      | Investigate
      | "How are these events related?"
      |
      | Explain
      | "What could these events mean?"
      |
      | Respond
      | "What should the administrator investigate next?"
      v
Administrator
```

### 7.1 Security Event Explanation

The AI converts structured security events into human-readable explanations.

Input:

```json
{
  "type": "ssh_brute_force",
  "source_ip": "10.0.0.8",
  "failed_attempts": 42,
  "time_window": 60
}
```

Possible output:

```text
A possible SSH brute-force attack was detected.

The host 10.0.0.8 attempted authentication 42 times
within 60 seconds.

This behavior is consistent with automated password
guessing.
```

---

### 7.2 Cross-Log Event Correlation

The AI analyzes multiple security events and identifies meaningful relationships between them.

Example:

```text
SSH Brute Force
      |
      v
Successful Login
      |
      v
sudo Activity
      |
      v
Suspicious System Activity
```

Instead of displaying four unrelated alerts, the Copilot may group them into a single potential incident.

Example:

```text
Possible Account Compromise

19:20
42 failed SSH login attempts
        |
19:21
Successful login from the same source
        |
19:22
Privilege-related activity detected
        |
19:23
Suspicious system activity
```

---

### 7.3 Attack Timeline Generation

The AI generates a concise chronological representation of an incident.

This allows administrators to quickly understand:

- when suspicious activity began;
- which systems or accounts were involved;
- how the activity progressed;
- what happened after initial access.

---

### 7.4 Natural-Language Investigation

Administrators can interact with the system using natural language.

Example questions include:

```text
What happened during the last hour?

What did 10.0.0.8 do?

Did any brute-force attempt result in a successful login?

Show me suspicious activity involving the admin account.

Why is this alert considered dangerous?
```

The AI answers these questions using the structured security events and incidents collected by the system.

---

### 7.5 Incident Report Generation

The Copilot can automatically generate a structured incident report.

Example:

```text
Incident: Possible SSH Account Compromise
Severity: HIGH

Summary:
Repeated SSH authentication failures were followed
by a successful login from the same source.

Timeline:
19:20:03  First failed authentication
19:20:58  42nd failed authentication
19:21:04  Successful authentication
19:22:11  Privileged activity observed

Affected Account:
admin

Source:
10.0.0.8

Recommended Investigation:
- Review commands executed during the SSH session.
- Review authentication history.
- Inspect privilege escalation activity.
- Check for persistence mechanisms.
```

---

### 7.6 Remediation Recommendations

The AI may recommend possible responses.

Recommendations can be separated into categories such as:

```text
Immediate Actions
- Investigate the suspicious SSH session.
- Consider temporarily blocking the source.

Investigation
- Review authentication history.
- Inspect commands executed after login.
- Check recently modified files.

Prevention
- Disable unnecessary password authentication.
- Consider SSH key authentication.
- Introduce authentication rate limiting.
```

Recommendations remain advisory.

---

## 8. AI Safety and Responsibility Boundaries

The AI Copilot will not automatically perform destructive or security-sensitive actions.

The initial version will **not** allow the AI to autonomously:

- modify firewall rules;
- block IP addresses;
- disable user accounts;
- terminate processes;
- execute shell commands;
- modify system configuration.

The system follows a human-in-the-loop model:

```text
Detection
    |
    v
AI Analysis
    |
    v
Recommendation
    |
    v
Human Decision
    |
    v
Action
```

This reduces the risk of an incorrect AI analysis causing operational damage.

---

## 9. Local AI and Privacy

Security logs may contain sensitive information, including:

- internal IP addresses;
- usernames;
- server paths;
- application endpoints;
- authentication information;
- infrastructure metadata.

Therefore, the project is designed around **local AI inference** whenever possible.

The intended architecture is:

```text
Sensitive Security Logs
          |
          v
Local Detection
          |
          v
Local AI Inference
          |
          v
Local Dashboard
```

This enables the project to emphasize:

> **Security logs can be analyzed without requiring raw logs to leave the local environment.**

Local inference also provides a natural use case for edge AI acceleration.

---

## 10. System Architecture

The proposed software architecture is:

```text
                  Linux Server
                       |
        +--------------+--------------+
        |              |              |
        v              v              v
     SSH Logs      Nginx Logs    System/Network Logs
        |              |              |
        +--------------+--------------+
                       |
                       v
                Log Collectors
                       |
                       v
                  Log Parsers
                       |
                       v
               Normalized Events
                       |
                       v
              Detection Engine
                       |
             +---------+---------+
             |                   |
             v                   v
       Security Alerts      Event Storage
             |                   |
             +---------+---------+
                       |
                       v
              AI Security Copilot
                       |
           +-----------+-----------+
           |           |           |
           v           v           v
       Explain     Correlate     Recommend
           |           |           |
           +-----------+-----------+
                       |
                       v
                 Incident Model
                       |
                       v
                  REST API
                       |
                       v
               Next.js Dashboard
```

---

## 11. Core Data Model

The system revolves around three main abstractions.

### LogEvent

Represents a normalized event parsed from raw logs.

```text
Raw Log
   |
   v
LogEvent
```

Possible fields:

```text
timestamp
source
event_type
source_ip
destination_ip
source_port
destination_port
username
metadata
raw_log
```

### SecurityAlert

Represents suspicious behavior detected from one or more `LogEvent` objects.

```text
LogEvent(s)
     |
     v
Detection Engine
     |
     v
SecurityAlert
```

Possible fields:

```text
id
timestamp
alert_type
severity
source_ip
evidence
related_events
status
```

### Incident

Represents one or more related alerts grouped into a higher-level security incident.

```text
SecurityAlert
SecurityAlert
SecurityAlert
      |
      v
AI / Correlation
      |
      v
Incident
```

Possible fields:

```text
id
title
severity
summary
start_time
end_time
related_alerts
timeline
affected_entities
recommendations
status
```

---

## 12. Web Dashboard

The web interface will initially contain three primary sections.

### Threat Dashboard

Displays detected security alerts.

Example:

```text
+------------------------------------------+
| Security Log Copilot                     |
+------------------------------------------+
| Active Threats                         3 |
|                                          |
| [HIGH] SSH Brute Force                   |
| Source: 10.0.0.8                         |
| Attempts: 42                             |
|                                          |
| [MEDIUM] Web Enumeration                 |
| Source: 10.0.0.12                        |
| Requests: 37                             |
+------------------------------------------+
```

### Incident Investigation

Displays correlated events and attack timelines.

```text
Possible Account Compromise

19:20  SSH brute force detected
  |
19:21  Successful authentication
  |
19:22  Privileged activity
  |
19:23  Suspicious system activity

[Generate Report]
[Ask Copilot]
```

### AI Copilot

Provides a conversational interface for security investigation.

```text
Security Copilot

> What happened during the last hour?

Three suspicious activities were detected...

> Did the SSH brute-force attack succeed?

A successful authentication from the same source
was observed shortly after the failed attempts...
```

---

## 13. Repository Structure

The project uses a monorepo containing the backend, frontend, sample data, and documentation.

```text
ai-security-log-copilot/
├── backend/
│   ├── app/
│   │   ├── parsers/
│   │   │   ├── ssh.py
│   │   │   ├── nginx.py
│   │   │   └── network.py
│   │   │
│   │   ├── detectors/
│   │   │   ├── ssh_bruteforce.py
│   │   │   ├── suspicious_login.py
│   │   │   ├── port_scan.py
│   │   │   ├── web_enumeration.py
│   │   │   └── web_attack.py
│   │   │
│   │   ├── agents/
│   │   │   └── security_copilot.py
│   │   │
│   │   ├── models/
│   │   │   ├── event.py
│   │   │   ├── alert.py
│   │   │   └── incident.py
│   │   │
│   │   └── main.py
│   │
│   ├── tests/
│   └── pyproject.toml
│
├── frontend/
│   └── Next.js application
│
├── samples/
│   ├── ssh/
│   │   ├── normal.log
│   │   ├── brute_force.log
│   │   └── compromised_login.log
│   │
│   ├── nginx/
│   │   ├── normal.log
│   │   ├── enumeration.log
│   │   ├── sqli.log
│   │   └── xss.log
│   │
│   └── network/
│       ├── normal.log
│       └── port_scan.log
│
├── docs/
│
├── proposal.md
├── README.md
├── LICENSE
└── .gitignore
```

---

## 14. Proposed Technology Stack

### Backend

- Python
- FastAPI
- Pydantic

Responsibilities:

- log parsing;
- threat detection;
- event storage and retrieval;
- AI integration;
- REST API.

### Frontend

- Next.js
- TypeScript
- Tailwind CSS

Responsibilities:

- security dashboard;
- alert visualization;
- incident timelines;
- Copilot interface.

### AI

The AI layer will use a locally deployed language model when possible.

The exact model and inference runtime will be selected during implementation based on:

- hardware compatibility;
- inference latency;
- model size;
- security reasoning capability;
- ASUS competition hardware availability.

The architecture should avoid tightly coupling the application to one specific model.

---

## 15. MVP Scope

The MVP should demonstrate the complete pipeline rather than maximize the number of supported attacks.

### Required MVP

- [ ] Parse SSH authentication logs.
- [ ] Detect SSH brute-force activity.
- [ ] Detect suspicious successful login after repeated failures.
- [ ] Generate structured security alerts.
- [ ] Expose alerts through FastAPI.
- [ ] Display alerts on the web dashboard.
- [ ] Use a local AI model to explain an alert.
- [ ] Generate a basic incident timeline.
- [ ] Generate remediation recommendations.

### Secondary Features

After the core pipeline is stable:

- [ ] Parse Nginx access logs.
- [ ] Detect web enumeration.
- [ ] Detect SQLi attempts.
- [ ] Detect XSS attempts.
- [ ] Detect port scanning.
- [ ] Support cross-log correlation.
- [ ] Add natural-language investigation.
- [ ] Generate complete incident reports.

### Future Extensions

Potential future work includes:

- anomaly detection using machine learning;
- additional Linux services;
- multi-host monitoring;
- real-time streaming;
- MITRE ATT&CK mapping;
- alert prioritization;
- SIEM integration;
- administrator-approved response actions.

---

## 16. Demonstration Scenario

The final prototype should demonstrate a coherent attack story rather than isolated alerts.

A possible demonstration scenario is:

```text
Attacker
   |
   | 1. Port scanning
   v
Reconnaissance detected
   |
   | 2. Web enumeration
   v
Sensitive endpoints discovered
   |
   | 3. SSH brute-force attempts
   v
Authentication attack detected
   |
   | 4. Successful authentication
   v
Possible account compromise
   |
   | 5. Privileged activity
   v
Potential post-compromise activity
```

The Detection Engine generates individual alerts.

The AI Security Copilot then reconstructs them into an incident:

```text
Possible Account Compromise

Attack Timeline
----------------------------------------

19:18  Port scanning detected
        Source: 10.0.0.8

19:19  Web enumeration detected
        /.env
        /.git/config

19:20  SSH brute-force detected
        42 failed attempts

19:21  Successful SSH login
        Same source IP

19:22  Privileged activity observed

----------------------------------------

AI Assessment:

The observed events may represent a sequence of
reconnaissance, authentication attacks, and possible
account compromise.

Recommended next step:

Review the authenticated session and subsequent
privileged activity.
```

This scenario demonstrates both the detection capabilities and the value of AI-based investigation.

---

## 17. Expected Benefits

### Reduced Investigation Time

Administrators no longer need to manually inspect every raw log entry before understanding an incident.

### Improved Accessibility

Natural-language explanations make security events easier to understand for users without extensive SOC experience.

### Cross-Source Context

Events from different log sources can be combined into a coherent incident timeline.

### Actionable Security Information

Instead of only generating alerts, the system explains potential impact and suggests investigation and remediation steps.

### Privacy-Preserving AI

Local inference allows sensitive security logs to remain inside the monitored environment.

---

## 18. Project Positioning

AI Security Log Copilot is not intended to replace a full SIEM, IDS, EDR, or professional SOC team.

Instead, the project explores how local AI can serve as an intelligent investigation layer on top of traditional security detection mechanisms.

The key idea is:

> **Traditional detection tells administrators that something suspicious happened.**
> **AI Security Log Copilot helps them understand what happened, how the events may be connected, and what they should investigate next.**

This combination of deterministic security detection and local AI-assisted investigation provides a practical use case for Edge AI in cybersecurity.

---

## 19. Development Principle

Development should follow this order:

```text
Reliable Detection
        |
        v
Structured Security Data
        |
        v
Useful AI Analysis
        |
        v
Clear User Experience
```

The project should avoid adding AI where deterministic logic provides a simpler and more reliable solution.

AI should be used where it provides clear value:

- reasoning across multiple events;
- summarizing large amounts of security information;
- explaining technical events;
- answering investigation questions;
- generating actionable reports.

The success of the project should therefore not be measured by how much AI is used, but by how effectively AI reduces the effort required to understand and investigate security incidents.

