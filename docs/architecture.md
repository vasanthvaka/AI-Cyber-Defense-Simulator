# System Architecture

## 1. Overview

The AI-Powered Cyber Defense Simulator uses a hybrid security architecture combining:

- Rule-based threat detection
- Isolation Forest anomaly detection
- Alert normalization
- Incident correlation
- Multi-agent analysis and response
- Response-safety policies
- Persistent storage
- REST API access
- Dashboard visualization

The system converts individual simulated security events into validated incidents and safe simulated defensive actions.

## 2. End-to-End Processing Flow

The complete processing sequence is:

```text
Simulator
    ↓
Event Validator
    ↓
Coordinator
    ↓
Monitoring Agent
    ↓
Rule Detectors and Isolation Forest
    ↓
Alert Normalization
    ↓
Alert Correlation
    ↓
Security Incident
    ↓
Analysis Agent
    ↓
Decision Agent
    ↓
Response Safety Layer
    ↓
Response Agent
    ↓
SQLite Storage
    ↓
FastAPI Backend
    ↓
React Dashboard
```

## 3. Simulation Layer

The simulation layer generates normal and malicious security activity.

Supported event types include:

- Login attempts
- HTTP requests
- Network connections
- Process activity

Supported attacks include:

- Brute force
- Distributed brute force
- DDoS
- Port scan
- Suspicious process execution

The scenario engine randomizes:

- Attacking IP addresses
- Target usernames
- Target systems
- HTTP endpoints
- Number of attack events
- Number of attacker sources
- Scanned ports
- Suspicious process templates
- Normal activity between attacks

Random seeds allow scenarios to be reproduced during tests and demonstrations.

## 4. Event Validation Layer

All events are validated before entering the security pipeline.

The validator checks:

- Event data type
- Required fields
- Timestamp format
- IP-address format
- Destination-port range
- Login status
- Connection status
- Process identifier

Malformed events are rejected before reaching detectors, agents, or database persistence.

Unknown event types can still be accepted when they contain valid common fields. This allows future event categories to be added without immediately modifying the complete pipeline.

## 5. Monitoring Agent

The Monitoring Agent receives validated events from the Coordinator.

It performs two independent operations:

1. Sends individual events to the appropriate rule-based detector.
2. Adds events to time-based windows for Isolation Forest analysis.

Rule alerts are produced immediately.

AI alerts are produced after a configured event window is completed.

## 6. Rule-Based Detection

Rule-based detectors identify known attack patterns using predefined security conditions.

### Brute Force

Detects repeated failed login attempts from one IP address within a configured time window.

### Distributed Brute Force

Detects several IP addresses repeatedly attacking the same user account.

### DDoS

Detects a large request volume from multiple sources against the same service or endpoint.

### Port Scan

Detects one source contacting an unusual number of destination ports on a target system.

### Suspicious Process

Assigns a risk score using indicators such as:

- Suspicious parent process
- Suspicious executable location
- Encoded commands
- Download-related commands
- Unusual process behaviour

Rule-based detection is precise for known patterns but may miss attacks designed to remain below fixed thresholds.

## 7. Isolation Forest Detection

Isolation Forest is an unsupervised anomaly-detection algorithm.

It learns the characteristics of normal event windows and assigns anomaly scores to new windows.

Window features include:

- Total events
- Login attempts
- Failed logins
- Unique source IPs
- HTTP requests
- Unique endpoints
- Network connections
- Unique destination ports
- Process activity
- Unique process names
- Maximum failed logins per user
- Maximum requests per source
- Maximum requests per service
- Maximum requests per endpoint
- Maximum ports per source
- Maximum command-line length

An unusual event window produces an `ANOMALOUS_BEHAVIOR` alert.

The model identifies unusual behaviour but does not always determine its exact attack category.

## 8. Hybrid Detection

Rule-based and AI detection operate independently.

```text
Known attack pattern
    → Rule detector
    → High-confidence classified alert

Unusual event pattern
    → Isolation Forest
    → Anomaly alert

Both forms of evidence
    → Correlated incident
    → Increased supporting evidence and risk
```

This design preserves reliable rule-based detection while allowing the system to detect threshold-evasion and previously unseen activity.

## 9. Alert Normalization

Different detectors originally returned alerts with different fields.

The normalization layer converts them into one shared alert structure containing:

- Alert ID
- Timestamp
- Attack type
- Detection method
- Sources
- Targets
- Severity
- Confidence
- Evidence
- Related event IDs
- Alert status
- Optional anomaly score

Typed entities distinguish IP addresses, user accounts, services, HTTP endpoints, process IDs, and process names.

## 10. Incident Correlation

Related alerts are combined into security incidents.

Correlation considers information such as:

- Attack type
- Source entities
- Target entities
- Detection method
- Event timing
- Existing open incidents

An incident may contain evidence from both rule-based and AI detection.

The correlator prevents every alert from becoming an unrelated case and provides a combined view of the attack.

## 11. Multi-Agent System

### Coordinator

The Coordinator manages messages between agents.

Its responsibilities include:

- Receiving events
- Creating agent messages
- Routing messages
- Tracking message history
- Collecting completed responses
- Recording failed messages
- Persisting pipeline results

### Monitoring Agent

Responsible for rule-based and AI detection.

### Analysis Agent

Evaluates an incident and produces:

- Risk score
- Confidence
- Human-review requirement
- Recommended escalation
- Supporting explanation

### Decision Agent

Maps analysed incidents to response policies.

Possible decisions include:

- Block one IP
- Block multiple IPs
- Rate-limit IPs
- Quarantine a process
- Flag for investigation
- Continue monitoring

### Response Agent

Executes simulated defensive actions and tracks:

- Blocked IPs
- Rate-limited IPs
- Quarantined processes
- Investigation queue
- Action history
- Temporary actions
- Reversed actions

## 12. Response Safety

The Response Agent does not blindly execute every recommendation.

Safety checks include:

- Protected targets
- Risk thresholds
- Confidence thresholds
- Human approval
- Cooldowns
- Duplicate suppression
- Action expiry
- Reversal support
- Audit logging

High-impact actions such as distributed IP blocking and process quarantine may require approval.

AI-only anomalies are generally sent for investigation instead of automatic containment.

## 13. Trusted Response Targets

AI windows can contain both malicious and normal activity.

Therefore, all source entities stored in an incident are considered evidence, but not every source is treated as a confirmed attacker.

Automatic containment targets are selected only from matching rule-based alerts.

This prevents normal IP addresses that appeared in the same AI window from being blocked or rate-limited.

## 14. Persistence Layer

SQLite stores the security workflow.

Stored records include:

- Events
- Alerts
- Incidents
- Analyses
- Decisions
- Responses
- Audit records

Persistence allows the dashboard and API to retrieve historical security information after processing finishes.

Runtime database files are excluded from Git.

## 15. FastAPI Backend

FastAPI exposes stored security information through REST endpoints.

The API provides access to:

- Statistics
- Events
- Alerts
- Incidents
- Incident details
- Analyses
- Decisions
- Responses
- Audit records

FastAPI also provides interactive OpenAPI documentation.

## 16. React Dashboard

The dashboard retrieves data from the FastAPI backend.

It displays:

- Security statistics
- Recent events
- Alerts
- Correlated incidents
- Risk analysis
- Response decisions
- Simulated actions
- Audit history

The dashboard refreshes periodically and reports backend connection errors to the user.

## 17. Central Configuration

Security and simulation settings are stored in:

```text
config/security_config.json
```

Centralized settings control:

- Rule thresholds
- Time windows
- AI window size
- Normal-event ranges
- Attack intensity
- Simulation delays
- Live attack probability

Configuration validation prevents invalid settings from silently changing system behaviour.

## 18. Failure Handling

The pipeline uses defensive failure handling.

- Malformed events are rejected.
- Detector or agent failures are recorded.
- Pipeline errors do not terminate the complete simulator.
- AI flush errors are contained.
- Duplicate responses are suppressed.
- Generated files are separated from source code.

## 19. Testing Strategy

The project contains automated tests for:

- Rule detectors
- Feature extraction
- Dataset construction
- Model loading
- AI windows
- Alert schemas
- Alert normalization
- Incident correlation
- Agent messaging
- Analysis decisions
- Response safety
- Persistence
- API endpoints
- Simulator scenarios
- Event validation
- Failure isolation
- End-to-end response flow

The current verified Python suite contains 271 passing tests.

The React dashboard contains six passing frontend tests and also passes linting and production build checks.

## 20. Design Limitations

The current implementation is intentionally designed as a safe simulation.

It does not:

- Monitor real network packets
- Modify firewall rules
- Terminate real processes
- Connect to real endpoint-security software
- Use a production threat-intelligence source
- Guarantee production-level attack detection

These capabilities remain future extensions and would require strict authorization and additional security controls.

