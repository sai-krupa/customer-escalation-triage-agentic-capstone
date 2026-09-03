# Customer Escalation Triage — Agentic Workflow

An agentic customer escalation triage workflow that combines Zapier, Python, Slack, Gmail, and Zapier Tables to automate escalation intake, severity analysis, routing recommendations, human approval, and controlled customer communication.

## Project Overview

This project demonstrates a human-in-the-loop agentic workflow for handling customer escalations.

The workflow reduces repetitive manual triage work while maintaining human oversight before customer communication.

The system uses three Zaps coordinated through Slack and Zapier Tables, with a Python-based escalation intelligence agent providing structured analysis.

## Architecture

### Zap 1 — Intake & Orchestration

**Gmail → AI Extraction → Zapier Tables → Slack**

1. Receives a new customer email.
2. Filters out sent messages.
3. Uses AI to extract structured escalation information.
4. Creates the escalation record in Zapier Tables.
5. Posts a `NEW CUSTOMER ESCALATION` notification to Slack.
6. Stores the Slack timestamp with the escalation record.

### Zap 2 — Severity, Routing & Approval

**Slack → Table Lookup → Python Agent → Table Update → Slack Approval**

1. Detects a new escalation notification in Slack.
2. Extracts the escalation ID.
3. Retrieves the corresponding record from Zapier Tables.
4. Sends the escalation information to the Python agent.
5. Python analyzes severity, confidence, risk, routing, and review requirements.
6. The results are written back to Zapier Tables.
7. Slack requests human approval.
8. The approval state is recorded for downstream control.

### Python Escalation Intelligence Agent

The Python agent provides deterministic escalation analysis.

It evaluates escalation information and produces structured results including:

- Severity
- Score
- Confidence
- Risk
- Recommended routing
- Human-review requirement
- Approval requirement
- Explanation
- Audit information

### Zap 3 — Controlled Customer Reply

**Slack `__REPLY__` → Approval Validation → Gmail → Table Update**

1. Detects an approved reply request.
2. Extracts the escalation ID.
3. Retrieves the escalation record.
4. Validates the required approval state.
5. Validates communication status to prevent duplicate sending.
6. Removes the internal `__REPLY__` marker.
7. Sends the controlled customer response through Gmail.
8. Updates the escalation record with completion and communication status.

## End-to-End Flow

```text
Customer Email
      ↓
   Zap 1
      ↓
AI Structured Extraction
      ↓
Zapier Tables
      ↓
     Slack
      ↓
   Zap 2
      ↓
Python Escalation Agent
      ↓
Severity / Risk / Routing
      ↓
Human Approval
      ↓
   Zap 3
      ↓
Approval Validation
      ↓
Customer Reply
      ↓
Zapier Tables Audit State
