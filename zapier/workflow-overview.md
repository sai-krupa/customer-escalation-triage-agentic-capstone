# Zapier Workflow

## Purpose

The Zapier workflows coordinate the customer escalation triage process and connect automation, AI processing, human review, and logging.

## Workflow Components

### Orchestrator

Coordinates incoming escalation information and starts the processing workflow.

### Classification and Severity

Analyzes incoming escalation information and determines classification and severity.

### Routing

Produces a routing recommendation based on the classification and workflow rules.

### Human Review

Escalations requiring human judgment are routed for review.

### Reply Sender

Handles approved customer-response actions through the controlled workflow.

### Logging

Records workflow state and decisions for auditability.

## Human-in-the-Loop

Human review is intentionally retained for cases where automation should not make the final decision independently.
