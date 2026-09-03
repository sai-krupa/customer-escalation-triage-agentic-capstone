# Customer Escalation Triage — Agentic AI Capstone

An AI-powered customer escalation triage workflow designed to reduce manual processing effort while maintaining human oversight, structured logging, routing controls, and measurable evaluation.

## Project Overview

Customer escalation handling often involves repetitive classification, severity assessment, routing, tracking, and response preparation.

This project demonstrates a hybrid automation approach where AI agents and workflow automation handle defined tasks while humans retain control over important decisions and exceptions.

## Business Impact

| Metric | Baseline | Target | Improvement |
|---|---:|---:|---:|
| Processing time / escalation | ~15 min | <5 min | ~67% faster |
| Analyst effort | ~25 hrs/week | ~10 hrs/week | ~60% reduction |
| Classification | Manual | Automated | Reduced repetitive work |
| Routing | Manual | Rule-based recommendation | More consistent |
| Audit | Partial | Structured table state | Improved traceability |
| Customer response | Manual | Approved automated workflow | Controlled execution |

### Estimated Capacity Savings

Approximately 15 analyst hours reclaimed per week.

Approximately 780 hours of annual analyst capacity.

## Architecture

The workflow combines:

- Zapier automation
- AI-powered classification
- Severity assessment
- Rule-based routing recommendations
- Human-in-the-loop review
- Python processing
- Slack coordination
- Structured workflow logging
- Evaluation and regression testing
- Controlled customer responses

## Workflow

Customer Escalation -> Orchestrator -> Classification -> Severity Assessment -> Routing Recommendation -> Human Review -> Response -> Audit Logging

## Key Design Principles

### Human-in-the-Loop

Automation supports analysts rather than removing human control from important escalation decisions.

### Traceability

Workflow state and decisions are logged to support auditability.

### Controlled Automation

Automated customer responses require the appropriate workflow conditions and approval controls.

### Evaluation

The workflow includes test cases and regression checks to validate expected behavior.

## Repository Structure

```text
docs/
  project-overview.md
  workflow-architecture.md
  business-value.md
  governance-and-safety.md

python-agent/
  escalation_agent.py
  requirements.txt
  README.md

zapier/
  workflow-overview.md
  orchestrator.md
  severity-routing.md
  reply-sender.md

evaluation/
  test-cases.md
  regression-tests.md
  results.md

evidence/
  screenshots/
  diagrams/
  presentation/

sample-data/
