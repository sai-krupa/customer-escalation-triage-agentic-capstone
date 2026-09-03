# Governance and Safety

## Human-in-the-Loop Controls

Human review is maintained for decisions that require additional judgment or present elevated risk.

## Audit Logging

Workflow decisions and relevant state changes are recorded to improve traceability.

## Routing Controls

Routing recommendations are rule-based and are not treated as unrestricted autonomous decisions.

## Response Controls

Customer responses follow an approved workflow rather than allowing uncontrolled automated communication.

## Data Protection

The project repository contains only synthetic or sanitized example information.

No passwords, API keys, authentication tokens, or confidential customer information should be committed to the repository.

## Access Control

Only the permissions required for the workflow should be granted to connected services.

## Failure Handling

When the workflow cannot confidently classify or route an escalation, the workflow should fall back to human review rather than making an unsupported automated decision.
