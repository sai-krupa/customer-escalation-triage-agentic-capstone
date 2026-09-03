"""
Escalation Processor - Input Validation and Business Logic
Handles escalation input validation, processing, and output formatting.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from escalation_intelligence_util import EscalationAnalyzer, TriageResult

logger = logging.getLogger(__name__)


@dataclass
class EscalationInput:
    """Validated escalation input data."""
    escalation_id: str
    slack_thread_id: Optional[str]
    customer_email: str
    account_tier: str
    issue_category: str
    issue_summary: str
    customer_impact: str
    urgency_signals: List[str]
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EscalationInput":
        """Create from dictionary with validation."""
        # Required fields
        required_fields = [
            "escalation_id",
            "customer_email",
            "account_tier",
            "issue_category",
            "issue_summary",
        ]

        missing_fields = [f for f in required_fields if f not in data or not data[f]]
        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

        # Handle optional fields with defaults
        slack_thread_id = data.get("slack_thread_id")
        customer_impact = data.get("customer_impact", "")
        urgency_signals = data.get("urgency_signals", [])
        timestamp = data.get("timestamp")

        # Use current time if timestamp not provided
        if not timestamp:
            timestamp = datetime.utcnow().isoformat() + "Z"

        # Validate types
        if not isinstance(urgency_signals, list):
            urgency_signals = [str(urgency_signals)] if urgency_signals else []

        # Validate account tier
        valid_tiers = ["enterprise", "premium", "standard", "free"]
        if data.get("account_tier", "").lower() not in valid_tiers:
            raise ValueError(
                f"Invalid account_tier. Must be one of: {', '.join(valid_tiers)}"
            )

        return cls(
            escalation_id=str(data["escalation_id"]).strip(),
            slack_thread_id=slack_thread_id,
            customer_email=str(data["customer_email"]).strip(),
            account_tier=str(data["account_tier"]).strip().lower(),
            issue_category=str(data["issue_category"]).strip(),
            issue_summary=str(data["issue_summary"]).strip(),
            customer_impact=str(customer_impact).strip(),
            urgency_signals=[str(s).strip() for s in urgency_signals if s],
            timestamp=timestamp,
        )


class EscalationProcessor:
    """Main processor for escalation triage."""

    def __init__(self):
        """Initialize processor with analyzer."""
        self.analyzer = EscalationAnalyzer()
        logger.info("EscalationProcessor initialized")

    def process_escalation(self, escalation_data: Dict[str, Any]) -> TriageResult:
        """
        Process escalation from raw input.

        Args:
            escalation_data: Dictionary with escalation details

        Returns:
            TriageResult with triage analysis

        Raises:
            ValueError: If input validation fails
        """
        try:
            # Validate and parse input
            escalation_input = EscalationInput.from_dict(escalation_data)
            logger.info(
                f"Processing escalation {escalation_input.escalation_id} "
                f"(tier: {escalation_input.account_tier})"
            )

            # Analyze escalation
            result = self.analyzer.analyze(
                escalation_id=escalation_input.escalation_id,
                slack_thread_id=escalation_input.slack_thread_id,
                customer_email=escalation_input.customer_email,
                account_tier=escalation_input.account_tier,
                issue_category=escalation_input.issue_category,
                issue_summary=escalation_input.issue_summary,
                customer_impact=escalation_input.customer_impact,
                urgency_signals=escalation_input.urgency_signals,
                timestamp=escalation_input.timestamp,
            )

            logger.info(
                f"Escalation {escalation_input.escalation_id} triaged: "
                f"{result.severity_level} (score: {result.severity_score})"
            )

            return result

        except ValueError as e:
            logger.error(f"Input validation error: {e}")
            raise
        except Exception as e:
            logger.error(f"Processing error: {e}", exc_info=True)
            raise

    def format_for_slack(self, result: TriageResult) -> Dict[str, Any]:
        """
        Format triage result for Slack thread reply.

        Args:
            result: TriageResult from analysis

        Returns:
            Dictionary with Slack blocks and text
        """
        # Color coding for severity
        color_map = {
            "P1": "#FF0000",  # Red
            "P2": "#FFA500",  # Orange
            "P3": "#FFFF00",  # Yellow
            "P4": "#00AA00",  # Green
        }

        color = color_map.get(result.severity_level, "#808080")

        # Build blocks
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Escalation Triage Analysis - {result.severity_level}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Escalation ID:*\n{result.escalation_id}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity Score:*\n{result.severity_score}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Confidence Score:*\n{result.confidence_score}/100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity Level:*\n{result.severity_level}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Response Priority:*\n{result.response_priority.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Account Risk:*\n{result.account_risk_level.upper()}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Human Review:*\n{'✅ YES' if result.human_review_required else '⏭️ NO'}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Approval Required:*\n{'✅ YES' if result.approval_required else '⏭️ NO'}",
                    },
                ],
            },
            {
                "type": "divider",
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Approval Status:*\n{result.approval_status.upper()}\n\n*Approval Reason:*\n{result.approval_reason}",
                },
            },
            {
                "type": "divider",
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Team:*\n{result.recommended_team.replace('_', ' ').title()}",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Action:*\n{result.recommended_action}",
                },
            },
        ]

        # Add risk factors if any detected
        risk_summary = self._format_risk_factors(result.risk_factors)
        if risk_summary:
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Risk Factors:*\n{risk_summary}",
                    },
                }
            )

        # Add scoring breakdown
        scoring_summary = self._format_scoring(result.scoring_breakdown)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Scoring Breakdown:*\n{scoring_summary}",
                },
            }
        )

        # Add audit trail summary
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Explanation:*\n{result.explanation}",
                },
            }
        )

        # Add footer with timestamp
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Analysis timestamp: {result.timestamp}",
                    }
                ],
            }
        )

        return {
            "blocks": blocks,
            "text": f"Escalation triaged as {result.severity_level}: {result.recommended_action}",
        }

    def _format_risk_factors(self, risk_factors: Dict[str, Any]) -> str:
        """Format risk factors for display."""
        risks = []
        if risk_factors.get("financial_risk"):
            risks.append("• Financial Risk")
        if risk_factors.get("security_risk"):
            risks.append("• Security Risk")
        if risk_factors.get("operational_risk"):
            risks.append("• Operational Risk")
        if risk_factors.get("churn_risk"):
            risks.append("• Churn Risk")
        if risk_factors.get("multi_customer_impact"):
            risks.append("• Multi-Customer Impact")

        return "\n".join(risks) if risks else "None detected"

    def _format_scoring(self, scoring: Dict[str, int]) -> str:
        """Format scoring breakdown for display."""
        lines = []
        if scoring["production_outage"]:
            lines.append(f"• Production Outage: +{scoring['production_outage']}")
        if scoring["multiple_customers"]:
            lines.append(f"• Multiple Customers: +{scoring['multiple_customers']}")
        if scoring["payment_or_security"]:
            lines.append(f"• Payment/Security: +{scoring['payment_or_security']}")
        if scoring["enterprise_account"]:
            lines.append(f"• Enterprise Account: +{scoring['enterprise_account']}")
        if scoring["churn_risk"]:
            lines.append(f"• Churn Risk: +{scoring['churn_risk']}")
        if scoring["revenue_impact"]:
            lines.append(f"• Revenue Impact: +{scoring['revenue_impact']}")
        if scoring["urgency_keywords"]:
            lines.append(f"• Urgency Keywords: +{scoring['urgency_keywords']}")
        if scoring.get("enterprise_security_bonus"):
            lines.append(f"• Enterprise Security Bonus: +{scoring['enterprise_security_bonus']}")

        lines.append(f"\n*Total: {scoring['total']}/100*")
        return "\n".join(lines)

    def format_for_cli(self, result: TriageResult) -> str:
        """
        Format triage result for CLI output.

        Args:
            result: TriageResult from analysis

        Returns:
            Formatted string for CLI display
        """
        output = []
        output.append("\n" + "=" * 70)
        output.append("ESCALATION TRIAGE ANALYSIS REPORT")
        output.append("=" * 70)

        output.append(f"\nEscalation ID:        {result.escalation_id}")
        output.append(f"Severity Score:       {result.severity_score}/100")
        output.append(f"Severity Level:       {result.severity_level}")
        output.append(f"Confidence Score:     {result.confidence_score}/100")
        output.append(f"Response Priority:    {result.response_priority.upper()}")
        output.append(f"Account Risk Level:   {result.account_risk_level.upper()}")
        output.append(
            f"Human Review Required: {'YES ✅' if result.human_review_required else 'NO ⏭️'}"
        )

        # APPROVAL SECTION (NEW)
        output.append("")
        output.append("-" * 70)
        output.append("APPROVAL DECISION")
        output.append("-" * 70)
        output.append(f"Approval Required:    {'YES ✅' if result.approval_required else 'NO ⏭️'}")
        output.append(f"Approval Status:      {result.approval_status.upper()}")
        if result.approval_reason:
            output.append(f"Approval Reason:      {result.approval_reason}")

        output.append(f"\nRecommended Team:     {result.recommended_team.replace('_', ' ').title()}")

        output.append("\n" + "-" * 70)
        output.append("SCORING BREAKDOWN")
        output.append("-" * 70)

        scoring = result.scoring_breakdown
        if scoring["production_outage"]:
            output.append(
                f"  Production Outage ...................... +{scoring['production_outage']}"
            )
        if scoring["multiple_customers"]:
            output.append(
                f"  Multiple Customers Affected ............ +{scoring['multiple_customers']}"
            )
        if scoring["payment_or_security"]:
            output.append(
                f"  Payment/Security Issue ................. +{scoring['payment_or_security']}"
            )
        if scoring["enterprise_account"]:
            output.append(
                f"  Enterprise Account ..................... +{scoring['enterprise_account']}"
            )
        if scoring["churn_risk"]:
            output.append(f"  Churn Risk .............................. +{scoring['churn_risk']}")
        if scoring["revenue_impact"]:
            output.append(f"  Revenue Impact .......................... +{scoring['revenue_impact']}")
        if scoring["urgency_keywords"]:
            output.append(
                f"  Critical Urgency Keywords .............. +{scoring['urgency_keywords']}"
            )
        if scoring.get("enterprise_security_bonus"):
            output.append(
                f"  Enterprise Security Bonus ............. +{scoring['enterprise_security_bonus']}"
            )

        output.append(f"  {'─' * 68}")
        output.append(f"  TOTAL SCORE ............................ {scoring['total']}/100")

        output.append("\n" + "-" * 70)
        output.append("RISK FACTORS")
        output.append("-" * 70)

        risk_factors = result.risk_factors
        output.append(f"  Financial Risk:        {'✅ DETECTED' if risk_factors.get('financial_risk') else '❌ None'}")
        output.append(f"  Security Risk:         {'✅ DETECTED' if risk_factors.get('security_risk') else '❌ None'}")
        output.append(f"  Operational Risk:      {'✅ DETECTED' if risk_factors.get('operational_risk') else '❌ None'}")
        output.append(f"  Churn Risk:            {'✅ DETECTED' if risk_factors.get('churn_risk') else '❌ None'}")
        output.append(f"  Multi-Customer Impact: {'✅ YES' if risk_factors.get('multi_customer_impact') else '❌ No'}")

        output.append("\n" + "-" * 70)
        output.append("RECOMMENDED ACTION")
        output.append("-" * 70)
        output.append(result.recommended_action)

        output.append("\n" + "-" * 70)
        output.append("EXPLANATION")
        output.append("-" * 70)
        output.append(result.explanation)

        output.append("\n" + "-" * 70)
        output.append("AUDIT TRAIL")
        output.append("-" * 70)
        for entry in result.audit_trail:
            output.append(f"  [{entry['category'].upper()}] {entry['description']}")
            output.append(f"    Details: {entry['details']}")

        output.append("\n" + "=" * 70)
        output.append(f"Generated: {result.timestamp}")
        output.append("=" * 70 + "\n")

        return "\n".join(output)
