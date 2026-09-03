"""
Escalation Intelligence Analyzer - Point-Based Scoring
Deterministic, audit-friendly severity assessment for customer escalations.

Scoring System (Point-Based):
- Production outage: +40
- Multiple customers affected: +25
- Payment failure or security issue: +25
- Enterprise account: +20
- Churn-risk indicator: +20
- Revenue impact: +15
- Critical urgency keywords: +10

Severity Levels:
- P1 Critical: 80-100
- P2 High: 60-79
- P3 Medium: 30-59
- P4 Low: 0-29
"""

import json
import re
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Set

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Severity priority levels."""
    P1_CRITICAL = "P1"
    P2_HIGH = "P2"
    P3_MEDIUM = "P3"
    P4_LOW = "P4"


class AccountTier(Enum):
    """Customer account tiers."""
    ENTERPRISE = "enterprise"
    PREMIUM = "premium"
    STANDARD = "standard"
    FREE = "free"


@dataclass
class ScoringBreakdown:
    """Detailed breakdown of severity score calculation."""
    production_outage: int = 0  # +40
    multiple_customers: int = 0  # +25
    payment_or_security: int = 0  # +25
    enterprise_account: int = 0  # +20
    churn_risk: int = 0  # +20
    revenue_impact: int = 0  # +15
    urgency_keywords: int = 0  # +10
    enterprise_security_bonus: int = 0  # +25 (only for enterprise security incidents)
    total: int = field(init=False)

    def __post_init__(self):
        """Calculate total score."""
        self.recalculate_total()

    def recalculate_total(self):
        """Recalculate total score."""
        self.total = (
            self.production_outage
            + self.multiple_customers
            + self.payment_or_security
            + self.enterprise_account
            + self.churn_risk
            + self.revenue_impact
            + self.urgency_keywords
            + self.enterprise_security_bonus
        )

    def to_dict(self) -> Dict[str, int]:
        """Convert to dictionary."""
        self.recalculate_total()
        return asdict(self)


@dataclass
class RiskFactors:
    """Risk assessment dimensions."""
    account_risk: str  # "high", "medium", "low"
    financial_risk: bool  # True if payment/billing involved
    security_risk: bool  # True if security issue
    operational_risk: bool  # True if production impact
    churn_risk: bool  # True if customer may leave
    multi_customer_impact: bool  # True if multiple customers affected


@dataclass
class AuditEntry:
    """Single audit trail entry documenting decision reasoning."""
    timestamp: str
    category: str  # "scoring", "routing", "human_review", etc.
    description: str
    details: str
    impact_points: int = 0


@dataclass
class TriageResult:
    """Complete escalation triage analysis result."""
    escalation_id: str
    severity_score: int  # 0-100
    severity_level: str  # "P1", "P2", "P3", "P4"
    account_risk_level: str  # "high", "medium", "low"
    response_priority: str  # "immediate", "urgent", "standard", "low"
    risk_factors: Dict[str, bool]
    recommended_team: str  # escalation team
    human_review_required: bool
    recommended_action: str
    explanation: str
    scoring_breakdown: Dict[str, int]
    audit_trail: List[Dict[str, Any]]
    timestamp: str
    slack_thread_id: Optional[str] = None
    confidence_score: int = 0  # 0-100, based on input completeness and clarity
    # Approval workflow metadata (NEW - for Zapier/Slack workflow integration)
    approval_required: bool = False
    approval_status: str = "not_required"  # "not_required" | "pending" | "approved" | "rejected"
    approval_reason: str = ""
    approval_triggers: List[str] = field(default_factory=list)  # Array of enum-style trigger strings
    approver_id: Optional[str] = None
    approval_timestamp: Optional[str] = None
    approval_comments: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class EscalationAnalyzer:
    """Core point-based triage intelligence engine."""

    # Keywords for production outage detection
    # Expanded to recognize: production issue, production incident, production environment,
    # production users affected, service unavailable, system unavailable, cannot operate,
    # customers cannot complete payments, payment service unavailable
    PRODUCTION_OUTAGE_KEYWORDS = {
        # Original patterns - service/system availability
        r"\b(service|system|platform).*\b(down|outage|offline|crashed|stopped)\b",
        r"\b(production|live|prod).*\b(down|outage|offline|crash|broken)\b",
        r"\b(production|service|platform)\s+(down|outage|offline|crashed|unavailable)\b",
        r"\b(complete|total|full).*\b(outage|service.*down|system.*down)\b",
        # New patterns - production-specific issues and incidents
        r"\b(production|prod|live)\s+(issue|incident|problem)\b",
        r"\b(production|prod|live)\s+(environment|users?)\s+",
        r"\b(service|system)\s+unavailable\b",
        r"\bpayment\s+service\s+unavailable\b",
        # New patterns - inability to operate/function
        r"\b(customers?|users?)\s+(cannot|can't|unable to)\b.*\b(operate|function|work|proceed|complete)\b",
        r"\b(cannot|can't|unable to)\s+(operate|function|work|proceed)\b",
        # New patterns - specific to payment operations in production
        r"\b(production|prod).*\b(payment|checkout|transaction).*\b(fail|issue|problem|unavailable)\b",
        r"\b(customers?|users?)\s+(cannot|can't)\s+complete\s+(payments?|checkout|transactions?)\b",
    }

    # Keywords for multiple customers affected
    MULTIPLE_CUSTOMERS_KEYWORDS = {
        r"\b(all users|all customers|multiple users|multiple customers|widespread)\b",
        r"\b(affecting (all|multiple|many))\b",
        r"\b(affecting \d+ (users|customers))\b",
        r"\b(breach|compromise).*\b(database|system|platform|records|customers)\b",
        r"\b(production).*\b(breach|compromise|data\s+leak|exposed)\b",
    }

    # Keywords for payment failures (explicit payment-related issues)
    # Expanded to recognize: cannot complete payments, payments cannot be processed,
    # payment processing failed, checkout failed, payment issue, payment problem,
    # transaction failure, transaction cannot be completed
    PAYMENT_FAILURE_KEYWORDS = {
        # Original patterns
        r"\b(payment|billing|transaction|charge|refund|invoice)\s+(failed|declined|error|issue|rejected)\b",
        r"\b(failed|declined)\s+(payment|billing|charge|transaction|card)\b",
        r"\b(payment|billing|subscription).*\b(problem|failure|error|issue)\b",
        r"\b(unable to|can't)\s+(charge|process payment|bill|collect)\b",
        # New patterns - cannot complete payments
        r"\b(cannot|can't|unable to)\s+complete\s+(payments?|checkout|transactions?)\b",
        # New patterns - payments cannot be processed
        r"\b(payments?|billing|transactions?)\s+(cannot|can't|unable to|cannot be)\s+processed?\b",
        # New patterns - payment processing failed
        r"\b(payment|transaction)\s+processing\s+(failed|failure|error|issue)\b",
        # New patterns - checkout failed
        r"\bcheckout\s+(failed|failure|error|issue)\b",
        # New patterns - payment/transaction issue or problem
        r"\b(payment|transaction|billing)\b.*\b(issue|problem|failure)\b",
        # New patterns - transaction failure/cannot be completed
        r"\btransaction\s+(failure|failed|cannot|can't)\b",
        r"\b(unable to|cannot|can't)\s+complete\s+(transactions?)\b",
    }

    # Keywords for security issues (explicit security-related issues)
    SECURITY_ISSUE_KEYWORDS = {
        r"\b(security|breach|hack|vulnerability|unauthorized|attack|intrusion)\b",
        r"\b(data|pii|personal information|credentials).*\b(breach|leak|exposed|compromised|stolen)\b",
        r"\b(unauthorized|suspicious).*\b(access|activity|login|request)\b",
        r"\b(breach|vulnerability|exploit|attack).*\b(data|system|database|account)\b",
    }

    # Keywords for churn risk
    CHURN_RISK_KEYWORDS = {
        r"\b(cancel|switch|competitor|alternative|leave|migrate)\b",
        r"\b(renewal|renewal at risk|contract)\b",
        r"\b(unhappy|frustrated|angry|very upset|threatening to leave)\b",
        r"\b(will.*be.*suspended|service.*will.*be.*disabled|subscription.*will.*end)\b",
    }

    # Keywords for revenue impact
    REVENUE_IMPACT_KEYWORDS = {
        r"\b(\$[\d,]+k?|\$\d+)\b",  # Money amounts
        r"\b(revenue|income|sales|deal|contract|financial|loss|impact)\b",
        r"\b(major customer|key account|vip|strategic|enterprise customer)\b",
        r"\b(regulatory|compliance|hipaa|pci|legal|notification|required)\b",
        r"\b(payment|billing|subscription).*\b(failure|failed|declined|error|issue)\b",
    }

    # Critical urgency keywords
    CRITICAL_URGENCY_KEYWORDS = {
        r"\b(urgent|critical|emergency|immediately|asap|right now)\b",
        r"\b(blocking|blocked|stopped|halted)\b",
        r"\b(ceo|executive|board|investor)\b",
    }

    def __init__(self):
        """Initialize analyzer."""
        self.audit_trail: List[AuditEntry] = []

    def _calculate_confidence_score(
        self,
        escalation_id: str,
        customer_email: str,
        account_tier: str,
        issue_summary: str,
        customer_impact: str,
        urgency_signals: List[str],
    ) -> int:
        """
        Calculate confidence score (0-100) based on input completeness and clarity.

        Scoring criteria:
        - Base: 50 points
        - Valid escalation_id: +5 points
        - Valid customer_email: +5 points
        - Valid account_tier: +5 points
        - Issue summary present and adequate length (>20 chars): +10 points
        - Customer impact present and adequate length (>20 chars): +10 points
        - Urgency signals provided: +5 points
        - All required fields present: +5 points

        Returns:
            Confidence score from 0-100
        """
        score = 50  # Base score

        # Escalation ID present and non-empty
        if escalation_id and len(str(escalation_id).strip()) > 0:
            score += 5

        # Email present and looks valid
        if customer_email and len(str(customer_email).strip()) > 3 and "@" in customer_email:
            score += 5

        # Account tier present and valid
        valid_tiers = ["enterprise", "premium", "standard", "free"]
        if account_tier and account_tier.lower() in valid_tiers:
            score += 5

        # Issue summary present with adequate detail
        if issue_summary and len(str(issue_summary).strip()) > 20:
            score += 10

        # Customer impact present with adequate detail
        if customer_impact and len(str(customer_impact).strip()) > 20:
            score += 10

        # Urgency signals provided
        if urgency_signals and len(urgency_signals) > 0:
            score += 5

        # Bonus for all required fields present
        required_present = (
            escalation_id
            and customer_email
            and account_tier
            and issue_summary
        )
        if required_present:
            score += 5

        # Cap at 100
        return min(score, 100)

    def analyze(
        self,
        escalation_id: str,
        slack_thread_id: Optional[str],
        customer_email: str,
        account_tier: str,
        issue_category: str,
        issue_summary: str,
        customer_impact: str,
        urgency_signals: List[str],
        timestamp: str,
    ) -> TriageResult:
        """
        Analyze an escalation and generate triage recommendation.

        Args:
            escalation_id: Unique identifier for the escalation
            slack_thread_id: Slack thread ID (for replies)
            customer_email: Customer email address
            account_tier: "enterprise", "premium", "standard", "free"
            issue_category: Issue category (e.g., "billing", "technical", "account")
            issue_summary: Brief issue summary
            customer_impact: Description of customer impact
            urgency_signals: List of urgency indicators
            timestamp: ISO timestamp of escalation

        Returns:
            TriageResult with severity, risk, routing, and audit trail

        Raises:
            ValueError: If required fields are missing or invalid
        """
        # Validate inputs
        self._validate_inputs(
            escalation_id,
            customer_email,
            account_tier,
            issue_summary,
        )

        # Normalize inputs
        normalized_summary = self._normalize_text(issue_summary)
        normalized_impact = self._normalize_text(customer_impact)
        normalized_category = issue_category.lower()

        # Reset audit trail
        self.audit_trail = []

        # Calculate confidence score based on input completeness
        confidence_score = self._calculate_confidence_score(
            escalation_id,
            customer_email,
            account_tier,
            issue_summary,
            customer_impact,
            urgency_signals,
        )

        # Calculate severity score using point-based system
        scoring = self._calculate_severity_score(
            normalized_summary,
            normalized_impact,
            account_tier,
            urgency_signals,
            normalized_category,
        )

        # Recalculate total to ensure it's correct
        scoring.recalculate_total()

        # Determine severity level based on score
        severity_level = self._get_severity_level(scoring.total)

        # Assess risk factors
        risk_factors = self._assess_risk_factors(
            normalized_summary,
            normalized_impact,
            normalized_category,
            account_tier,
        )

        # Determine account risk level
        account_risk = self._calculate_account_risk(account_tier, risk_factors)

        # Determine response priority
        response_priority = self._get_response_priority(severity_level)

        # Determine recommended team
        recommended_team = self._determine_routing(
            normalized_category,
            risk_factors,
            severity_level,
        )

        # Determine if human review is required (including low confidence)
        human_review = self._requires_human_review(
            severity_level,
            risk_factors,
            account_tier,
            confidence_score,
        )

        # Determine if approval is required (NEW - for Zapier workflow)
        approval_required, approval_status, approval_reason, approval_triggers = self._requires_approval(
            severity_level=severity_level,
            risk_factors=risk_factors,
            account_tier=account_tier,
            confidence_score=confidence_score,
            issue_category=normalized_category,
            issue_summary=normalized_summary,
            customer_impact=normalized_impact,
        )

        # Generate recommended action
        recommended_action = self._generate_recommended_action(
            severity_level,
            risk_factors,
            recommended_team,
        )

        # Generate explanation
        explanation = self._generate_explanation(
            severity_level,
            scoring,
            risk_factors,
            recommended_team,
        )

        # Build result
        result = TriageResult(
            escalation_id=escalation_id,
            severity_score=min(scoring.total, 100),
            severity_level=severity_level,
            account_risk_level=account_risk,
            response_priority=response_priority,
            risk_factors=asdict(risk_factors),
            recommended_team=recommended_team,
            human_review_required=human_review,
            recommended_action=recommended_action,
            explanation=explanation,
            scoring_breakdown=scoring.to_dict(),
            audit_trail=[asdict(entry) for entry in self.audit_trail],
            timestamp=datetime.utcnow().isoformat() + "Z",
            slack_thread_id=slack_thread_id,
            confidence_score=confidence_score,
            # Approval workflow metadata (NEW)
            approval_required=approval_required,
            approval_status=approval_status,
            approval_reason=approval_reason,
            approval_triggers=approval_triggers,
            approver_id=None,  # Will be populated by Zapier when approved
            approval_timestamp=None,  # Will be populated by Zapier
            approval_comments=None,  # Will be populated by Zapier
        )

        return result

    def _validate_inputs(
        self,
        escalation_id: str,
        customer_email: str,
        account_tier: str,
        issue_summary: str,
    ):
        """Validate required input fields."""
        if not escalation_id or not isinstance(escalation_id, str):
            raise ValueError("escalation_id is required and must be a string")
        if not customer_email or not isinstance(customer_email, str):
            raise ValueError("customer_email is required and must be a string")
        if not account_tier or account_tier.lower() not in [
            "enterprise",
            "premium",
            "standard",
            "free",
        ]:
            raise ValueError(
                "account_tier must be one of: enterprise, premium, standard, free"
            )
        if not issue_summary or not isinstance(issue_summary, str):
            raise ValueError("issue_summary is required and must be a string")

        logger.info(f"Input validation passed for escalation {escalation_id}")

    def _normalize_text(self, text: str) -> str:
        """Normalize text for pattern matching."""
        text = text.lower().strip()
        text = re.sub(r"\s+", " ", text)
        return text

    def _calculate_severity_score(
        self,
        issue_summary: str,
        customer_impact: str,
        account_tier: str,
        urgency_signals: List[str],
        issue_category: str,
    ) -> ScoringBreakdown:
        """Calculate severity score using point-based system."""
        scoring = ScoringBreakdown()
        combined_text = f"{issue_summary} {customer_impact}".lower()

        # Check production outage (+40)
        if self._check_keywords(combined_text, self.PRODUCTION_OUTAGE_KEYWORDS):
            scoring.production_outage = 40
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Production outage detected",
                    details="Keywords match production/outage/down/offline pattern",
                    impact_points=40,
                )
            )

        # Check multiple customers affected (+25)
        if self._check_keywords(combined_text, self.MULTIPLE_CUSTOMERS_KEYWORDS):
            scoring.multiple_customers = 25
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Multiple customers affected",
                    details="Keywords match multiple/all customers pattern",
                    impact_points=25,
                )
            )

        # Check payment or security issue (+25)
        has_payment_issue = self._check_keywords(
            combined_text, self.PAYMENT_FAILURE_KEYWORDS
        ) and self._is_payment_category(issue_category)
        
        has_security_issue = self._check_keywords(
            combined_text, self.SECURITY_ISSUE_KEYWORDS
        ) and self._is_security_category(issue_category, combined_text)
        
        if has_payment_issue or has_security_issue:
            scoring.payment_or_security = 25
            issue_type = "Payment failure" if has_payment_issue else "Security issue"
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description=f"{issue_type} detected",
                    details=f"Issue category: {issue_category}",
                    impact_points=25,
                )
            )

        # Check enterprise account (+20)
        if account_tier.lower() == "enterprise":
            scoring.enterprise_account = 20
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Enterprise account",
                    details="Account tier is enterprise",
                    impact_points=20,
                )
            )

        # Check churn risk (+20)
        if self._check_keywords(combined_text, self.CHURN_RISK_KEYWORDS):
            scoring.churn_risk = 20
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Churn risk identified",
                    details="Keywords match churn/cancel/leave pattern",
                    impact_points=20,
                )
            )

        # Check revenue impact (+15)
        if self._check_keywords(combined_text, self.REVENUE_IMPACT_KEYWORDS):
            scoring.revenue_impact = 15
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Revenue impact detected",
                    details="Keywords match revenue/deal/strategic account pattern",
                    impact_points=15,
                )
            )

        # Check critical urgency keywords (+10)
        if self._check_keywords(
            combined_text, self.CRITICAL_URGENCY_KEYWORDS
        ) or (
            urgency_signals and len(urgency_signals) > 0
        ):
            scoring.urgency_keywords = 10
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Critical urgency signals",
                    details=f"Urgency signals: {', '.join(urgency_signals) if urgency_signals else 'keywords match urgent/critical pattern'}",
                    impact_points=10,
                )
            )

        # Check enterprise security incident bonus (+25)
        # Enterprise customers with security breaches get additional bonus to ensure P2/P1
        if account_tier.lower() == "enterprise" and has_security_issue:
            scoring.enterprise_security_bonus = 25
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="scoring",
                    description="Enterprise security incident bonus",
                    details="Additional +25 bonus for enterprise account with security breach (ensures P2/P1 classification)",
                    impact_points=25,
                )
            )

        logger.debug(f"Severity score calculated: {scoring.total}/100")
        return scoring

    def _check_keywords(self, text: str, keyword_patterns: Set[str]) -> bool:
        """Check if any keyword pattern matches the text."""
        for pattern in keyword_patterns:
            if re.search(pattern, text):
                return True
        return False

    def _is_payment_category(self, issue_category: str) -> bool:
        """Check if issue is payment/billing related."""
        payment_categories = {"billing", "payment", "subscription", "invoice"}
        return any(
            cat in issue_category.lower() for cat in payment_categories
        )

    def _is_security_category(self, issue_category: str, text: str) -> bool:
        """Check if issue is security related."""
        security_categories = {"security", "data", "privacy", "compliance"}
        
        # Check if category explicitly mentions security
        category_match = any(
            cat in issue_category.lower() for cat in security_categories
        )
        
        # Or if text contains explicit security keywords with data/access
        explicit_security = bool(
            self._check_keywords(text, {
                r"\b(breach|hack|vulnerability|unauthorized access|intrusion|attack)\b"
            })
        )
        
        return category_match or explicit_security

    def _get_severity_level(self, score: int) -> str:
        """Map score to severity level."""
        if score >= 80:
            return "P1"
        elif score >= 60:
            return "P2"
        elif score >= 30:
            return "P3"
        else:
            return "P4"

    def _assess_risk_factors(
        self,
        issue_summary: str,
        customer_impact: str,
        issue_category: str,
        account_tier: str,
    ) -> RiskFactors:
        """Assess risk factors from issue details."""
        combined_text = f"{issue_summary} {customer_impact}".lower()

        return RiskFactors(
            account_risk="high"
            if account_tier.lower() in ["enterprise", "premium"]
            else "medium" if account_tier.lower() == "standard" else "low",
            financial_risk=bool(
                self._check_keywords(
                    combined_text,
                    {
                        r"\b(payment|billing|transaction|charge|refund|invoice)\b",
                        r"\b(revenue|financial|loss)\b",
                    },
                )
            ),
            security_risk=bool(
                self._check_keywords(
                    combined_text,
                    {
                        r"\b(security|breach|hack|vulnerability|unauthorized|attack)\b",
                        r"\b(pii|personal information|data\s+(leak|breach|exposed)|exposed.*data)\b",
                    },
                )
            ),
            operational_risk=bool(
                self._check_keywords(
                    combined_text,
                    {r"\b(down|outage|offline|unavailable|broken|service\s+unavailable)\b"},
                )
            ),
            churn_risk=bool(
                self._check_keywords(
                    combined_text,
                    {
                        r"\b(cancel|leave|migrate|switch|competitor)\b",
                        r"\b(threatening|considering)\b",
                    },
                )
            ),
            multi_customer_impact=bool(
                self._check_keywords(
                    combined_text,
                    {r"\b(all|multiple|many|widespread)\s+(users|customers)\b"},
                )
            ),
        )

    def _calculate_account_risk(self, account_tier: str, risk_factors: RiskFactors) -> str:
        """Calculate account risk level."""
        if account_tier.lower() in ["enterprise", "premium"]:
            return "high"
        elif risk_factors.financial_risk or risk_factors.security_risk:
            return "high"
        elif account_tier.lower() == "standard" or risk_factors.operational_risk:
            return "medium"
        else:
            return "low"

    def _get_response_priority(self, severity_level: str) -> str:
        """Map severity level to response priority."""
        priority_map = {
            "P1": "immediate",
            "P2": "urgent",
            "P3": "standard",
            "P4": "low",
        }
        return priority_map.get(severity_level, "standard")

    def _determine_routing(
        self,
        issue_category: str,
        risk_factors: RiskFactors,
        severity_level: str,
    ) -> str:
        """
        Determine recommended team for escalation using priority-based rules.
        
        Priority order:
        1. Security issues → Security Team
        2. Production outages → Engineering Team
        3. Bug reports → Engineering Team
        4. Billing disputes → Billing Team
        5. Account issues → Customer Success Team
        6. Otherwise → Support Team
        """
        # Priority 1: Security issues always go to security team
        if risk_factors.security_risk:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="routing",
                    description="Routed to security team",
                    details="Security risk detected (Priority 1: Security)",
                )
            )
            return "security_team"

        # Priority 2: Production outages go to engineering team
        if risk_factors.operational_risk:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="routing",
                    description="Routed to engineering team",
                    details="Production/operational issue detected (Priority 2: Production Outage)",
                )
            )
            return "engineering_team"

        # Priority 3: Bug reports go to engineering team
        category_lower = issue_category.lower()
        if "bug" in category_lower or category_lower == "bug report":
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="routing",
                    description="Routed to engineering team",
                    details=f"Bug report detected (Priority 3: Bug Report) - Category: {issue_category}",
                )
            )
            return "engineering_team"

        # Priority 4: Billing disputes go to billing team
        billing_keywords = {
            "billing",
            "payment",
            "invoice",
            "subscription",
            "billing dispute",
            "payment dispute",
        }
        if any(keyword in category_lower for keyword in billing_keywords):
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="routing",
                    description="Routed to billing team",
                    details=f"Billing/payment issue detected (Priority 4: Billing Dispute) - Category: {issue_category}",
                )
            )
            return "billing_team"

        # Priority 5: Account issues go to customer success team
        account_keywords = {"account", "profile", "settings", "preferences"}
        if any(keyword in category_lower for keyword in account_keywords):
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="routing",
                    description="Routed to customer success team",
                    details=f"Account issue detected (Priority 5: Account Issues) - Category: {issue_category}",
                )
            )
            return "customer_success_team"

        # Default: Support team
        self.audit_trail.append(
            AuditEntry(
                timestamp=datetime.utcnow().isoformat() + "Z",
                category="routing",
                description="Routed to support team",
                details=f"Default routing (Priority 6: Support Team) - Category: {issue_category}",
            )
        )
        return "support_team"

    def _requires_human_review(
        self,
        severity_level: str,
        risk_factors: RiskFactors,
        account_tier: str,
        confidence_score: int = 100,
    ) -> bool:
        """Determine if human review is required."""
        # Low confidence always requires human review
        if confidence_score < 70:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="human_review",
                    description="Human review required - Low confidence",
                    details=f"Confidence score {confidence_score}/100 is below threshold (70)",
                )
            )
            return True

        # P1 and P2 always require human review
        if severity_level in ["P1", "P2"]:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="human_review",
                    description=f"Human review required for {severity_level}",
                    details="Severity level requires immediate human attention",
                )
            )
            return True

        # Financial or security issues always require human review
        if risk_factors.financial_risk or risk_factors.security_risk:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="human_review",
                    description="Human review required - Financial or Security risk",
                    details="Financial/security risks require human evaluation",
                )
            )
            return True

        # Enterprise accounts with operational issues
        if account_tier.lower() == "enterprise" and risk_factors.operational_risk:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="human_review",
                    description="Human review required - Enterprise operational issue",
                    details="Enterprise account with operational impact",
                )
            )
            return True

        # Churn risk requires human review
        if risk_factors.churn_risk:
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="human_review",
                    description="Human review required - Churn risk",
                    details="Customer churn risk detected",
                )
            )
            return True

        return False

    def _is_billing_dispute(self, issue_category: str, issue_summary: str, customer_impact: str) -> bool:
        """
        Detect billing/payment disputes using BOTH methods:
        1. Check issue_category for billing-related keywords
        2. Check issue_summary and customer_impact for payment keywords
        
        Returns True if this is likely a billing dispute that requires approval.
        """
        # METHOD 1: Check category
        billing_categories = {"billing", "payment", "invoice", "subscription", "billing dispute", "payment dispute"}
        category_match = any(cat in issue_category.lower() for cat in billing_categories)
        
        # METHOD 2: Check summary and impact for billing/payment keywords
        combined_text = f"{issue_summary} {customer_impact}".lower()
        billing_keywords = {
            r"\b(billing|payment|charge|charged|refund|invoice)\b",
            r"\b(subscription payment|payment failure|incorrect charge)\b",
            r"\b(cannot|can't)\s+(charge|process payment|bill|collect)\b",
        }
        keyword_match = self._check_keywords(combined_text, billing_keywords)
        
        return category_match or keyword_match

    def _is_security_incident(self, issue_category: str, issue_summary: str, customer_impact: str) -> bool:
        """
        Detect security incidents using BOTH methods:
        1. Check issue_category for security-related keywords
        2. Check issue_summary and customer_impact for clear security signals
        
        Returns True if this is a security incident that requires approval.
        """
        # METHOD 1: Check category
        security_categories = {"security", "data", "privacy", "compliance", "security incident"}
        category_match = any(cat in issue_category.lower() for cat in security_categories)
        
        # METHOD 2: Check summary and impact for explicit security keywords
        combined_text = f"{issue_summary} {customer_impact}".lower()
        security_keywords = {
            r"\b(security breach|unauthorized access|compromised account|suspicious access|data exposure|vulnerability|security incident)\b",
            r"\b(breach|hack|intrusion|attack)\b",
        }
        keyword_match = self._check_keywords(combined_text, security_keywords)
        
        return category_match or keyword_match

    def _requires_approval(
        self,
        severity_level: str,
        risk_factors: RiskFactors,
        account_tier: str,
        confidence_score: int,
        issue_category: str,
        issue_summary: str,
        customer_impact: str,
    ) -> tuple[bool, str, str, List[str]]:
        """
        Determine if human approval is required using HYBRID logic.
        
        APPROVAL REQUIRED IF ANY OF:
        1. P1 severity (critical)
        2. P2 severity (high)
        3. Security incident detected (category OR keywords)
        4. Billing dispute detected (category OR keywords)
        5. Churn signal detected
        6. Enterprise account
        7. Confidence score < 0.80 (80%)
        
        Also checks existing risk_factors for defense-in-depth (Option A).
        
        Returns:
            Tuple of (approval_required: bool, approval_status: str, approval_reason: str, approval_triggers: List[str])
            - approval_required: True if approval needed
            - approval_status: "pending" (needs approval) or "not_required" (no approval needed)
            - approval_reason: Human-readable explanation
            - approval_triggers: List of enum-style trigger strings (e.g., ["P1_CRITICAL", "ENTERPRISE_ACCOUNT"])
        """
        # Collect reasons and triggers
        reasons = []
        triggers = []
        approval_needed = False
        
        # RULE 1: P1 severity - always require approval
        if severity_level == "P1":
            reasons.append("P1 Critical escalation")
            triggers.append("P1_CRITICAL")
            approval_needed = True
        
        # RULE 2: P2 severity - always require approval
        elif severity_level == "P2":
            reasons.append("P2 High-severity escalation")
            triggers.append("P2_HIGH")
            approval_needed = True
        
        # RULE 3: Security incident - check both category and keywords (OPTION A: also check risk_factors)
        is_security_incident = self._is_security_incident(issue_category, issue_summary, customer_impact)
        if is_security_incident or risk_factors.security_risk:
            reasons.append("Security incident detected")
            triggers.append("SECURITY_INCIDENT")
            approval_needed = True
        
        # RULE 4: Billing dispute - check both category and keywords (OPTION A: also check risk_factors)
        is_billing_dispute = self._is_billing_dispute(issue_category, issue_summary, customer_impact)
        if is_billing_dispute or risk_factors.financial_risk:
            reasons.append("Billing/Payment dispute detected")
            triggers.append("BILLING_DISPUTE")
            approval_needed = True
        
        # RULE 5: Churn signal
        if risk_factors.churn_risk:
            reasons.append("Customer churn risk detected")
            triggers.append("CHURN_RISK")
            approval_needed = True
        
        # RULE 6: Enterprise account
        if account_tier.lower() == "enterprise":
            reasons.append("Enterprise account")
            triggers.append("ENTERPRISE_ACCOUNT")
            approval_needed = True
        
        # RULE 7: Low confidence score (< 0.80 = 80%)
        if confidence_score < 80:
            reasons.append(f"Low confidence score ({confidence_score}/100, threshold is 80)")
            triggers.append("LOW_CONFIDENCE")
            approval_needed = True
        
        # Build approval reason and status
        if approval_needed:
            approval_reason = "Approval required: " + "; ".join(reasons)
            approval_status = "pending"
            
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="approval",
                    description="Approval required",
                    details=approval_reason,
                )
            )
        else:
            approval_reason = "No approval required - routine low-risk request"
            approval_status = "not_required"
            
            self.audit_trail.append(
                AuditEntry(
                    timestamp=datetime.utcnow().isoformat() + "Z",
                    category="approval",
                    description="No approval required",
                    details="Request meets no high-risk approval criteria",
                )
            )
        
        logger.debug(f"Approval decision: required={approval_needed}, status={approval_status}, triggers={triggers}")
        return approval_needed, approval_status, approval_reason, triggers

    def _generate_recommended_action(
        self,
        severity_level: str,
        risk_factors: RiskFactors,
        team: str,
    ) -> str:
        """Generate recommended action based on severity, risk, and assigned team."""
        if severity_level == "P1":
            # P1 (Critical) - Immediate escalation based on team
            if team == "security_team":
                return "IMMEDIATE: Escalate to security team and management. Review access logs and implement containment measures. Notify compliance if required."
            elif team == "engineering_team":
                return "IMMEDIATE: Page on-call engineer. Start incident response. Communicate status to customer. Focus on service restoration."
            elif team == "billing_team":
                return "IMMEDIATE: Escalate to billing team and management. Resolve payment issue and offer compensatory gesture. Prevent revenue loss."
            elif team == "customer_success_team":
                return "IMMEDIATE: Escalate to customer success and management. Provide dedicated support and resolution plan."
            else:
                return "IMMEDIATE: Assign to management for direct handling. Aim for resolution within 1 hour."

        elif severity_level == "P2":
            # P2 (High) - Urgent escalation based on team
            if team == "security_team":
                return "URGENT: Assign to security team. Investigate and remediate within 4 hours. Document findings."
            elif team == "engineering_team":
                return "URGENT: Assign to engineering team. Investigate root cause and implement fix within 4 hours."
            elif team == "billing_team":
                if risk_factors.financial_risk:
                    return "URGENT: Assign to billing team. Resolve within 2 hours. Consider account credit or compensation."
                return "URGENT: Assign to billing team. Resolve within 4 hours."
            elif team == "customer_success_team":
                if risk_factors.churn_risk:
                    return "URGENT: Assign to success team. Proactive outreach and mitigation within 4 hours. Focus on retention."
                return "URGENT: Assign to customer success team. Resolve within 4 hours."
            else:
                return "URGENT: Assign to responsible team. Target resolution within 4-8 hours."

        elif severity_level == "P3":
            # P3 (Medium) - Standard escalation based on team
            if team == "engineering_team":
                return "Standard: Assign to engineering team. Investigate and fix within 24-48 hours."
            elif team == "billing_team":
                return "Standard: Assign to billing team. Resolve within 24 hours."
            elif team == "security_team":
                return "Standard: Assign to security team. Investigate within 24 hours."
            elif team == "customer_success_team":
                if risk_factors.churn_risk:
                    return "Standard: Assign to success team. Follow up within 24 hours. Monitor customer satisfaction."
                return "Standard: Assign to customer success team. Address within 24 hours."
            else:
                return "Standard: Assign to responsible team. Address within 24-48 hours."

        else:
            # P4 (Low) - Low priority
            return "Low priority: Handle in normal queue. Address within 5 business days."

    def _generate_explanation(
        self,
        severity_level: str,
        scoring: ScoringBreakdown,
        risk_factors: RiskFactors,
        team: str,
    ) -> str:
        """Generate human-readable explanation of the triage decision."""
        explanation_parts = []

        explanation_parts.append(
            f"Severity Level: {severity_level} (Score: {scoring.total}/100)"
        )
        explanation_parts.append("\nScoring Breakdown:")

        if scoring.production_outage:
            explanation_parts.append(f"  • Production Outage: +{scoring.production_outage}")
        if scoring.multiple_customers:
            explanation_parts.append(
                f"  • Multiple Customers Affected: +{scoring.multiple_customers}"
            )
        if scoring.payment_or_security:
            explanation_parts.append(
                f"  • Payment/Security Issue: +{scoring.payment_or_security}"
            )
        if scoring.enterprise_account:
            explanation_parts.append(
                f"  • Enterprise Account: +{scoring.enterprise_account}"
            )
        if scoring.churn_risk:
            explanation_parts.append(f"  • Churn Risk: +{scoring.churn_risk}")
        if scoring.revenue_impact:
            explanation_parts.append(f"  • Revenue Impact: +{scoring.revenue_impact}")
        if scoring.urgency_keywords:
            explanation_parts.append(
                f"  • Critical Urgency Signals: +{scoring.urgency_keywords}"
            )
        if scoring.enterprise_security_bonus:
            explanation_parts.append(
                f"  • Enterprise Security Bonus: +{scoring.enterprise_security_bonus}"
            )

        explanation_parts.append("\nRisk Factors:")
        if risk_factors.financial_risk:
            explanation_parts.append("  • Financial Risk: Detected")
        if risk_factors.security_risk:
            explanation_parts.append("  • Security Risk: Detected")
        if risk_factors.operational_risk:
            explanation_parts.append("  • Operational Risk: Detected")
        if risk_factors.churn_risk:
            explanation_parts.append("  • Churn Risk: Detected")
        if risk_factors.multi_customer_impact:
            explanation_parts.append("  • Multi-Customer Impact: Yes")

        explanation_parts.append(f"\nRecommended Team: {team}")

        return "\n".join(explanation_parts)
