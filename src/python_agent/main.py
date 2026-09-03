"""
Escalation Intelligence Agent - CLI & Slack Integration
Main entry point for processing customer escalations.

Supports:
- CLI execution with JSON input (-f/--file or -j/--json)
- Programmatic JSON input mode (for Slack automation and integrations)
- Slack thread reply integration
- Structured logging
- Environment-based credentials (no credentials exposed in output)

JSON Input Mode (Programmatic API):
    Use json_input_mode(escalation_data: dict) -> str for direct Python integration.
    This is ideal for Slack automation, webhooks, and external integrations.
    
    Example:
        from main import json_input_mode
        escalation = {"escalation_id": "E123", "customer_email": "user@example.com", ...}
        result_json = json_input_mode(escalation)  # Returns JSON string
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from typing import Dict, Any, Optional

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from escalation_processor import EscalationProcessor
from escalation_intelligence_util import TriageResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("escalation_agent.log"),
    ],
)
logger = logging.getLogger(__name__)


class EscalationAgent:
    """Main escalation analysis agent."""

    def __init__(self, slack_token: Optional[str] = None):
        """
        Initialize the escalation agent.

        Args:
            slack_token: Slack bot token (from environment if not provided)
        """
        self.processor = EscalationProcessor()
        self.slack_client = None

        # Initialize Slack client if token provided
        if slack_token:
            self.slack_client = WebClient(token=slack_token)
            logger.info("Slack client initialized")
        else:
            logger.debug("No Slack token provided - Slack features disabled")

    @classmethod
    def from_env(cls) -> "EscalationAgent":
        """Create agent from environment variables."""
        slack_token = os.getenv("SLACK_BOT_TOKEN")
        if slack_token:
            logger.info("Using SLACK_BOT_TOKEN from environment")
        return cls(slack_token=slack_token)

    def process_escalation_json(self, json_data: str) -> TriageResult:
        """
        Process escalation from JSON string.

        Args:
            json_data: JSON string with escalation details

        Returns:
            TriageResult from analysis

        Raises:
            ValueError: If JSON is invalid or missing required fields
            json.JSONDecodeError: If JSON parsing fails
        """
        try:
            data = json.loads(json_data)
            logger.debug(f"Parsed JSON input: {json.dumps(data, indent=2)}")
            return self.processor.process_escalation(data)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON input: {e}")
            raise ValueError(f"Invalid JSON: {e}")

    def process_escalation_dict(self, data: Dict[str, Any]) -> TriageResult:
        """
        Process escalation from dictionary.

        Args:
            data: Dictionary with escalation details

        Returns:
            TriageResult from analysis
        """
        return self.processor.process_escalation(data)

    def process_escalation_file(self, file_path: str) -> TriageResult:
        """
        Process escalation from JSON file.

        Args:
            file_path: Path to JSON file with escalation data

        Returns:
            TriageResult from analysis

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If JSON is invalid
        """
        try:
            path = Path(file_path)
            if not path.exists():
                raise FileNotFoundError(f"File not found: {file_path}")

            with open(path, "r") as f:
                json_data = f.read()

            logger.info(f"Loaded escalation from {file_path}")
            return self.process_escalation_json(json_data)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")
            raise

    def post_to_slack_thread(
        self,
        channel_id: str,
        thread_ts: str,
        result: TriageResult,
    ) -> Optional[str]:
        """
        Post triage result to Slack thread.

        Args:
            channel_id: Slack channel ID
            thread_ts: Thread timestamp to reply to
            result: TriageResult from analysis

        Returns:
            Message timestamp if successful, None if Slack unavailable

        Raises:
            SlackApiError: If Slack API call fails
        """
        if not self.slack_client:
            logger.warning("Slack client not available - skipping thread reply")
            return None

        try:
            formatted = self.processor.format_for_slack(result)

            response = self.slack_client.chat_postMessage(
                channel=channel_id,
                thread_ts=thread_ts,
                blocks=formatted["blocks"],
                text=formatted["text"],
            )

            message_ts = response["ts"]
            logger.info(
                f"Posted triage result to Slack: channel={channel_id}, "
                f"thread={thread_ts}, message={message_ts}"
            )
            return message_ts

        except SlackApiError as e:
            logger.error(
                f"Failed to post to Slack: {e.response['error']}",
                exc_info=True,
            )
            raise

    def print_result(self, result: TriageResult) -> None:
        """
        Print triage result to console.

        Args:
            result: TriageResult from analysis
        """
        output = self.processor.format_for_cli(result)
        print(output)

    def save_result_json(self, result: TriageResult, file_path: str) -> None:
        """
        Save triage result to JSON file.

        Args:
            result: TriageResult from analysis
            file_path: Path to save JSON file
        """
        try:
            path = Path(file_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, "w") as f:
                f.write(result.to_json())

            logger.info(f"Saved result to {file_path}")
        except Exception as e:
            logger.error(f"Error saving result to {file_path}: {e}")
            raise


def json_input_mode(escalation_data: Dict[str, Any]) -> str:
    """
    JSON Input Mode - Programmatic API for Slack automation and integrations.
    
    This function processes escalation data and returns the triage result as JSON.
    It is designed for direct Python integration, webhooks, and external automation.
    
    IMPORTANT SECURITY NOTES:
    - This function NEVER exposes credentials (SLACK_BOT_TOKEN is NOT included in output)
    - Only the TriageResult is returned (see escalation_intelligence_util.py:TriageResult)
    - The function logs are sent to stderr only; output is pure JSON
    
    Args:
        escalation_data: Dictionary with escalation details matching EscalationInput contract:
            Required fields:
                - escalation_id (str): Unique escalation identifier
                - customer_email (str): Customer's email address
                - account_tier (str): One of: enterprise, premium, standard, free
                - issue_category (str): Category of the issue
                - issue_summary (str): Brief description of the issue
            
            Optional fields:
                - slack_thread_id (str): Slack thread ID for context
                - customer_impact (str): Description of customer impact
                - urgency_signals (list): List of urgency indicators
                - timestamp (str): ISO timestamp (uses current time if omitted)
    
    Returns:
        JSON string containing TriageResult with:
            - escalation_id
            - severity_score (0-100+)
            - severity_level (P1, P2, P3, P4)
            - account_risk_level (high, medium, low)
            - response_priority (immediate, urgent, standard, low)
            - risk_factors (dict with detected risks)
            - recommended_team (which team should handle)
            - human_review_required (bool)
            - recommended_action (specific action to take)
            - explanation (detailed reasoning)
            - scoring_breakdown (point-by-point scoring)
            - audit_trail (complete decision log)
            - timestamp (ISO timestamp)
            - confidence_score (0-100)
            - slack_thread_id (if provided in input)
    
    Raises:
        ValueError: If input validation fails (missing required fields, invalid account_tier)
        TypeError: If escalation_data is not a dictionary
    
    Example for Slack Automation:
        from main import json_input_mode
        
        escalation = {
            "escalation_id": "ESC-2024-001",
            "customer_email": "ceo@techcompany.com",
            "account_tier": "enterprise",
            "issue_category": "technical",
            "issue_summary": "Production API service is completely down",
            "customer_impact": "All customers unable to access platform",
            "urgency_signals": ["CEO contacted", "Executive escalation"],
            "slack_thread_id": "1693478800.000100"
        }
        
        result_json = json_input_mode(escalation)
        # result_json is a JSON string with TriageResult
        
        # Parse if needed:
        import json
        result_dict = json.loads(result_json)
        print(f"Severity: {result_dict['severity_level']}")
        print(f"Action: {result_dict['recommended_action']}")
    """
    if not isinstance(escalation_data, dict):
        raise TypeError(
            f"escalation_data must be a dictionary, got {type(escalation_data).__name__}"
        )
    
    try:
        agent = EscalationAgent()  # No credentials exposed
        result = agent.process_escalation_dict(escalation_data)
        logger.info(
            f"Escalation {result.escalation_id} processed via JSON input mode: "
            f"{result.severity_level} (score: {result.severity_score})"
        )
        return result.to_json()
    except ValueError as e:
        logger.error(f"Input validation error in JSON input mode: {e}")
        raise
    except Exception as e:
        logger.error(f"Error in JSON input mode: {e}", exc_info=True)
        raise


def main():
    """CLI entry point for escalation agent."""
    parser = argparse.ArgumentParser(
        description="Escalation Intelligence Agent - Analyze customer escalations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze from JSON file
  python main.py analyze -f escalation.json

  # Analyze from inline JSON
  python main.py analyze -j '{"escalation_id": "E123", ...}'

  # Analyze and post to Slack thread
  python main.py analyze -f escalation.json --slack-channel C123 --slack-thread 1234567890.123456

  # Save result to JSON
  python main.py analyze -f escalation.json -o result.json

  # Analyze from stdin
  echo '{"escalation_id": "E123", ...}' | python main.py analyze -j -
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an escalation",
    )

    input_group = analyze_parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-f",
        "--file",
        help="Path to JSON file with escalation data",
        type=str,
    )
    input_group.add_argument(
        "-j",
        "--json",
        help="Inline JSON string with escalation data (use '-' to read from stdin)",
        type=str,
    )

    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Output file path for result (JSON format)",
        type=str,
    )

    analyze_parser.add_argument(
        "--slack-channel",
        help="Slack channel ID for thread reply",
        type=str,
    )

    analyze_parser.add_argument(
        "--slack-thread",
        help="Slack thread timestamp for reply",
        type=str,
    )

    analyze_parser.add_argument(
        "--log-level",
        help="Logging level (DEBUG, INFO, WARNING, ERROR)",
        default="INFO",
        type=str.upper,
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Set logging level
    if args.log_level:
        logging.getLogger().setLevel(getattr(logging, args.log_level, logging.INFO))

    # Initialize agent
    agent = EscalationAgent.from_env()

    try:
        # Process escalation
        if args.file:
            logger.info(f"Loading escalation from file: {args.file}")
            result = agent.process_escalation_file(args.file)
        else:  # args.json
            if args.json == "-":
                logger.info("Reading escalation from stdin")
                json_input = sys.stdin.read()
            else:
                json_input = args.json

            logger.info("Processing escalation from JSON input")
            result = agent.process_escalation_json(json_input)

        # Print result to console
        agent.print_result(result)

        # Save to file if specified
        if args.output:
            agent.save_result_json(result, args.output)

        # Post to Slack if specified
        if args.slack_channel and args.slack_thread:
            logger.info("Posting result to Slack thread")
            agent.post_to_slack_thread(
                channel_id=args.slack_channel,
                thread_ts=args.slack_thread,
                result=result,
            )
        elif args.slack_channel or args.slack_thread:
            logger.warning(
                "Both --slack-channel and --slack-thread required for Slack posting"
            )

        logger.info(
            f"Escalation {result.escalation_id} processed successfully: "
            f"{result.severity_level} (score: {result.severity_score})"
        )
        sys.exit(0)

    except FileNotFoundError as e:
        logger.error(f"File error: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
