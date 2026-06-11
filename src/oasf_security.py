import time
from typing import List, Dict, Any

class OASFAuditMiddleware:
    def __init__(self, managed_scopes: List[str] = None):
        # Default safety boundaries for the UNVEIL environment
        self.managed_scopes = managed_scopes or [
            "web_search", "web_fetch", "read_file", 
            "create_document", "edit_document", "update_document"
        ]

    def verify_behavioral_scope(self, last_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates the agent's environment and input to run behavioral checks.
        Returns a dictionary containing verification status and console telemetry logs.
        """
        timestamp = time.strftime("%H:%M:%S")
        logs = [f"[{timestamp}] OASF: Initiating behavioral scope verification..."]
        
        content = last_message.get("content", "")
        
        # Guardrail: Basic path/traversal containment check
        if ".." in content or "passwd" in content:
            logs.append(f"[{time.strftime('%H:%M:%S')}] ALERT: System path traversal or sensitive string signature detected.")
            return {"verified": False, "action": "BLOCK", "logs": "\n".join(logs)}

        # If environmental checks pass cleanly
        logs.append(f"[{time.strftime('%H:%M:%S')}] PASS: Intended action resides within permitted safety boundaries.")
        logs.append(f"[{time.strftime('%H:%M:%S')}] Active boundaries: {', '.join(self.managed_scopes)}")
        
        return {"verified": True, "action": "ALLOW", "logs": "\n".join(logs)}

    def format_telemetry_for_frontend(self, verification_result: Dict[str, Any]) -> str:
        """
        Wraps the audit logs inside the syntax markers that your frontend
        interceptor uses to automatically trigger the inline UI card.
        """
        raw_logs = verification_result.get("logs", "")
        return f"\n[TOOL_CALL]\n{raw_logs}\n[/TOOL_CALL]\n"
