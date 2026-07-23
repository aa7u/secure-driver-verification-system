"""
Risk Evaluation Engine for Kernel Drivers.
Calculates risk levels based on signature status, PE attributes, and blocklist presence.
"""

from blocklist import BlocklistChecker


class RiskEvaluator:
    """Evaluates safety and risk level for device drivers."""

    _blocklist_checker = BlocklistChecker()

    @classmethod
    def evaluate_driver(
        cls,
        driver_name: str,
        has_signature: bool = True,
        is_beta: bool = False,
        file_hash: str = None,
    ) -> dict:
        """
        Assigns a risk level, color UI tag, and recommendation based on driver properties.
        """
        # 1. Critical Risk Condition: Known Vulnerable/Exploited Driver (BYOVD Threat)
        if file_hash and cls._blocklist_checker.is_blocked(file_hash):
            return {
                "level": "CRITICAL RISK",
                "color": "bold magenta",
                "recommendation": "BLOCKED! Driver SHA-256 matches a known vulnerable/exploited kernel driver (BYOVD threat).",
            }

        # 2. High Risk Condition: No signature or revoked
        if not has_signature:
            return {
                "level": "HIGH RISK",
                "color": "red",
                "recommendation": "Do NOT install/load. Unsigned kernel drivers pose severe security threats.",
            }

        # 3. Medium Risk Condition: Experimental or Beta
        if is_beta or "test" in driver_name.lower():
            return {
                "level": "MEDIUM RISK",
                "color": "yellow",
                "recommendation": "Proceed with caution. Experimental or test-signed driver detected.",
            }

        # 4. Low Risk Condition: Fully signed & stable
        return {
            "level": "LOW RISK",
            "color": "green",
            "recommendation": "Driver is officially signed and appears safe for kernel operation.",
        }