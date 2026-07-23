class RiskEvaluator:
    """Evaluates safety and risk level for device drivers."""

    @staticmethod
    def evaluate_driver(driver_name: str, has_signature: bool = True, is_beta: bool = False) -> dict:
        """Assigns a risk level and recommendation based on driver properties."""
        
        # High Risk Condition: No signature or revoked
        if not has_signature:
            return {
                "level": "HIGH RISK",
                "color": "red",
                "recommendation": "Do NOT install/load. Unsigned kernel drivers pose severe security threats."
            }
        
        # Medium Risk Condition: Experimental or Beta
        if is_beta or "test" in driver_name.lower():
            return {
                "level": "MEDIUM RISK",
                "color": "yellow",
                "recommendation": "Proceed with caution. Experimental or test-signed driver detected."
            }

        # Low Risk Condition: Fully signed & stable
        return {
            "level": "LOW RISK",
            "color": "green",
            "recommendation": "Driver is officially signed and appears safe for kernel operation."
        }