import yaml
from pathlib import Path

class RuleEngine:
    def __init__(self, rules_file: str = "rules.yaml"):
        self.rules = []
        self.load_rules(rules_file)

    def load_rules(self, rules_file: str):
        path = Path(rules_file)
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    self.rules = data.get("rules", [])
            except Exception as e:
                print(f"[!] Warning: Failed to parse rules file {rules_file}: {e}")

    def evaluate(self, driver_data: dict) -> list:
        """
        Evaluates a driver against loaded YAML rules.
        Returns a list of triggered rule matches.
        """
        triggered = []

        for rule in self.rules:
            cond = rule.get("condition", {})
            match = True

            # Condition 1: Signature Status
            if "signature" in cond:
                if cond["signature"] == "unsigned" and driver_data.get("is_signed"):
                    match = False
                elif cond["signature"] == "signed" and not driver_data.get("is_signed"):
                    match = False

            # Condition 2: Path pattern
            if match and "path_contains" in cond:
                if cond["path_contains"].lower() not in driver_data.get("path", "").lower():
                    match = False

            # Condition 3: Entropy threshold
            if match and "min_entropy" in cond:
                if driver_data.get("entropy", 0.0) < cond["min_entropy"]:
                    match = False

            # Condition 4: Name patterns
            if match and "name_contains" in cond:
                name_matches = any(
                    kw.lower() in driver_data.get("driver_name", "").lower()
                    for kw in cond["name_contains"]
                )
                if not name_matches:
                    match = False

            if match:
                triggered.append({
                    "rule_name": rule.get("name"),
                    "severity": rule.get("severity"),
                    "deduction": rule.get("deduction", 0),
                    "description": rule.get("description")
                })

        return triggered