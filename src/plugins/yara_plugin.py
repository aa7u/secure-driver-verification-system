"""
YARA Scanner Plugin for SDVS.
"""

import os
from typing import Dict, Any
import yara
from plugins.base_plugin import BasePlugin


class YaraScannerPlugin(BasePlugin):
    """Plugin to run YARA threat intelligence rules against kernel drivers."""

    @property
    def name(self) -> str:
        return "YARA Threat Scanner"

    @property
    def description(self) -> str:
        return "Scans driver bytes against YARA threat signatures for suspicious APIs and rootkits."

    def __init__(self):
        rule_path = os.path.join(os.path.dirname(__file__), "..", "rules", "kernel_suspicious.yar")
        if os.path.exists(rule_path):
            self.rules = yara.compile(filepath=rule_path)
        else:
            self.rules = None

    def inspect(self, driver_path: str, driver_info: Dict[str, Any]) -> Dict[str, Any]:
        if not self.rules or not os.path.exists(driver_path):
            return {"score_deduction": 0, "findings": [], "risk_flag": False}

        try:
            matches = self.rules.match(driver_path)
            if matches:
                findings = [f"YARA Match: {m.rule}" for m in matches]
                return {
                    "score_deduction": 40 * len(matches),
                    "findings": findings,
                    "risk_flag": True
                }
        except Exception:
            pass

        return {"score_deduction": 0, "findings": [], "risk_flag": False}