"""
SARIF (Static Analysis Results Interchange Format) Exporter for SDVS.
Generates SARIF v2.1.0 compliant JSON reports for GitHub Security Code Scanning integration.
"""

import json
from typing import List, Dict, Any


class SarifExporter:
    """Exports SDVS kernel driver audit findings to SARIF v2.1.0 format."""

    @staticmethod
    def generate_sarif_report(results: List[Dict[str, Any]], output_file: str = "sdvs_results.sarif") -> str:
        """
        Converts driver audit results into SARIF format and saves to a file.
        """
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Secure Driver Verification System (SDVS)",
                            "version": "1.3.0",
                            "informationUri": "https://github.com/aa7u/secure-driver-verification-system",
                            "rules": [
                                {
                                    "id": "SDVS001",
                                    "name": "UnsignedKernelDriver",
                                    "shortDescription": {"text": "Unsigned Windows Kernel Driver Detected"},
                                    "fullDescription": {"text": "Kernel drivers operating without valid digital signatures pose severe security risks."},
                                    "defaultConfiguration": {"level": "warning"}
                                },
                                {
                                    "id": "SDVS002",
                                    "name": "KnownVulnerableDriverBlocklist",
                                    "shortDescription": {"text": "Known Vulnerable Driver Hash Match"},
                                    "fullDescription": {"text": "Driver SHA-256 matches Microsoft or LOLDrivers blocklists (BYOVD Threat)."},
                                    "defaultConfiguration": {"level": "error"}
                                },
                                {
                                    "id": "SDVS003",
                                    "name": "YaraThreatSignatureMatch",
                                    "shortDescription": {"text": "YARA Rule Threat Match Detected"},
                                    "fullDescription": {"text": "Driver contains suspicious binary patterns matching known rootkits or exploits."},
                                    "defaultConfiguration": {"level": "error"}
                                }
                            ]
                        }
                    },
                    "results": []
                }
            ]
        }

        sarif_results = []

        for driver in results:
            risk = driver.get("risk_eval", {})
            driver_name = driver.get("name", "Unknown Driver")
            driver_path = driver.get("path", "")
            trust_score = risk.get("trust_score", 100)

            # Map deductions and matches to SARIF results
            for deduction in risk.get("deductions", []):
                rule_id = "SDVS001"
                level = "note"

                if "Blocked" in deduction or "CRITICAL" in risk.get("level", ""):
                    rule_id = "SDVS002"
                    level = "error"
                elif "YARA" in deduction:
                    rule_id = "SDVS003"
                    level = "error"
                elif "Unsigned" in deduction:
                    rule_id = "SDVS001"
                    level = "warning"

                sarif_results.append({
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"Driver [{driver_name}] (Score: {trust_score}/100): {deduction}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": driver_path.replace("\\", "/") if driver_path else driver_name
                                }
                            }
                        }
                    ]
                })

        sarif_data["runs"][0]["results"] = sarif_results

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(sarif_data, f, indent=2)

        return output_file