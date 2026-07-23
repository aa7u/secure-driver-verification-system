"""
YARA Engine Module for Kernel Driver Threat Intelligence Scanning.
"""

from pathlib import Path
import yara


class YaraVerifier:
    """Compiles and executes YARA rules against kernel driver binaries."""

    def __init__(self, rules_dir: str = "rules"):
        self.rules = None
        self.load_rules(rules_dir)

    def load_rules(self, rules_dir: str):
        """Compiles all .yar files found inside the rules directory."""
        dir_path = Path(rules_dir)
        if not dir_path.exists():
            return

        filepaths = {}
        for index, yar_file in enumerate(dir_path.glob("*.yar")):
            filepaths[f"namespace_{index}"] = str(yar_file)

        if filepaths:
            try:
                self.rules = yara.compile(filepaths=filepaths)
            except Exception as e:
                print(f"[!] Warning: Failed to compile YARA rules: {e}")

    def scan_file(self, file_path: str) -> list:
        """
        Scans a binary file against loaded YARA rules.
        Returns a list of matched rule metadata.
        """
        matches_info = []
        if not self.rules or not file_path or not Path(file_path).exists():
            return matches_info

        try:
            matches = self.rules.match(file_path)
            for match in matches:
                matches_info.append({
                    "rule_name": match.rule,
                    "description": match.meta.get("description", "No description"),
                    "severity": match.meta.get("severity", "MEDIUM"),
                })
        except Exception as e:
            print(f"[!] Warning: Error scanning file {file_path} with YARA: {e}")

        return matches_info