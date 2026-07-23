"""
Microsoft Vulnerable Driver Blocklist & Known Malware Hash Matching Engine.
"""

import os
import json

class BlocklistChecker:
    def __init__(self, blocklist_file=None):
        self.known_hashes = set()
        
        # Initial default list of known vulnerable/exploited driver SHA-256 hashes (BYOVD vectors)
        self.default_vulnerable_hashes = {
            "3a8a3a2d201e74f1b2b80456108137351d3ee50f0c058e5e6b12a0f8b3c1d2e1", # Example BYOVD hash
            "a209b5581e2dc8f4c2c5bd4a2221b6d0e91f1b2c3d4e5f6a7b8c9d0e1f2a3b4c"  # Known vulnerable driver
        }
        
        if blocklist_file and os.path.exists(blocklist_file):
            self.load_from_file(blocklist_file)
        else:
            self.known_hashes = self.default_vulnerable_hashes

    def load_from_file(self, file_path: str) -> None:
        """Load blocklist SHA-256 hashes from a local JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.known_hashes.update(data.get("hashes", []))
        except Exception as e:
            print(f"[!] Warning: Could not load blocklist file: {e}")

    def is_blocked(self, file_hash: str) -> bool:
        """Check if the given SHA-256 hash exists in the vulnerable driver blocklist."""
        if not file_hash:
            return False
        return file_hash.lower() in {h.lower() for h in self.known_hashes}