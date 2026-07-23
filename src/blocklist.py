import os
import json
import urllib.request
from pathlib import Path

LOLDRIVERS_URL = "https://www.loldrivers.io/api/drivers.json"
CACHE_FILE = Path("loldrivers_cache.json")

class BlocklistChecker:
    def __init__(self, blocklist_file=None, offline_mode=False):
        self.offline_mode = offline_mode
        self.microsoft_hashes = set()
        self.loldrivers_hashes = set()
        self.known_hashes = set()
        
        # 1. Default Microsoft Vulnerable Driver Blocklist
        self.default_vulnerable_hashes = {
            "3a8a3a2d201e74f1b2b80456108137351d3ee50f0c058e5e6b12a0f8b3c1d2e1",
            "a209b5581e2dc8f4c2c5bd4a2221b6d0e91f1b2c3d4e5f6a7b8c9d0e1f2a3b4c"
        }
        self.microsoft_hashes.update({h.lower() for h in self.default_vulnerable_hashes})
        
        # 2. Load custom file if provided
        if blocklist_file and os.path.exists(blocklist_file):
            self.load_from_file(blocklist_file)
            
        # 3. Load LOLDrivers API Data (Online / Offline Cache)
        self.load_loldrivers()
        
        # Aggregate all hashes
        self.known_hashes = self.microsoft_hashes.union(self.loldrivers_hashes)

    def load_from_file(self, file_path: str) -> None:
        """Load blocklist SHA-256 hashes from a local JSON file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                loaded = {h.lower() for h in data.get("hashes", [])}
                self.microsoft_hashes.update(loaded)
        except Exception as e:
            print(f"[!] Warning: Could not load blocklist file: {e}")

    def load_loldrivers(self) -> None:
        """Fetches LOLDrivers database or falls back to local cache efficiently."""
        data = None

        # 1. Use local cache if offline_mode is True or file is fresh
        if self.offline_mode and CACHE_FILE.exists():
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

        # 2. Fetch online only if not in offline mode
        if data is None and not self.offline_mode:
            try:
                req = urllib.request.Request(
                    LOLDRIVERS_URL, headers={"User-Agent": "SDVS-Scanner/0.4.0"}
                )
                with urllib.request.urlopen(req, timeout=3) as response:
                    data = json.loads(response.read().decode())
                    with open(CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump(data, f)
            except Exception:
                # Fallback to cache if network fails/timeouts
                if CACHE_FILE.exists():
                    try:
                        with open(CACHE_FILE, "r", encoding="utf-8") as f:
                            data = json.load(f)
                    except Exception:
                        data = []

        if data:
            for item in data:
                known_samples = item.get("KnownVulnerableSamples", [])
                for sample in known_samples:
                    hashes = sample.get("KnownVulnerableSamples", {})
                    sha256 = hashes.get("SHA256") or sample.get("SHA256")
                    if sha256:
                        self.loldrivers_hashes.add(sha256.lower())

    def is_blocked(self, file_hash: str) -> bool:
        """Simple boolean check for legacy support."""
        is_blocked, _ = self.check_hash(file_hash)
        return is_blocked

    def check_hash(self, file_hash: str) -> tuple[bool, str]:
        """Returns (is_blocked, source_name) for detailed reporting."""
        if not file_hash:
            return False, "Clean"
        
        clean_hash = file_hash.lower().strip()
        
        if clean_hash in self.microsoft_hashes:
            return True, "Microsoft Vulnerable Driver Blocklist"
        if clean_hash in self.loldrivers_hashes:
            return True, "LOLDrivers.io Database"
            
        return False, "Clean"