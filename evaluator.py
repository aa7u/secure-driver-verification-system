"""
Risk Evaluation Engine for Kernel Drivers.
Calculates trust scores (0-100) and risk levels based on signature status, PE attributes, entropy, and blocklist presence.
"""

import math
import pefile
from blocklist import BlocklistChecker


def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon Entropy of a binary stream (0.0 to 8.0)."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


def extract_pe_metadata(file_path: str) -> dict:
    """Extracts extended PE metadata including Entropy, Sections, and PDB Path."""
    metadata = {
        "entropy": 0.0,
        "pdb_path": None,
        "sections": [],
        "is_packed": False,
    }

    if not file_path:
        return metadata

    try:
        pe = pefile.PE(file_path, fast_load=True)

        with open(file_path, "rb") as f:
            full_data = f.read()
            metadata["entropy"] = calculate_entropy(full_data)

        # High entropy (> 7.2) indicates potential packing or encryption
        if metadata["entropy"] > 7.2:
            metadata["is_packed"] = True

        # Extract PDB Path from debug directory if present
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]])
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                if hasattr(entry, "entry") and hasattr(entry.entry, "PdbFileName"):
                    metadata["pdb_path"] = entry.entry.PdbFileName.decode("utf-8", errors="ignore").strip("\x00")

        # Extract Sections and entropy
        for section in pe.sections:
            sec_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
            sec_entropy = calculate_entropy(section.get_data())
            metadata["sections"].append({"name": sec_name, "entropy": sec_entropy})

        pe.close()
    except Exception:
        pass

    return metadata


class RiskEvaluator:
    """Evaluates safety, trust score, and risk level for device drivers."""

    _blocklist_checker = BlocklistChecker()

    @classmethod
    def evaluate_driver(
        cls,
        driver_name: str,
        has_signature: bool = True,
        is_beta: bool = False,
        file_hash: str = None,
        file_path: str = None,
    ) -> dict:
        """
        Assigns a Trust Score (0-100), Risk Level, UI Color, and detailed recommendation.
        """
        score = 100
        deductions = []
        
        # Check Blocklist matching (Microsoft or LOLDrivers)
        is_blocked, block_source = cls._blocklist_checker.check_hash(file_hash) if file_hash else (False, "Clean")
        
        # Extract extended PE attributes
        pe_meta = extract_pe_metadata(file_path) if file_path else {"entropy": 0.0, "is_packed": False, "pdb_path": None}

        # 1. Critical Risk Condition: Blocklist hit
        if is_blocked:
            score = 0
            deductions.append(f"Blocked by {block_source} (-100)")
            return {
                "level": "CRITICAL RISK",
                "color": "bold magenta",
                "trust_score": 0,
                "entropy": pe_meta["entropy"],
                "pdb_path": pe_meta["pdb_path"],
                "deductions": deductions,
                "recommendation": f"BLOCKED! Driver SHA-256 matches a known vulnerable/exploited kernel driver ({block_source}).",
            }

        # 2. Signature Deductions
        if not has_signature:
            score -= 50
            deductions.append("Unsigned Kernel Driver (-50)")

        # 3. Experimental or Beta Deductions
        is_test = is_beta or "test" in driver_name.lower()
        if is_test:
            score -= 30
            deductions.append("Experimental / Test-Signed Driver (-30)")

        # 4. PE Entropy / Packing Deductions
        if pe_meta.get("is_packed"):
            score -= 20
            deductions.append(f"High Entropy / Packed Binary ({pe_meta['entropy']}) (-20)")

        # Clamp final score between 0 and 100
        final_score = max(0, min(100, score))

        # Determine level & UI colors based on Trust Score matrix
        if final_score >= 80:
            level = "LOW RISK"
            color = "green"
            rec = "Driver is officially signed and appears safe for kernel operation."
        elif final_score >= 50:
            level = "MEDIUM RISK"
            color = "yellow"
            rec = "Proceed with caution. Experimental or test-signed driver detected."
        elif final_score >= 20:
            level = "HIGH RISK"
            color = "red"
            rec = "Do NOT install/load. Unsigned or suspicious kernel drivers pose severe security threats."
        else:
            level = "CRITICAL RISK"
            color = "bold magenta"
            rec = "High-risk driver detected. Execution should be blocked."

        return {
            "level": level,
            "color": color,
            "trust_score": final_score,
            "entropy": pe_meta["entropy"],
            "pdb_path": pe_meta["pdb_path"],
            "deductions": deductions,
            "recommendation": rec,
        }