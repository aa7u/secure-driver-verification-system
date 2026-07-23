import hashlib
import os

class DriverVerifier:
    """Verifies cryptographic integrity and hashes of Windows driver binaries."""

    @staticmethod
    def get_file_hash(file_path: str) -> str:
        """Generates a SHA-256 hash for a given driver file."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Driver file not found: {file_path}")

        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

if __name__ == "__main__":
    # تجربة سريعة على ملف تعريف حقيقي في نظام ويندوز
    sample_driver = r"C:\Windows\System32\drivers\null.sys"
    
    if os.path.exists(sample_driver):
        driver_hash = DriverVerifier.get_file_hash(sample_driver)
        print(f"[+] Sample Driver: {sample_driver}")
        print(f"[+] Computed SHA-256: {driver_hash}")
    else:
        print("[-] Sample driver path not found.")