import hashlib
import os
import pefile

class DriverVerifier:
    """Provides cryptographic hashing and PE structure analysis for kernel drivers."""

    @staticmethod
    def get_file_hash(file_path: str) -> str:
        """Calculates the SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def check_digital_signature(file_path: str) -> bool:
        """
        Inspects the PE Security Directory of a .sys driver file 
        to verify if an Authenticode digital signature is present.
        """
        if not os.path.exists(file_path):
            return False

        try:
            # Parse PE file headers
            pe = pefile.PE(file_path, fast_load=True)
            
            # Parse Security Directory (Index 4 in Data Directories)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            ])

            # Check if Security Directory contains a valid entry
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            ]
            
            return security_dir.VirtualAddress != 0 and security_dir.Size > 0

        except Exception:
            return False

if __name__ == "__main__":
    sample_driver = r"C:\Windows\System32\drivers\null.sys"
    if os.path.exists(sample_driver):
        is_signed = DriverVerifier.check_digital_signature(sample_driver)
        print(f"[+] Driver: {sample_driver}")
        print(f"[+] Signed Authenticode: {is_signed}")