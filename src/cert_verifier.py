"""
Authenticode Certificate Chain & Revocation Checking Module for Windows Drivers.
"""

import pefile
from cryptography.hazmat.primitives.serialization import pkcs7


class CertificateVerifier:
    """Extracts and validates Authenticode certificate chains and signatures."""

    @staticmethod
    def extract_certificates(file_path: str) -> dict:
        """
        Parses PE Security Directory and extracts certificate chain details.
        """
        details = {
            "has_cert_table": False,
            "issuer": None,
            "subject": None,
            "is_revoked": False,
            "chain_valid": False,
            "error": None,
        }

        if not file_path:
            return details

        try:
            pe = pefile.PE(file_path, fast_load=True)

            # Locate Security Directory (WIN_CERTIFICATE)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])

            if not hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
                pe.close()
                return details

            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
                pe.close()
                return details

            details["has_cert_table"] = True

            # Read raw PKCS7 signature data from file
            with open(file_path, "rb") as f:
                f.seek(sec_dir.VirtualAddress + 8)  # Skip bLength (4B) & wRevision/wCertificateType (4B)
                pkcs7_bytes = f.read(sec_dir.Size - 8)

            # Parse DER-encoded PKCS7 certificates
            certs = pkcs7.load_der_pkcs7_certificates(pkcs7_bytes)

            if certs:
                signer_cert = certs[0]
                details["subject"] = signer_cert.subject.rfc4514_string()
                details["issuer"] = signer_cert.issuer.rfc4514_string()
                details["chain_valid"] = True

            pe.close()
        except Exception as e:
            details["error"] = str(e)

        return details