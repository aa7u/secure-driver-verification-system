from collector import DriverCollector
from verifier import DriverVerifier
from evaluator import RiskEvaluator

def run_sdvs_audit(limit: int = 5):
    print("==================================================")
    print(" 🛡️ Secure Driver Verification System (SDVS) ")
    print("==================================================\n")
    print(f"[+] Scanning first {limit} kernel drivers...\n")

    try:
        drivers = DriverCollector.get_installed_drivers(limit=limit)
        
        for idx, driver in enumerate(drivers, start=1):
            driver_name = driver["name"]
            driver_path = driver["path"]
            
            # 1. Compute Hash
            sha256_hash = DriverVerifier.get_file_hash(driver_path)
            
            # 2. Risk Evaluation
            risk = RiskEvaluator.evaluate_driver(driver_name=driver_name, has_signature=True)
            
            print(f"[{idx}] Driver: {driver_name}")
            print(f"    Path: {driver_path}")
            print(f"    Size: {driver['size_bytes']} bytes")
            print(f"    SHA-256: {sha256_hash}")
            print(f"    Risk Assessment: [{risk['level']}]")
            print(f"    Recommendation: {risk['recommendation']}")
            print("-" * 50)
            
    except Exception as e:
        print(f"[-] Error during execution: {e}")

if __name__ == "__main__":
    run_sdvs_audit(limit=5)