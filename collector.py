import os
import win32api

class DriverCollector:
    """Collects installed kernel drivers from the Windows drivers directory."""

    DRIVERS_DIR = r"C:\Windows\System32\drivers"

    @classmethod
    def get_installed_drivers(cls, limit: int = 10) -> list[dict]:
        """Scans System32/drivers and returns basic metadata for binary files."""
        if not os.path.exists(cls.DRIVERS_DIR):
            raise FileNotFoundError(f"Drivers directory not found at {cls.DRIVERS_DIR}")

        drivers_list = []
        # Get list of .sys driver files
        sys_files = [f for f in os.listdir(cls.DRIVERS_DIR) if f.endswith(".sys")]

        for file_name in sys_files[:limit]:
            full_path = os.path.join(cls.DRIVERS_DIR, file_name)
            drivers_list.append({
                "name": file_name,
                "path": full_path,
                "size_bytes": os.path.getsize(full_path)
            })

        return drivers_list

if __name__ == "__main__":
    print("[+] Scanning installed Windows Kernel Drivers...\n")
    drivers = DriverCollector.get_installed_drivers(limit=5)
    for driver in drivers:
        print(f"Driver: {driver['name']} | Size: {driver['size_bytes']} bytes")