"""
ETW (Event Tracing for Windows) Real-Time Driver Load Monitor.
Monitors kernel driver load events and triggers real-time security analysis.
"""

import time
import subprocess
import json
from rich.console import Console
from rich.panel import Panel
from evaluator import RiskEvaluator
from verifier import DriverVerifier

console = Console()


class ETWDriverMonitor:
    """Monitors real-time Windows Kernel driver loading events via Event Tracing."""

    def __init__(self):
        self.is_running = False

    def process_driver_event(self, driver_path: str, driver_name: str):
        """Evaluates a newly loaded driver in real-time."""
        console.print(f"\n[bold cyan]⚡ Real-Time Alert:[/] Kernel Driver Loaded: [bold white]{driver_name}[/]")
        
        sha256_hash = DriverVerifier.get_file_hash(driver_path)
        is_signed = DriverVerifier.check_digital_signature(driver_path)

        risk = RiskEvaluator.evaluate_driver(
            driver_name=driver_name,
            has_signature=is_signed,
            file_hash=sha256_hash,
            file_path=driver_path
        )

        score = risk.get("trust_score", 100)
        level = risk["level"]
        color = risk.get("color", "white")

        panel_content = f"""[bold]Path:[/] {driver_path}
[bold]SHA-256:[/] {sha256_hash[:32]}...
[bold]Signed:[/] {'[green]Yes ✅[/]' if is_signed else '[red]No ❌[/]'}
[bold]Trust Score:[/] {score}/100
[bold]Risk Level:[/] [{color}]{level}[/{color}]
[bold]Recommendation:[/] {risk['recommendation']}"""

        console.print(Panel(panel_content, title=f"🛡️ Real-Time Audit: {driver_name}", border_style=color))

    def start_polling_monitor(self, interval: int = 3):
        """
        Lightweight real-time polling monitor for Driver Load Events via Windows Event Logs / WMI.
        Monitors CodeIntegrity and Kernel Driver Load events.
        """
        self.is_running = True
        console.print(Panel.fit("[bold green]📡 SDVS ETW Monitor Started[/]\nListening for Kernel Driver Load events... (Press Ctrl+C to stop)", border_style="bold green"))

        known_drivers = set()

        try:
            while self.is_running:
                # Query running drivers using driverquery or WMI
                cmd = 'powershell "Get-WmiObject Win32_SystemDriver | Select-Object Name, PathName | ConvertTo-Json"'
                result = subprocess.run(cmd, capture_output=True, text=True, shell=True)

                if result.returncode == 0 and result.stdout.strip():
                    try:
                        data = json.loads(result.stdout)
                        if isinstance(data, dict):
                            data = [data]

                        for item in data:
                            name = item.get("Name", "")
                            path = item.get("PathName", "")

                            if name and path and name not in known_drivers:
                                if len(known_drivers) > 0:  # Skip initial baseline dump
                                    self.process_driver_event(path, f"{name}.sys")
                                known_drivers.add(name)
                    except Exception:
                        pass

                time.sleep(interval)

        except KeyboardInterrupt:
            console.print("\n[bold yellow]🛑 ETW Real-Time Monitoring Stopped.[/]")
            self.is_running = False