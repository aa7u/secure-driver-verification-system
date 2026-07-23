"""
Baseline Snapshot & Differential Analysis Engine for SDVS.
Saves system driver states and compares changes to detect new, missing, or tampered kernel drivers.
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from collector import DriverCollector
from verifier import DriverVerifier

console = Console()


class BaselineManager:
    """Manages baseline snapshot saving and differential analysis."""

    @staticmethod
    def save_baseline(filepath: str = "baseline.json") -> str:
        """Captures current system kernel drivers state and saves to a baseline file."""
        console.print("[bold yellow]📸 Capturing current kernel drivers state for baseline...[/]")
        
        drivers = DriverCollector.get_installed_drivers(limit=1000)
        baseline_data = {
            "timestamp": datetime.now().isoformat(),
            "total_drivers": len(drivers),
            "drivers": {}
        }

        for driver in drivers:
            name = driver["name"]
            path = driver["path"]
            file_hash = DriverVerifier.get_file_hash(path) if path else ""
            
            baseline_data["drivers"][name] = {
                "path": path,
                "sha256": file_hash
            }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=4)

        console.print(Panel.fit(
            f"[bold green]✔ Baseline Snapshot Successfully Saved![/]\n"
            f"[bold white]File:[/] {filepath}\n"
            f"[bold white]Total Drivers Snapshotted:[/] {len(drivers)}",
            border_style="bold green"
        ))
        return filepath

    @staticmethod
    def compare_baseline(filepath: str = "baseline.json") -> Dict[str, Any]:
        """Compares current kernel drivers against a previously saved baseline snapshot."""
        if not os.path.exists(filepath):
            console.print(f"[bold red]❌ Error:[/] Baseline file '{filepath}' not found! Run '--baseline-save' first.")
            return {}

        with open(filepath, "r", encoding="utf-8") as f:
            baseline = json.load(f)

        old_drivers = baseline.get("drivers", {})
        current_drivers_list = DriverCollector.get_installed_drivers(limit=1000)
        current_drivers = {d["name"]: {"path": d["path"], "sha256": DriverVerifier.get_file_hash(d["path"])} for d in current_drivers_list}

        added = []
        removed = []
        modified = []

        # Check for added and modified drivers
        for name, info in current_drivers.items():
            if name not in old_drivers:
                added.append({"name": name, "path": info["path"], "sha256": info["sha256"]})
            else:
                if info["sha256"] != old_drivers[name]["sha256"] and info["sha256"]:
                    modified.append({
                        "name": name,
                        "path": info["path"],
                        "old_sha256": old_drivers[name]["sha256"],
                        "new_sha256": info["sha256"]
                    })

        # Check for removed drivers
        for name, info in old_drivers.items():
            if name not in current_drivers:
                removed.append({"name": name, "path": info["path"]})

        # Render Results Table
        table = Table(title="🔍 Baseline Differential Audit Results", header_style="bold magenta")
        table.add_column("Status", justify="center", style="bold")
        table.add_column("Driver Name", style="bold white")
        table.add_column("Details", style="italic")

        for item in added:
            table.add_row("[green]NEW 🆕[/]", item["name"], f"Path: {item['path']}")
        for item in modified:
            table.add_row("[red]MODIFIED ⚠️[/]", item["name"], f"Hash Mismatch! Tampering suspected.")
        for item in removed:
            table.add_row("[yellow]REMOVED ❌[/]", item["name"], f"Driver unloaded or uninstalled.")

        console.print(table)

        if not added and not modified and not removed:
            console.print("[bold green]✔ Baseline Integrity Verification Passed: No driver changes detected.[/]")

        return {"added": added, "modified": modified, "removed": removed}