import argparse
import json
import os
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

from collector import DriverCollector
from verifier import DriverVerifier
from evaluator import RiskEvaluator

console = Console()

def export_json(results, output_path="report.json"):
    """Saves scan results to a structured JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]✔ Report successfully exported to JSON:[/] {output_path}")

def export_html(results, output_path="report.html"):
    """Saves scan results to a clean HTML report."""
    rows = ""
    for r in results:
        # Badge color map including CRITICAL RISK
        badge_color = "#28a745" if r["risk_level"] == "LOW RISK" else \
                      "#ffc107" if r["risk_level"] == "MEDIUM RISK" else \
                      "#dc3545" if r["risk_level"] == "HIGH RISK" else \
                      "#6f42c1" # Purple for CRITICAL RISK

        rows += f"""
        <tr>
            <td><strong>{r['driver_name']}</strong></td>
            <td><code>{r['sha256'][:16]}...</code></td>
            <td>{'Yes ✅' if r['is_signed'] else 'No ❌'}</td>
            <td><span style="background-color: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;">{r['risk_level']}</span></td>
            <td>{r['recommendation']}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>SDVS Audit Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f8f9fa; color: #333; }}
            h1 {{ color: #0056b3; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #343a40; color: white; }}
            tr:hover {{ background-color: #f1f1f1; }}
        </style>
    </head>
    <body>
        <h1>🛡️ SDVS Kernel Driver Audit Report</h1>
        <p><strong>Generated At:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <table>
            <thead>
                <tr>
                    <th>Driver Name</th>
                    <th>SHA-256 (Short)</th>
                    <th>Signed</th>
                    <th>Risk Level</th>
                    <th>Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    console.print(f"[bold green]✔ Report successfully exported to HTML:[/] {output_path}")

def run_sdvs_audit(limit=5, export_format=None):
    console.print(Panel.fit("[bold cyan]🛡️ Secure Driver Verification System (SDVS)[/]", border_style="bold blue"))
    
    drivers = DriverCollector.get_installed_drivers(limit=limit)
    audit_results = []

    table = Table(title=f"Kernel Drivers Audit (Top {limit})", show_header=True, header_style="bold magenta")
    table.add_column("Driver", style="bold white")
    table.add_column("Signed", justify="center")
    table.add_column("SHA-256", style="dim", overflow="fold")
    table.add_column("Risk Level", justify="center")
    table.add_column("Recommendation", style="italic")

    for driver in track(drivers, description="[green]Scanning & Verifying PE headers..."):
        driver_name = driver["name"]
        driver_path = driver["path"]

        sha256_hash = DriverVerifier.get_file_hash(driver_path)
        is_signed = DriverVerifier.check_digital_signature(driver_path)
        
        # Pass file_hash to RiskEvaluator to trigger Blocklist checks!
        risk = RiskEvaluator.evaluate_driver(
            driver_name=driver_name,
            has_signature=is_signed,
            file_hash=sha256_hash
        )

        risk_level = risk["level"]
        risk_color = risk.get("color", "white")
        risk_styled = f"[{risk_color}]{risk_level}[/{risk_color}]"

        signed_icon = "[green]Yes ✅[/]" if is_signed else "[red]No ❌[/]"

        table.add_row(
            driver_name,
            signed_icon,
            f"{sha256_hash[:12]}...",
            risk_styled,
            risk["recommendation"]
        )

        audit_results.append({
            "driver_name": driver_name,
            "path": driver_path,
            "sha256": sha256_hash,
            "is_signed": is_signed,
            "risk_level": risk_level,
            "recommendation": risk["recommendation"]
        })

    console.print(table)

    if export_format == "json":
        export_json(audit_results)
    elif export_format == "html":
        export_html(audit_results)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SDVS - Secure Driver Verification System")
    parser.add_argument("--limit", type=int, default=5, help="Number of drivers to scan")
    parser.add_argument("--export", choices=["json", "html"], help="Export audit results (json or html)")
    args = parser.parse_args()

    run_sdvs_audit(limit=args.limit, export_format=args.export)