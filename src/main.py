import argparse
import json
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track

from collector import DriverCollector
from verifier import DriverVerifier
from evaluator import RiskEvaluator
from cert_verifier import CertificateVerifier

console = Console()


def export_json(results, output_path="report.json"):
    """Saves scan results to a structured JSON file."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4)
    console.print(f"[bold green]✔ Report successfully exported to JSON:[/] {output_path}")


def export_html(results, output_path="report.html"):
    """Generates an Interactive Security Dashboard 2.0 using Chart.js."""
    
    # Calculate Summary Stats
    total = len(results)
    low_risk = sum(1 for r in results if r["risk_level"] == "LOW RISK")
    med_risk = sum(1 for r in results if r["risk_level"] == "MEDIUM RISK")
    high_risk = sum(1 for r in results if r["risk_level"] == "HIGH RISK")
    crit_risk = sum(1 for r in results if r["risk_level"] == "CRITICAL RISK")

    rows = ""
    for r in results:
        badge_color = (
            "#28a745" if r["risk_level"] == "LOW RISK" else
            "#ffc107" if r["risk_level"] == "MEDIUM RISK" else
            "#dc3545" if r["risk_level"] == "HIGH RISK" else
            "#6f42c1"
        )

        score = r.get("trust_score", 100)
        entropy = r.get("entropy", 0.0)
        cert_info = r.get("cert_issuer") or "Unsigned / Unknown"
        
        # Format Triggered Rules & YARA Matches
        rules_triggered = len(r.get("triggered_rules", []))
        yara_matches = len(r.get("yara_matches", []))
        findings_badge = f"<span style='color: #6c757d;'>None</span>"
        if rules_triggered > 0 or yara_matches > 0:
            findings_badge = f"<span style='color: #dc3545; font-weight: bold;'>⚠️ {rules_triggered} Rules, {yara_matches} YARA</span>"

        rows += f"""
        <tr>
            <td><strong>{r['driver_name']}</strong></td>
            <td><code>{r['sha256'][:16]}...</code></td>
            <td>{'<span style="color: green;">Yes ✅</span>' if r['is_signed'] else '<span style="color: red;">No ❌</span>'}</td>
            <td><strong>{score}/100</strong></td>
            <td>{entropy:.2f}</td>
            <td><small>{cert_info[:35]}</small></td>
            <td><span style="background-color: {badge_color}; color: white; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px;">{r['risk_level']}</span></td>
            <td>{findings_badge}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SDVS Interactive Dashboard v0.6.0</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background-color: #1e1e2e; color: #cdd6f4; padding: 30px; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #313244; padding-bottom: 15px; margin-bottom: 25px; }}
            h1 {{ margin: 0; color: #89b4fa; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }}
            .stat-card {{ background: #181825; padding: 20px; border-radius: 8px; border-left: 5px solid #89b4fa; text-align: center; }}
            .stat-card h3 {{ margin: 0; font-size: 14px; color: #a6adc8; }}
            .stat-card p {{ margin: 10px 0 0 0; font-size: 28px; font-weight: bold; color: #cdd6f4; }}
            .charts-container {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }}
            .chart-box {{ background: #181825; padding: 20px; border-radius: 8px; max-height: 300px; display: flex; justify-content: center; }}
            table {{ width: 100%; border-collapse: collapse; background: #181825; border-radius: 8px; overflow: hidden; }}
            th, td {{ padding: 14px; text-align: left; border-bottom: 1px solid #313244; }}
            th {{ background-color: #11111b; color: #89b4fa; font-size: 14px; }}
            tr:hover {{ background-color: #313244; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ SDVS Kernel Security Dashboard (v0.6.0)</h1>
            <span>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>

        <div class="stats-grid">
            <div class="stat-card" style="border-color: #89b4fa;"><h3>TOTAL DRIVERS</h3><p>{total}</p></div>
            <div class="stat-card" style="border-color: #28a745;"><h3>LOW RISK</h3><p>{low_risk}</p></div>
            <div class="stat-card" style="border-color: #ffc107;"><h3>MEDIUM RISK</h3><p>{med_risk}</p></div>
            <div class="stat-card" style="border-color: #dc3545;"><h3>HIGH / CRITICAL</h3><p>{high_risk + crit_risk}</p></div>
        </div>

        <div class="charts-container">
            <div class="chart-box"><canvas id="riskChart"></canvas></div>
            <div class="chart-box"><canvas id="scoreChart"></canvas></div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Driver Name</th>
                    <th>SHA-256</th>
                    <th>Signed</th>
                    <th>Trust Score</th>
                    <th>Entropy</th>
                    <th>Issuer</th>
                    <th>Risk Level</th>
                    <th>Findings</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>

        <script>
            const ctxRisk = document.getElementById('riskChart').getContext('2d');
            new Chart(ctxRisk, {{
                type: 'doughnut',
                data: {{
                    labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical Risk'],
                    datasets: [{{
                        data: [{low_risk}, {med_risk}, {high_risk}, {crit_risk}],
                        backgroundColor: ['#28a745', '#ffc107', '#dc3545', '#6f42c1']
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{ title: {{ display: true, text: 'Risk Level Distribution', color: '#cdd6f4' }} }}
                }}
            }});

            const ctxScore = document.getElementById('scoreChart').getContext('2d');
            new Chart(ctxScore, {{
                type: 'bar',
                data: {{
                    labels: [{", ".join([f"'{r['driver_name']}'" for r in results])}],
                    datasets: [{{
                        label: 'Trust Score (0-100)',
                        data: [{", ".join([str(r['trust_score']) for r in results])}],
                        backgroundColor: '#89b4fa'
                    }}]
                }},
                options: {{
                    responsive: true,
                    scales: {{ y: {{ beginAtZero: true, max: 100 }} }},
                    plugins: {{ title: {{ display: true, text: 'Driver Trust Scores', color: '#cdd6f4' }} }}
                }}
            }});
        </script>
    </body>
    </html>
    """
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    console.print(f"[bold green]✔ Interactive Dashboard 2.0 successfully exported to:[/] {output_path}")


def run_sdvs_audit(limit=5, export_format=None):
    console.print(Panel.fit("[bold cyan]🛡️ Secure Driver Verification System (SDVS) v0.6.0[/]", border_style="bold blue"))

    drivers = DriverCollector.get_installed_drivers(limit=limit)
    audit_results = []

    table = Table(title=f"Kernel Drivers Audit (Top {limit})", show_header=True, header_style="bold magenta")
    table.add_column("Driver", style="bold white")
    table.add_column("Signed", justify="center")
    table.add_column("Trust Score", justify="center")
    table.add_column("Entropy", justify="center")
    table.add_column("Risk Level", justify="center")
    table.add_column("Recommendation", style="italic")

    for driver in track(drivers, description="[green]Scanning PE, Certs, Rules & YARA Engine..."):
        driver_name = driver["name"]
        driver_path = driver["path"]

        sha256_hash = DriverVerifier.get_file_hash(driver_path)
        is_signed = DriverVerifier.check_digital_signature(driver_path)

        cert_details = CertificateVerifier.extract_certificates(driver_path)

        risk = RiskEvaluator.evaluate_driver(
            driver_name=driver_name,
            has_signature=is_signed,
            file_hash=sha256_hash,
            file_path=driver_path
        )

        trust_score = risk.get("trust_score", 100)
        entropy = risk.get("entropy", 0.0)
        risk_level = risk["level"]
        risk_color = risk.get("color", "white")

        if trust_score >= 80:
            score_styled = f"[bold green]{trust_score}/100[/bold green]"
        elif trust_score >= 50:
            score_styled = f"[bold yellow]{trust_score}/100[/bold yellow]"
        else:
            score_styled = f"[bold red]{trust_score}/100[/bold red]"

        risk_styled = f"[{risk_color}]{risk_level}[/{risk_color}]"
        signed_icon = "[green]Yes ✅[/]" if is_signed else "[red]No ❌[/]"

        table.add_row(
            driver_name,
            signed_icon,
            score_styled,
            f"{entropy:.2f}",
            risk_styled,
            risk["recommendation"]
        )

        audit_results.append({
            "driver_name": driver_name,
            "path": driver_path,
            "sha256": sha256_hash,
            "is_signed": is_signed,
            "cert_issuer": cert_details.get("issuer"),
            "cert_subject": cert_details.get("subject"),
            "trust_score": trust_score,
            "entropy": entropy,
            "risk_level": risk_level,
            "deductions": risk.get("deductions", []),
            "triggered_rules": risk.get("triggered_rules", []),
            "yara_matches": risk.get("yara_matches", []),
            "recommendation": risk["recommendation"]
        })

    console.print(table)

    if export_format == "json":
        export_json(audit_results)
    elif export_format == "html":
        export_html(audit_results)


def run_cli():
    """CLI entry point for pip/package distribution."""
    parser = argparse.ArgumentParser(description="SDVS - Secure Driver Verification System")
    parser.add_argument("--limit", type=int, default=5, help="Number of drivers to scan")
    parser.add_argument("--export", choices=["json", "html"], help="Export audit results (json or html)")
    args = parser.parse_args()

    run_sdvs_audit(limit=args.limit, export_format=args.export)


if __name__ == "__main__":
    run_cli()