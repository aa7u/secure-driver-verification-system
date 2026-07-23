"""
Plugin Manager for SDVS.
Dynamically discovers, loads, and executes all plugins in src/plugins/.
"""

import importlib
import pkgutil
import inspect
from typing import List, Dict, Any
from plugins.base_plugin import BasePlugin
from rich.console import Console

console = Console()


class PluginManager:
    """Manages dynamic discovery and execution of SDVS security plugins."""

    def __init__(self):
        self.plugins: List[BasePlugin] = []
        self._discover_plugins()

    def _discover_plugins(self):
        """Scans the plugins directory and instantiates all BasePlugin subclasses."""
        import plugins

        for _, module_name, _ in pkgutil.iter_modules(plugins.__path__):
            if module_name in ["base_plugin", "manager"]:
                continue

            full_module_name = f"plugins.{module_name}"
            module = importlib.import_module(full_module_name)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    instance = obj()
                    self.plugins.append(instance)

    def run_all_plugins(self, driver_path: str, driver_info: Dict[str, Any]) -> Dict[str, Any]:
        """Runs all discovered plugins against a target driver."""
        total_deduction = 0
        all_findings = []
        plugin_results = {}

        for plugin in self.plugins:
            try:
                result = plugin.inspect(driver_path, driver_info)
                deduction = result.get("score_deduction", 0)
                findings = result.get("findings", [])

                total_deduction += deduction
                all_findings.extend(findings)
                plugin_results[plugin.name] = result
            except Exception as e:
                console.print(f"[bold red]❌ Plugin Error ({plugin.name}):[/] {e}")

        return {
            "total_deduction": total_deduction,
            "findings": all_findings,
            "details": plugin_results
        }