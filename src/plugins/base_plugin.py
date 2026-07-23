"""
SDVS Base Plugin SDK.
All custom security scan plugins must inherit from BasePlugin.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any


class BasePlugin(ABC):
    """Abstract Base Class for all SDVS Inspection Plugins."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Brief description of what the plugin checks."""
        pass

    @abstractmethod
    def inspect(self, driver_path: str, driver_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes the security inspection logic.

        Args:
            driver_path: Path to the .sys driver file.
            driver_info: Metadata dictionary (hash, signature status, etc.).

        Returns:
            Dict containing:
                - "score_deduction": int (0-100 deduction)
                - "findings": list of string findings
                - "risk_flag": bool
        """
        pass