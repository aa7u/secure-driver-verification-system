import os
import pytest
from collector import DriverCollector
from verifier import DriverVerifier
from evaluator import RiskEvaluator

def test_driver_collector_returns_list():
    """Verify that collector retrieves installed drivers."""
    drivers = DriverCollector.get_installed_drivers(limit=2)
    assert isinstance(drivers, list)
    if drivers:
        assert "name" in drivers[0]
        assert "path" in drivers[0]

def test_verifier_file_hash_valid():
    """Verify SHA-256 calculation on a known Windows driver."""
    sample_driver = r"C:\Windows\System32\drivers\null.sys"
    if os.path.exists(sample_driver):
        file_hash = DriverVerifier.get_file_hash(sample_driver)
        assert isinstance(file_hash, str)
        assert len(file_hash) == 64

def test_risk_evaluator_levels():
    """Test the risk scoring logic."""
    unsigned_risk = RiskEvaluator.evaluate_driver("sample_driver.sys", has_signature=False)
    assert unsigned_risk["level"] == "HIGH RISK"

    signed_risk = RiskEvaluator.evaluate_driver("sample_driver.sys", has_signature=True)
    assert signed_risk["level"] == "LOW RISK"