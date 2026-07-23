import os
import tempfile
import pytest
from evaluator import RiskEvaluator
from verifier import DriverVerifier

def test_risk_evaluator_signed():
    """Test that a signed driver evaluates to LOW RISK."""
    result = RiskEvaluator.evaluate_driver(driver_name="test_signed.sys", has_signature=True)
    assert result["level"] == "LOW RISK"
    assert "officially signed" in result["recommendation"].lower()

def test_risk_evaluator_unsigned():
    """Test that an unsigned driver evaluates to HIGH RISK."""
    result = RiskEvaluator.evaluate_driver(driver_name="test_unsigned.sys", has_signature=False)
    assert result["level"] == "HIGH RISK"
    assert "do not install" in result["recommendation"].lower()

def test_hash_calculation():
    """Test SHA-256 hash calculation using a temporary file."""
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(b"SDVS Test Binary Payload")
        temp_file_path = temp_file.name

    try:
        calculated_hash = DriverVerifier.get_file_hash(temp_file_path)
        # Expected SHA-256 hash for b"SDVS Test Binary Payload"
        expected_hash = "6798a0f8bfd9a5b3a35bd1600f735d46c8230248e3d09a0cd89aef44a958e9fb"
        assert calculated_hash == expected_hash
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)