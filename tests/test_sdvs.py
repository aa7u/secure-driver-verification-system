import hashlib
import os
import tempfile
from evaluator import RiskEvaluator
from verifier import DriverVerifier

def test_risk_evaluator_signed():
    """Test driver evaluation for signed status."""
    result = RiskEvaluator.evaluate_driver(driver_name="3ware.sys", has_signature=True)
    assert result["level"] == "LOW RISK"
    assert "officially signed" in result["recommendation"].lower()

def test_risk_evaluator_unsigned():
    """Test driver evaluation for unsigned status."""
    result = RiskEvaluator.evaluate_driver(driver_name="test_unsigned.sys", has_signature=False)
    assert result["level"] == "HIGH RISK"
    assert "do not install" in result["recommendation"].lower()

def test_hash_calculation():
    """Test SHA-256 hash calculation using a dynamic temporary file."""
    test_data = b"SDVS Test Binary Payload"
    expected_hash = hashlib.sha256(test_data).hexdigest()

    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(test_data)
        temp_file_path = temp_file.name

    try:
        calculated_hash = DriverVerifier.get_file_hash(temp_file_path)
        assert calculated_hash == expected_hash
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)