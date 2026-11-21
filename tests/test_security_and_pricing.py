"""
test_security_and_pricing.py
Automated pytest test suite verifying the compiled release artifact inside dist/client_release.
Tests:
  - Source-leak audit (native binary verification, zero source .py/.c files)
  - Mathematical correctness of dynamic pricing, volume tiers, taxes, and commissions
  - Minimum 18% net profit margin guardrail enforcement
  - License tier capabilities and discount capping (Starter vs Enterprise)
  - Cryptographic tamper detection on payload modifications
  - Expiration and hostname lockouts
  - Live FastAPI web wrapper endpoints
"""

import base64
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = REPO_ROOT / "dist" / "client_release"
CORE_ENGINE_DIR = DIST_DIR / "core_engine"
SECRETS_DIR = REPO_ROOT / ".secrets"


def load_module_from_path(module_name: str, file_path: Path):
    """Load a Python or compiled C-extension module from an exact file path."""
    spec = importlib.util.spec_from_file_location(module_name, str(file_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session", autouse=True)
def ensure_release_built():
    """Build the release if dist/client_release does not already exist with binaries."""
    binaries = list(CORE_ENGINE_DIR.glob("*.so")) + list(CORE_ENGINE_DIR.glob("*.pyd"))
    if not (DIST_DIR.exists() and len(binaries) >= 2):
        res = subprocess.run(["bash", str(REPO_ROOT / "scripts" / "build_release.sh")], cwd=str(REPO_ROOT), capture_output=True, text=True)
        if res.returncode != 0:
            pytest.fail(f"build_release.sh failed during test setup:\n{res.stderr}\n{res.stdout}")


@pytest.fixture(scope="session")
def compiled_engine(ensure_release_built):
    """Load the compiled core_engine binaries from dist/client_release."""
    if str(DIST_DIR) not in sys.path:
        sys.path.insert(0, str(DIST_DIR))

    import core_engine.license_guard as lg
    import core_engine.pricing_engine as pe

    return {"license_guard": lg, "pricing_engine": pe}


@pytest.fixture(scope="session")
def sign_tool():
    """Load the signing utility from scripts."""
    script_path = REPO_ROOT / "scripts" / "sign_license.py"
    mod = load_module_from_path("sign_license_script", script_path)
    return mod.sign_license


def test_source_leak_and_binary_audit(compiled_engine):
    """Verify core_engine contains only compiled binaries and zero readable source files."""
    lg = compiled_engine["license_guard"]
    pe = compiled_engine["pricing_engine"]

    assert lg.__file__.endswith((".so", ".pyd")), f"license_guard must be compiled binary, got {lg.__file__}"
    assert pe.__file__.endswith((".so", ".pyd")), f"pricing_engine must be compiled binary, got {pe.__file__}"

    prohibited_files = list(CORE_ENGINE_DIR.glob("*.c")) + list(CORE_ENGINE_DIR.glob("*.pem")) + list(CORE_ENGINE_DIR.glob("*.pyx"))
    assert len(prohibited_files) == 0, f"Found prohibited source/secret files: {prohibited_files}"

    py_files = [p for p in CORE_ENGINE_DIR.glob("*.py") if p.name != "__init__.py"]
    assert len(py_files) == 0, f"Found source Python files in release core_engine: {py_files}"

    init_file = CORE_ENGINE_DIR / "__init__.py"
    assert init_file.exists(), "Empty package marker __init__.py missing"
    assert init_file.stat().st_size <= 100, "__init__.py should be an empty package marker"


def test_valid_license_and_pricing_calculation(compiled_engine):
    """Verify that calculations succeed under a valid enterprise license."""
    pe = compiled_engine["pricing_engine"]
    license_file = DIST_DIR / "license.key"
    assert license_file.exists(), "Release license.key is missing"

    sample_orders_file = DIST_DIR / "app_wrapper" / "sample_orders.json"
    with open(sample_orders_file, "r", encoding="utf-8") as f:
        orders = json.load(f)

    result = pe.calculate_batch(orders, license_path=str(license_file))

    assert result["status"] == "SUCCESS"
    assert len(result["integrity_sha256"]) == 64
    totals = result["totals"]
    assert totals["order_count"] == len(orders)
    assert totals["total_gross"] > 0
    assert totals["total_net_revenue"] > 0
    assert totals["total_net_profit"] > 0

    # Verify regional tax rates
    items = result["items"]
    bd_item = next(it for it in items if it["region"] == "BD")
    us_item = next(it for it in items if it["region"] == "US")
    eu_item = next(it for it in items if it["region"] == "EU")

    assert bd_item["tax_rate_pct"] == 15.0
    assert us_item["tax_rate_pct"] == 8.0
    assert eu_item["tax_rate_pct"] == 20.0

    # Verify 18% minimum net profit margin guardrail enforcement
    flagged = [it for it in items if it["guardrail_triggered"]]
    assert len(flagged) > 0, "Expected at least 1 order to trigger margin guardrail"
    for item in flagged:
        assert item["net_margin_pct"] >= 18.0 or item["applied_discount_pct"] == 0.0


def test_tier_enforcement_and_discount_capping(compiled_engine, sign_tool, tmp_path):
    """Verify that 'starter' tier caps volume discounts at 12% while 'enterprise' unlocks 20%."""
    pe = compiled_engine["pricing_engine"]
    priv_key = SECRETS_DIR / "private.pem"

    order_bulk = [{"order_id": "BULK-1", "quantity": 300, "unit_price": 100.0, "unit_cost": 40.0}]

    # 1. Starter Tier -> Max 12%
    starter_key = tmp_path / "starter.key"
    sign_tool(client_name="Test Starter", tier="starter", days=10, host="*", private_key_path=str(priv_key), out_path=str(starter_key))
    starter_res = pe.calculate_batch(order_bulk, license_path=str(starter_key))
    starter_item = starter_res["items"][0]
    assert starter_item["eligible_discount_pct"] == 20.0
    assert starter_item["applied_discount_pct"] == 12.0
    assert starter_item["tier_capped"] is True

    # 2. Enterprise Tier -> Full 20%
    enterprise_key = tmp_path / "enterprise.key"
    sign_tool(client_name="Test Enterprise", tier="enterprise", days=10, host="*", private_key_path=str(priv_key), out_path=str(enterprise_key))
    ent_res = pe.calculate_batch(order_bulk, license_path=str(enterprise_key))
    ent_item = ent_res["items"][0]
    assert ent_item["eligible_discount_pct"] == 20.0
    assert ent_item["applied_discount_pct"] == 20.0
    assert ent_item["tier_capped"] is False


def test_tamper_resistance(compiled_engine, tmp_path):
    """Assert that modifying license payload without re-signing raises signature verification failure."""
    lg = compiled_engine["license_guard"]
    valid_key = DIST_DIR / "license.key"

    with open(valid_key, "r", encoding="utf-8") as f:
        raw_b64 = f.read().strip()

    envelope = json.loads(base64.b64decode(raw_b64).decode("utf-8"))

    # Modify tier
    tampered_data = dict(envelope["data"])
    tampered_data["tier"] = "unauthorized_escalated_tier"
    tampered_token = base64.b64encode(json.dumps({"data": tampered_data, "sig": envelope["sig"]}).encode("utf-8")).decode("ascii")

    tampered_key_path = tmp_path / "tampered.key"
    tampered_key_path.write_text(tampered_token, encoding="utf-8")

    with pytest.raises(RuntimeError, match="Cryptographic signature mismatch|tampered"):
        lg.verify_license(str(tampered_key_path))


def test_expiry_and_hostname_binding(compiled_engine, sign_tool, tmp_path):
    """Assert that expired licenses and mismatched hostnames are blocked immediately."""
    lg = compiled_engine["license_guard"]
    pe = compiled_engine["pricing_engine"]
    priv_key = SECRETS_DIR / "private.pem"

    # Expired token
    expired_key = tmp_path / "expired.key"
    sign_tool(client_name="Expired Co", tier="enterprise", days=-1, host="*", private_key_path=str(priv_key), out_path=str(expired_key))
    with pytest.raises(RuntimeError, match="expired"):
        lg.verify_license(str(expired_key))
    with pytest.raises(RuntimeError, match="expired"):
        pe.calculate_batch([{"unit_price": 50, "quantity": 1}], license_path=str(expired_key))

    # Host mismatch
    host_key = tmp_path / "host_mismatch.key"
    sign_tool(client_name="Host Co", tier="enterprise", days=10, host="unauthorized-server-node-404", private_key_path=str(priv_key), out_path=str(host_key))
    with pytest.raises(RuntimeError, match="Host mismatch"):
        lg.verify_license(str(host_key))
    with pytest.raises(RuntimeError, match="Host mismatch"):
        pe.calculate_batch([{"unit_price": 50, "quantity": 1}], license_path=str(host_key))


def test_fastapi_wrapper_endpoints():
    """Verify HTTP behavior across all wrapper API routes."""
    from app_wrapper.main import app

    client = TestClient(app)

    # Dashboard UI
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "B2B Dynamic Pricing & Commission Engine" in res_index.text

    # License Status
    res_status = client.get("/api/license-status")
    assert res_status.status_code == 200
    assert res_status.json()["status"] == "VALID"

    # Sample Orders
    res_samples = client.get("/api/sample-orders")
    assert res_samples.status_code == 200
    orders = res_samples.json()
    assert len(orders) > 0

    # Calculation API with valid license
    res_calc = client.post("/api/calculate", json={"orders": orders})
    assert res_calc.status_code == 200
    calc_data = res_calc.json()
    assert calc_data["status"] == "SUCCESS"
    assert "integrity_sha256" in calc_data

    # Calculation API blocked when license is missing
    lic_file = DIST_DIR / "license.key"
    lic_bak = DIST_DIR / "license.key.bak"
    shutil.move(lic_file, lic_bak)
    try:
        res_blocked = client.post("/api/calculate", json={"orders": orders})
        assert res_blocked.status_code == 403
    finally:
        shutil.move(lic_bak, lic_file)

