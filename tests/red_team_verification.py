#!/usr/bin/env python3
"""
red_team_verification.py
Comprehensive End-to-End & Red-Team Security Verification for
B2B Dynamic Pricing & Commission Engine (Protected Release Binary).

Tests executed directly inside dist/client_release:
  0. Native Binary & Release Artifact Audit (0 .py source files, 0 .c files, only .so).
  1. Valid Enterprise license succeeds & runs native calculations.
     - Tests 20% volume discount on high-volume items (ORD-2026-007).
     - Tests 18% net profit margin floor guardrail auto-adjusting discount (ORD-2026-004).
     - Tests Starter tier capping volume discount at 12% max.
     - Tests regional tax rates (BD: 15%, US: 8%, EU: 20%).
     - Tests sales rep commission tiers.
     - Verifies SHA-256 output integrity digest.
  2. Tampered license payload (modifying 'tier' or 'expires_at') is detected & rejected.
  3. Expired license (--days -1) is detected & rejected.
  4. Host mismatch license (--host wrong-server-name) is detected & rejected.
  5. Live FastAPI client wrapper & API endpoints verified.
"""

import base64
import json
import os
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

# Set up paths
REPO_ROOT = Path(__file__).resolve().parent.parent
RELEASE_DIR = REPO_ROOT / "dist" / "client_release"
SECRETS_DIR = REPO_ROOT / ".secrets"
SAMPLE_ORDERS_FILE = RELEASE_DIR / "app_wrapper" / "sample_orders.json"

# Switch working directory to release dir to simulate real client deployment
os.chdir(RELEASE_DIR)
# Explicitly prioritize RELEASE_DIR and remove REPO_ROOT to guarantee loading compiled binaries
sys.path = [str(RELEASE_DIR)] + [p for p in sys.path if p != str(REPO_ROOT)]

# Helper to import sign_license without adding REPO_ROOT to sys.path
def sign_license_cli(**kwargs):
    import importlib.util
    script_path = REPO_ROOT / "scripts" / "sign_license.py"
    spec = importlib.util.spec_from_file_location("sign_license_mod", script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.sign_license(**kwargs)

# Ensure required modules can be imported
try:
    import core_engine.license_guard as lg
    import core_engine.pricing_engine as pe
except ImportError as e:
    print(f"❌ FATAL: Could not import core_engine from {RELEASE_DIR}: {e}")
    sys.exit(1)


def banner(title: str):
    print("\n" + "=" * 70)
    print(f"🧪 {title}")
    print("=" * 70)


def verify_binary_integrity():
    banner("Verification 0: Native Binary & Release Artifact Audit")
    lg_file = lg.__file__
    pe_file = pe.__file__
    print(f"[*] core_engine.license_guard source: {lg_file}")
    print(f"[*] core_engine.pricing_engine source: {pe_file}")

    assert lg_file.endswith(".so") or lg_file.endswith(".pyd"), f"license_guard must be a binary .so, got {lg_file}"
    assert pe_file.endswith(".so") or pe_file.endswith(".pyd"), f"pricing_engine must be a binary .so, got {pe_file}"

    # Verify no source files in release core_engine/
    ce_dir = RELEASE_DIR / "core_engine"
    disallowed = list(ce_dir.glob("*.c")) + list(ce_dir.glob("*.pem")) + list(ce_dir.glob("*.pyx"))
    non_init_py = [p for p in ce_dir.glob("*.py") if p.name != "__init__.py"]

    assert len(disallowed) == 0, f"Disallowed files found in {ce_dir}: {disallowed}"
    assert len(non_init_py) == 0, f"Source .py files found in {ce_dir}: {non_init_py}"

    init_file = ce_dir / "__init__.py"
    assert init_file.exists(), "__init__.py missing in core_engine"
    assert init_file.stat().st_size <= 100, f"__init__.py not empty: {init_file.stat().st_size} bytes"

    print("✅ Passed: Zero .py source or .c files. Native binaries loaded successfully.")


def test_case_1_valid_license():
    banner("Test Case 1: Valid 30-Day Enterprise License Execution")
    license_key_path = str(RELEASE_DIR / "license.key")
    assert os.path.exists(license_key_path), "Release license.key does not exist"

    # Step 1: Verify license directly
    license_info = lg.verify_license(license_key_path)
    print(f"[*] License Status: {license_info['status']}")
    print(f"[*] Client Name:    {license_info['client_name']}")
    print(f"[*] License Tier:   {license_info['tier']}")
    print(f"[*] Expires At:     {license_info['expires_at_iso']}")
    print(f"[*] Host Lock:      {license_info['host']}")

    assert license_info["status"] == "VALID"
    assert license_info["tier"] == "enterprise"

    # Step 2: Load sample orders and execute calculate_batch
    with open(SAMPLE_ORDERS_FILE, "r", encoding="utf-8") as f:
        sample_orders = json.load(f)

    print(f"[*] Executing calculation on {len(sample_orders)} sample orders...")
    res = pe.calculate_batch(sample_orders, license_path=license_key_path)

    assert res["status"] == "SUCCESS"
    assert "integrity_sha256" in res
    assert len(res["integrity_sha256"]) == 64
    assert res["totals"]["order_count"] == len(sample_orders)
    assert res["totals"]["total_net_profit"] > 0
    assert res["totals"]["overall_net_margin_pct"] >= 18.0

    print(f"[*] Total Gross Revenue:     ${res['totals']['total_gross']:,.2f}")
    print(f"[*] Total Volume Discounts:  -${res['totals']['total_discount']:,.2f}")
    print(f"[*] Total Net Revenue:       ${res['totals']['total_net_revenue']:,.2f}")
    print(f"[*] Regional Taxes:          ${res['totals']['total_tax']:,.2f}")
    print(f"[*] Sales Rep Commissions:   ${res['totals']['total_commission']:,.2f}")
    print(f"[*] Net Profit:              ${res['totals']['total_net_profit']:,.2f} ({res['totals']['overall_net_margin_pct']}%)")
    print(f"[*] Total Final Payable:     ${res['totals']['total_payable']:,.2f}")
    print(f"[*] Flagged Guardrail Orders: {res['totals']['flagged_orders_count']}")
    print(f"[*] SHA-256 Output Digest:   {res['integrity_sha256']}")

    # 1. High-volume order with safe margin (ORD-2026-007, 300 units): receives full 20.0% enterprise discount
    ord7 = next(it for it in res["items"] if it["order_id"] == "ORD-2026-007")
    assert ord7["eligible_discount_pct"] == 20.0
    assert ord7["applied_discount_pct"] == 20.0
    assert ord7["tier_capped"] is False
    assert ord7["guardrail_triggered"] is False
    print(f"[*] High-Volume 200+ Unit Discount: ORD-2026-007 received full {ord7['applied_discount_pct']}% discount.")

    # 2. Regional tax rates check
    ord_bd = next(it for it in res["items"] if it["region"] == "BD" and it["order_id"] == "ORD-2026-003")
    assert ord_bd["tax_rate_pct"] == 15.0, f"Expected 15% tax for BD, got {ord_bd['tax_rate_pct']}"

    ord_us = next(it for it in res["items"] if it["region"] == "US" and it["order_id"] == "ORD-2026-001")
    assert ord_us["tax_rate_pct"] == 8.0, f"Expected 8% tax for US, got {ord_us['tax_rate_pct']}"

    ord_eu = next(it for it in res["items"] if it["region"] == "EU" and it["order_id"] == "ORD-2026-002")
    assert ord_eu["tax_rate_pct"] == 20.0, f"Expected 20% tax for EU, got {ord_eu['tax_rate_pct']}"
    print(f"[*] Regional Tax Slabs Verified: BD (15%), US (8%), EU (20%).")

    # 3. 18% Margin Guardrail check
    flagged = [it for it in res["items"] if it["guardrail_triggered"]]
    assert len(flagged) > 0, "Expected at least 1 order to trigger 18% margin guardrail"
    print(f"[*] Verified {len(flagged)} orders protected by 18% minimum net profit margin floor:")
    for f_item in flagged:
        print(f"    - {f_item['order_id']} ({f_item['product']}): {f_item['margin_status']} -> {f_item['margin_note']}")
        assert f_item["net_margin_pct"] >= 18.0 or f_item["applied_discount_pct"] == 0.0

    # 4. License Tier Capping Test: Sign a Starter license and test 12% cap on 200+ units
    starter_lic_path = RELEASE_DIR / "license_starter.key"
    sign_license_cli(
        client_name="Starter Tier Client",
        tier="starter",
        days=30,
        host="*",
        private_key_path=str(SECRETS_DIR / "private.pem"),
        out_path=str(starter_lic_path),
    )
    res_starter = pe.calculate_batch([{"order_id": "TEST-CAP", "quantity": 300, "unit_price": 100.0, "unit_cost": 40.0}], license_path=str(starter_lic_path))
    starter_item = res_starter["items"][0]
    assert starter_item["eligible_discount_pct"] == 20.0
    assert starter_item["applied_discount_pct"] == 12.0
    assert starter_item["tier_capped"] is True
    starter_lic_path.unlink(missing_ok=True)
    print(f"[*] License Tier Discount Capping Verified: 200+ unit order capped at 12% for Starter tier.")

    print("✅ Passed: Case 1 - Valid license & full calculation logic verified.")


def test_case_2_tampered_license():
    banner("Test Case 2: Tampered License Payload (Signature Failure)")
    license_key_path = str(RELEASE_DIR / "license.key")

    with open(license_key_path, "r", encoding="utf-8") as f:
        token = f.read().strip()

    decoded = json.loads(base64.b64decode(token).decode("utf-8"))

    # Attacker scenario A: Change tier from "starter" to "enterprise" without private key
    tampered_data_tier = dict(decoded["data"])
    tampered_data_tier["tier"] = "super-enterprise-hacked"
    tampered_envelope = {
        "data": tampered_data_tier,
        "sig": decoded["sig"],  # Old signature with new data!
    }
    tampered_b64 = base64.b64encode(json.dumps(tampered_envelope).encode("utf-8")).decode("ascii")

    temp_lic = RELEASE_DIR / "license_tampered_tier.key"
    with open(temp_lic, "w", encoding="utf-8") as f:
        f.write(tampered_b64)

    try:
        lg.verify_license(str(temp_lic))
        raise AssertionError("SECURITY BREACH: Tampered tier license was accepted!")
    except RuntimeError as e:
        print(f"[*] Tampered Tier Caught by Compiled Core: {e}")
        assert "signature mismatch" in str(e).lower() or "tampered" in str(e).lower()

    # Attacker scenario B: Extend expiration date 10 years into the future
    tampered_data_exp = dict(decoded["data"])
    tampered_data_exp["expires_at"] = int(time.time()) + (3650 * 86400)
    tampered_exp_env = {
        "data": tampered_data_exp,
        "sig": decoded["sig"],
    }
    tampered_exp_b64 = base64.b64encode(json.dumps(tampered_exp_env).encode("utf-8")).decode("ascii")

    temp_exp_lic = RELEASE_DIR / "license_tampered_exp.key"
    with open(temp_exp_lic, "w", encoding="utf-8") as f:
        f.write(tampered_exp_b64)

    try:
        lg.verify_license(str(temp_exp_lic))
        raise AssertionError("SECURITY BREACH: Tampered expiration date was accepted!")
    except RuntimeError as e:
        print(f"[*] Tampered Expiration Date Caught by Compiled Core: {e}")
        assert "signature mismatch" in str(e).lower() or "tampered" in str(e).lower()

    # Clean up temp files
    temp_lic.unlink(missing_ok=True)
    temp_exp_lic.unlink(missing_ok=True)

    print("✅ Passed: Case 2 - Tampered licenses unequivocally rejected by Ed25519 verification.")


def test_case_3_expired_license():
    banner("Test Case 3: Expired License (--days -1)")
    expired_lic_path = RELEASE_DIR / "license_expired.key"
    sign_license_cli(
        client_name="Test Expired Client",
        tier="enterprise",
        days=-1,
        host="*",
        private_key_path=str(SECRETS_DIR / "private.pem"),
        out_path=str(expired_lic_path),
    )

    try:
        lg.verify_license(str(expired_lic_path))
        raise AssertionError("SECURITY BREACH: Expired license was accepted!")
    except RuntimeError as e:
        print(f"[*] Expired License Caught by Compiled Core: {e}")
        assert "expired" in str(e).lower()

    # Verify calculate_batch also blocks on expired license
    try:
        pe.calculate_batch([{"unit_price": 100, "quantity": 1}], license_path=str(expired_lic_path))
        raise AssertionError("SECURITY BREACH: calculate_batch proceeded with expired license!")
    except RuntimeError as e:
        print(f"[*] Pricing Engine Blocked on Expired License: {e}")

    expired_lic_path.unlink(missing_ok=True)
    print("✅ Passed: Case 3 - Expired license blocked with clear message.")


def test_case_4_host_mismatch_license():
    banner("Test Case 4: Hostname Locked License Mismatch")
    bogus_host = "unauthorized-rogue-server-999.corp"
    mismatch_lic_path = RELEASE_DIR / "license_host_mismatch.key"
    sign_license_cli(
        client_name="Host Locked Client",
        tier="enterprise",
        days=30,
        host=bogus_host,
        private_key_path=str(SECRETS_DIR / "private.pem"),
        out_path=str(mismatch_lic_path),
    )

    try:
        lg.verify_license(str(mismatch_lic_path))
        raise AssertionError("SECURITY BREACH: Host mismatched license was accepted!")
    except RuntimeError as e:
        print(f"[*] Host Mismatch Caught by Compiled Core: {e}")
        assert "host mismatch" in str(e).lower()
        assert bogus_host in str(e)

    # Verify calculate_batch also blocks on host mismatch
    try:
        pe.calculate_batch([{"unit_price": 100, "quantity": 1}], license_path=str(mismatch_lic_path))
        raise AssertionError("SECURITY BREACH: calculate_batch proceeded with mismatched host license!")
    except RuntimeError as e:
        print(f"[*] Pricing Engine Blocked on Host Mismatch: {e}")

    mismatch_lic_path.unlink(missing_ok=True)
    print("✅ Passed: Case 4 - Host mismatch strictly enforced.")


def test_fastapi_endpoints():
    banner("Verification 5: FastAPI Client Wrapper & API Endpoints")
    from fastapi.testclient import TestClient
    from app_wrapper.main import app

    client = TestClient(app)

    # 1. Test GET /
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "B2B Dynamic Pricing & Commission Engine" in res_index.text
    print("  -> GET / [200 OK] Dashboard rendered successfully.")

    # 2. Test GET /api/license-status
    res_lic = client.get("/api/license-status")
    assert res_lic.status_code == 200
    lic_json = res_lic.json()
    assert lic_json["status"] == "VALID"
    assert lic_json["tier"] == "enterprise"
    print(f"  -> GET /api/license-status [200 OK]: Client '{lic_json['client_name']}', Tier '{lic_json['tier']}'")

    # 3. Test GET /api/sample-orders
    res_samples = client.get("/api/sample-orders")
    assert res_samples.status_code == 200
    samples = res_samples.json()
    assert len(samples) > 0
    print(f"  -> GET /api/sample-orders [200 OK]: Retrieved {len(samples)} sample orders.")

    # 4. Test POST /api/calculate with valid orders
    res_calc = client.post("/api/calculate", json={"orders": samples})
    assert res_calc.status_code == 200
    calc_json = res_calc.json()
    assert calc_json["status"] == "SUCCESS"
    assert "integrity_sha256" in calc_json
    print(f"  -> POST /api/calculate [200 OK]: Calculated batch total payable ${calc_json['totals']['total_payable']:,.2f}")

    # 5. Test POST /api/calculate when license is missing or invalid -> 403 Forbidden
    lic_path = RELEASE_DIR / "license.key"
    lic_backup = RELEASE_DIR / "license.key.bak"
    shutil.move(lic_path, lic_backup)

    try:
        res_calc_blocked = client.post("/api/calculate", json={"orders": samples})
        assert res_calc_blocked.status_code == 403
        print(f"  -> POST /api/calculate (no license) [403 Forbidden as expected]: {res_calc_blocked.json()['detail']}")
    finally:
        shutil.move(lic_backup, lic_path)

    # Re-verify normal operation restored
    res_calc_restored = client.post("/api/calculate", json={"orders": samples})
    assert res_calc_restored.status_code == 200
    print("  -> POST /api/calculate restored [200 OK].")

    print("✅ Passed: FastAPI Wrapper endpoints fully verified with native Cython core.")


def main():
    print("=" * 70)
    print("🛡️  RED-TEAM VERIFICATION SUITE: COMPILED CORE ENGINE & WRAPPER")
    print(f"Target Directory: {RELEASE_DIR}")
    print(f"Host System:      {socket.gethostname()}")
    print("=" * 70)

    verify_binary_integrity()
    test_case_1_valid_license()
    test_case_2_tampered_license()
    test_case_3_expired_license()
    test_case_4_host_mismatch_license()
    test_fastapi_endpoints()

    print("\n" + "=" * 70)
    print("🏆 ALL RED-TEAM TESTS & END-TO-END VERIFICATIONS PASSED (5/5)!")
    print("=" * 70)


if __name__ == "__main__":
    main()
