"""
pricing_engine.py
Core Calculation Engine for B2B Dynamic Pricing, Regional Taxation,
Sales Rep Commissions, and Net Profit Margin Guardrails.
Compiled to native binaries in release distributions.
"""

import hashlib
import json
import time
from .license_guard import verify_license

# Regional Tax Slabs
TAX_SLABS = {
    "BD": 0.15,      # Bangladesh VAT 15%
    "US": 0.08,      # US Average Sales Tax 8%
    "EU": 0.20,      # European Standard VAT 20%
}
DEFAULT_TAX_RATE = 0.10  # Standard fallback 10%

# Tiered Sales Rep Commission Slabs (based on order net value)
def _get_commission_rate(net_value: float) -> float:
    if net_value >= 20000:
        return 0.08  # 8% for enterprise-scale deals
    elif net_value >= 5000:
        return 0.06  # 6% for mid-market deals
    else:
        return 0.04  # 4% for standard orders

# Minimum Net Profit Margin Floor Guardrail
MIN_PROFIT_MARGIN_FLOOR = 0.18  # 18.0%


def _compute_volume_discount(quantity: int, tier: str) -> tuple[float, float, bool]:
    """
    Computes volume discount percentage based on quantity and license tier cap.
    Returns (raw_discount_pct, applied_discount_pct, is_capped)
    """
    # Base volume tiers:
    # 200+ units: 20%
    # 50+ units:  12%
    # 10+ units:  5%
    # <10 units:  0%
    if quantity >= 200:
        raw_discount = 20.0
    elif quantity >= 50:
        raw_discount = 12.0
    elif quantity >= 10:
        raw_discount = 5.0
    else:
        raw_discount = 0.0

    # License Tier Caps:
    # 'starter' -> capped at 12.0%
    # 'standard' -> capped at 15.0%
    # 'enterprise' -> full 20.0%
    tier_cap = 20.0
    if tier == "starter":
        tier_cap = 12.0
    elif tier == "standard":
        tier_cap = 15.0

    applied_discount = min(raw_discount, tier_cap)
    is_capped = raw_discount > applied_discount
    return raw_discount, applied_discount, is_capped


def calculate_batch(orders: list[dict], license_path: str = "license.key") -> dict:
    """
    Executes pricing, discount capping, tax calculation, sales commission,
    and 18% net profit margin guardrails across a batch of B2B orders.
    Enforces active, valid cryptographic license before running.
    """
    # Strict license verification before calculation
    license_info = verify_license(license_path)
    tier = license_info.get("tier", "starter").lower()

    processed_items = []
    total_gross = 0.0
    total_discount = 0.0
    total_net_revenue = 0.0
    total_tax = 0.0
    total_commission = 0.0
    total_cost = 0.0
    total_net_profit = 0.0
    total_units = 0
    flagged_orders_count = 0

    for idx, order in enumerate(orders):
        order_id = str(order.get("order_id", f"ORD-{idx + 1:04d}"))
        product = str(order.get("product", "Standard Item"))
        quantity = int(order.get("quantity", 1))
        unit_price = float(order.get("unit_price", 0.0))
        sales_rep = str(order.get("sales_rep", "House Account"))
        region = str(order.get("region", "OTHER")).upper()

        # Base Cost / COGS (defaults to 65% of unit price if unspecified)
        unit_cost = float(order.get("unit_cost", round(unit_price * 0.65, 2)))
        total_item_cost = round(unit_cost * quantity, 2)

        gross_price = round(unit_price * quantity, 2)

        # Volume discount computation with tier cap
        eligible_discount_pct, applied_discount_pct, capped_by_tier = _compute_volume_discount(quantity, tier)
        discount_amount = round(gross_price * (applied_discount_pct / 100.0), 2)
        net_revenue = round(gross_price - discount_amount, 2)

        # Commission rate based on order net value
        commission_rate = float(order.get("custom_commission_rate", _get_commission_rate(net_revenue)))
        commission_amount = round(net_revenue * commission_rate, 2)

        # Initial Net Profit calculation
        net_profit = round(net_revenue - total_item_cost - commission_amount, 2)
        net_margin_pct = round((net_profit / net_revenue * 100.0), 2) if net_revenue > 0 else 0.0

        # Hidden Minimum Net Profit Margin Guardrail (18% floor)
        guardrail_triggered = False
        margin_status = "OPTIMAL"
        margin_note = "Net margin exceeds 18.0% minimum threshold."
        adjusted_discount_pct = applied_discount_pct
        adjusted_discount_amount = discount_amount

        if net_revenue > 0 and (net_margin_pct < (MIN_PROFIT_MARGIN_FLOOR * 100.0)):
            guardrail_triggered = True
            flagged_orders_count += 1

            # Margin floor equation:
            # Net Profit = Net_Rev * (1 - commission_rate) - total_cost
            # We require Net_Profit / Net_Rev >= MIN_PROFIT_MARGIN_FLOOR (0.18)
            # Net_Rev * (1 - commission_rate - 0.18) >= total_cost
            denom = 1.0 - commission_rate - MIN_PROFIT_MARGIN_FLOOR
            if denom > 0:
                min_required_net_rev = round(total_item_cost / denom, 2)
            else:
                min_required_net_rev = gross_price

            if min_required_net_rev >= gross_price:
                # Even 0% discount breaches floor due to high unit cost
                adjusted_discount_pct = 0.0
                adjusted_discount_amount = 0.0
                net_revenue = gross_price
                commission_amount = round(net_revenue * commission_rate, 2)
                net_profit = round(net_revenue - total_item_cost - commission_amount, 2)
                net_margin_pct = round((net_profit / net_revenue * 100.0), 2) if net_revenue > 0 else 0.0
                margin_status = "CRITICAL_GUARDRAIL_BREACH"
                margin_note = (
                    f"COGS (${total_item_cost:.2f}) and commission exceed threshold. "
                    f"Discount revoked completely (0.0%). Resulting margin: {net_margin_pct:.1f}%."
                )
            else:
                # Adjust discount downward to maintain exactly the 18% floor
                max_allowed_discount_amt = round(gross_price - min_required_net_rev, 2)
                adjusted_discount_amount = max(0.0, max_allowed_discount_amt)
                adjusted_discount_pct = round((adjusted_discount_amount / gross_price) * 100.0, 2)
                net_revenue = round(gross_price - adjusted_discount_amount, 2)
                commission_amount = round(net_revenue * commission_rate, 2)
                net_profit = round(net_revenue - total_item_cost - commission_amount, 2)
                net_margin_pct = round((net_profit / net_revenue * 100.0), 2) if net_revenue > 0 else 0.0
                margin_status = "GUARDRAIL_PROTECTED"
                margin_note = (
                    f"Discount curtailed from {applied_discount_pct:.1f}% to {adjusted_discount_pct:.1f}% "
                    f"to lock in minimum 18.0% net profit floor."
                )

        # Regional Tax Calculation on net revenue
        tax_rate = TAX_SLABS.get(region, DEFAULT_TAX_RATE)
        tax_amount = round(net_revenue * tax_rate, 2)

        final_order_total = round(net_revenue + tax_amount, 2)

        item_result = {
            "order_id": order_id,
            "product": product,
            "quantity": quantity,
            "unit_price": unit_price,
            "unit_cost": unit_cost,
            "gross_price": gross_price,
            "eligible_discount_pct": eligible_discount_pct,
            "applied_discount_pct": adjusted_discount_pct,
            "initial_discount_pct": applied_discount_pct,
            "tier_capped": capped_by_tier,
            "discount_amount": adjusted_discount_amount,
            "net_revenue": net_revenue,
            "region": region,
            "tax_rate_pct": round(tax_rate * 100.0, 1),
            "tax_amount": tax_amount,
            "sales_rep": sales_rep,
            "commission_rate_pct": round(commission_rate * 100.0, 1),
            "commission_amount": commission_amount,
            "total_cost": total_item_cost,
            "net_profit": net_profit,
            "net_margin_pct": net_margin_pct,
            "guardrail_triggered": guardrail_triggered,
            "margin_status": margin_status,
            "margin_note": margin_note,
            "final_order_total": final_order_total,
        }
        processed_items.append(item_result)

        total_gross += gross_price
        total_discount += adjusted_discount_amount
        total_net_revenue += net_revenue
        total_tax += tax_amount
        total_commission += commission_amount
        total_cost += total_item_cost
        total_net_profit += net_profit
        total_units += quantity

    # Round batch totals
    total_gross = round(total_gross, 2)
    total_discount = round(total_discount, 2)
    total_net_revenue = round(total_net_revenue, 2)
    total_tax = round(total_tax, 2)
    total_commission = round(total_commission, 2)
    total_cost = round(total_cost, 2)
    total_net_profit = round(total_net_profit, 2)
    total_payable = round(total_net_revenue + total_tax, 2)
    overall_net_margin_pct = round((total_net_profit / total_net_revenue * 100.0), 2) if total_net_revenue > 0 else 0.0

    batch_totals = {
        "order_count": len(processed_items),
        "total_units": total_units,
        "total_gross": total_gross,
        "total_discount": total_discount,
        "total_net_revenue": total_net_revenue,
        "total_tax": total_tax,
        "total_commission": total_commission,
        "total_cost": total_cost,
        "total_net_profit": total_net_profit,
        "total_payable": total_payable,
        "overall_net_margin_pct": overall_net_margin_pct,
        "flagged_orders_count": flagged_orders_count,
    }

    # Cryptographic integrity digest of output calculation
    digest_payload = {
        "totals": batch_totals,
        "license_tier": tier,
        "item_checksums": [
            f"{it['order_id']}:{it['final_order_total']}:{it['net_margin_pct']}"
            for it in processed_items
        ],
    }
    canonical_digest = json.dumps(digest_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sha256_digest = hashlib.sha256(canonical_digest).hexdigest()

    return {
        "status": "SUCCESS",
        "calculated_at": int(time.time()),
        "calculated_at_iso": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "license": license_info,
        "totals": batch_totals,
        "items": processed_items,
        "integrity_sha256": sha256_digest,
    }

