"""describe-savings-plans-offering-rates-basic-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offering-rates-basic-fields"
GROUP = "control-plane"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferingRates returns rate records with a nested, consistent offering."""
    sp = ctx.client("savingsplans")
    resp = sp.describe_savings_plans_offering_rates(
        savingsPlanTypes=["Compute"],
        savingsPlanPaymentOptions=["No Upfront"],
        maxResults=10,
    )
    results = resp["searchResults"]
    assert len(results) > 0, "expected at least one Compute / No Upfront offering rate"
    for rate in results:
        assert float(rate["rate"]) >= 0, f"expected a non-negative rate, got {rate['rate']!r}"
        assert rate["unit"], f"expected a non-empty unit, got {rate['unit']!r}"
        assert rate["productType"], f"expected a non-empty productType, got {rate['productType']!r}"
        assert rate["serviceCode"], f"expected a non-empty serviceCode, got {rate['serviceCode']!r}"
        offering = rate["savingsPlanOffering"]
        assert offering["paymentOption"] == "No Upfront", (
            f"expected paymentOption 'No Upfront' (as requested), got {offering['paymentOption']!r}"
        )
        assert offering["planType"] == "Compute", (
            f"expected planType 'Compute' (as requested), got {offering['planType']!r}"
        )
        assert offering["offeringId"], f"expected a non-empty offeringId, got {offering['offeringId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
