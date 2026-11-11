"""describe-savings-plans-offerings-basic-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offerings-basic-fields"
GROUP = "control-plane"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferings returns well-formed offering records matching the requested filters."""
    sp = ctx.client("savingsplans")
    resp = sp.describe_savings_plans_offerings(
        planTypes=["Compute"],
        paymentOptions=["No Upfront"],
        currencies=["USD"],
        maxResults=10,
    )
    results = resp["searchResults"]
    assert len(results) > 0, "expected at least one Compute / No Upfront / USD offering"
    for offering in results:
        assert offering["planType"] == "Compute", f"expected planType Compute, got {offering['planType']!r}"
        assert offering["paymentOption"] == "No Upfront", (
            f"expected paymentOption 'No Upfront', got {offering['paymentOption']!r}"
        )
        assert offering["currency"] == "USD", f"expected currency USD, got {offering['currency']!r}"
        assert offering["offeringId"], f"expected non-empty offeringId, got {offering['offeringId']!r}"
        assert offering["durationSeconds"] > 0, (
            f"expected positive durationSeconds, got {offering['durationSeconds']!r}"
        )
        assert isinstance(offering["productTypes"], list) and len(offering["productTypes"]) > 0, (
            f"expected non-empty productTypes list, got {offering['productTypes']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
