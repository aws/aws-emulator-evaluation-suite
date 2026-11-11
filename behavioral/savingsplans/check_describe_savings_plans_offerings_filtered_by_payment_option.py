"""describe-savings-plans-offerings-filtered-by-payment-option."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offerings-filtered-by-payment-option"
GROUP = "control-plane"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferings 'paymentOptions' filter restricts every offering to that payment option."""
    sp = ctx.client("savingsplans")
    resp = sp.describe_savings_plans_offerings(
        planTypes=["Compute"],
        paymentOptions=["No Upfront"],
        maxResults=20,
    )
    results = resp["searchResults"]
    assert len(results) > 0, "expected at least one No Upfront Compute offering"
    for offering in results:
        assert offering["paymentOption"] == "No Upfront"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
