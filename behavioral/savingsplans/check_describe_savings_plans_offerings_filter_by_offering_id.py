"""describe-savings-plans-offerings-filter-by-offering-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-savings-plans-offerings-filter-by-offering-id"
GROUP = "control-plane"
SERVICES = ["savingsplans"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSavingsPlansOfferings 'offeringIds' filter narrows the catalog to exactly that offering."""
    sp = ctx.client("savingsplans")
    seed = sp.describe_savings_plans_offerings(planTypes=["Compute"], maxResults=5)
    seed_results = seed["searchResults"]
    assert len(seed_results) > 0, "expected at least one Compute offering in the catalog seed"
    target_id = seed_results[0]["offeringId"]

    resp = sp.describe_savings_plans_offerings(offeringIds=[target_id])
    results = resp["searchResults"]
    # offeringId is unique per catalog entry, so filtering on exactly one id narrows to exactly
    # one result -- not merely "at least one".
    assert len(results) == 1, f"expected exactly one offering for {target_id}, got {len(results)}"
    assert results[0]["offeringId"] == target_id, (
        f"expected offeringId {target_id}, got {results[0]['offeringId']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
