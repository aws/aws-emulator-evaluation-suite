"""list-change-sets-filter-by-status-success."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-change-sets-filter-by-status-success"
GROUP = "data-plane"
SERVICES = ["marketplace-catalog"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChangeSets with a Status=FAILED filter returns only change sets whose Status is FAILED."""
    # The Marketplace Catalog API is served only in us-east-1, so every target is called there.
    mp = ctx.client("marketplace-catalog", region="us-east-1")

    resp = mp.list_change_sets(
        Catalog="AWSMarketplace",
        FilterList=[{"Name": "Status", "ValueList": ["FAILED"]}],
        MaxResults=20,
    )
    assert "ChangeSetSummaryList" in resp, f"missing ChangeSetSummaryList in response: {resp}"
    for item in resp["ChangeSetSummaryList"]:
        assert item["Status"] == "FAILED", f"filter leaked non-FAILED item: {item}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
