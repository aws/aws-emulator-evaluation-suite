"""list-controls-pagination-no-duplicates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-pagination-no-duplicates"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Consecutive ListControls pages return disjoint sets of control ARNs."""
    cc = ctx.client("controlcatalog")
    page1 = cc.list_controls(MaxResults=5)
    controls1 = page1.get("Controls", [])
    assert len(controls1) == 5, "expected a full first page of 5 controls from a large catalog"
    token = page1.get("NextToken")
    assert token, "expected a NextToken after the first page of a large catalog"

    page2 = cc.list_controls(MaxResults=5, NextToken=token)
    controls2 = page2.get("Controls", [])
    assert len(controls2) > 0, "expected a non-empty second page while a NextToken was returned"

    arns1 = {c["Arn"] for c in controls1}
    arns2 = {c["Arn"] for c in controls2}
    assert arns1.isdisjoint(arns2), "pages 1 and 2 shared control ARNs"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
