"""list-objectives-pagination-stitches-consistently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-objectives-pagination-stitches-consistently"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListObjectives NextToken pagination stitches to the same ARNs, in the same order, as an
    unpaginated call over the same span."""
    cc = ctx.client("controlcatalog")
    full = cc.list_objectives(MaxResults=3)
    full_items = full["Objectives"]
    assert len(full_items) == 3, f"expected exactly 3 objectives in a MaxResults=3 page, got {len(full_items)}"

    page1 = cc.list_objectives(MaxResults=1)
    assert len(page1["Objectives"]) == 1, f"MaxResults=1 did not return exactly 1 item, got {len(page1['Objectives'])}"
    token = page1.get("NextToken")
    assert token, "expected a NextToken since more results remain beyond the first item"

    page2 = cc.list_objectives(MaxResults=2, NextToken=token)
    assert len(page2["Objectives"]) == 2, (
        f"continuation page did not respect MaxResults=2, got {len(page2['Objectives'])}"
    )

    stitched_arns = [o["Arn"] for o in page1["Objectives"] + page2["Objectives"]]
    full_arns = [o["Arn"] for o in full_items]
    assert stitched_arns == full_arns, (
        f"paginated stitching {stitched_arns} did not match unpaginated listing {full_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
