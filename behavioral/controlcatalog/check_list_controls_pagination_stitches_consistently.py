"""list-controls-pagination-stitches-consistently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-pagination-stitches-consistently"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControls NextToken pagination stitches to the same ARNs, in the same order, as an
    unpaginated call for the same total count (catches emulators that ignore MaxResults/NextToken
    and just dump everything, or that reorder pages)."""
    cc = ctx.client("controlcatalog")
    full = cc.list_controls(MaxResults=3)
    full_items = full["Controls"]
    assert len(full_items) == 3, f"expected exactly 3 controls in a MaxResults=3 page, got {len(full_items)}"

    page1 = cc.list_controls(MaxResults=1)
    assert len(page1["Controls"]) == 1, "MaxResults=1 did not return exactly 1 item"
    token = page1.get("NextToken")
    assert token, "expected a NextToken since more results remain beyond the first item"

    page2 = cc.list_controls(MaxResults=2, NextToken=token)
    assert len(page2["Controls"]) == 2, "continuation page did not respect MaxResults=2"

    stitched_arns = [c["Arn"] for c in page1["Controls"] + page2["Controls"]]
    full_arns = [c["Arn"] for c in full_items]
    assert stitched_arns == full_arns, (
        f"paginated stitching {stitched_arns} did not match unpaginated listing {full_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
