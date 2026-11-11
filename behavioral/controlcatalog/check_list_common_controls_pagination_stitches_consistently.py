"""list-common-controls-pagination-stitches-consistently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-common-controls-pagination-stitches-consistently"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCommonControls NextToken pagination stitches to the same ARNs, in the same order, as
    an unpaginated call over the same span."""
    cc = ctx.client("controlcatalog")
    full = cc.list_common_controls(MaxResults=3)
    full_items = full["CommonControls"]
    assert len(full_items) == 3, f"expected exactly 3 common controls in a MaxResults=3 page, got {len(full_items)}"

    page1 = cc.list_common_controls(MaxResults=1)
    assert len(page1["CommonControls"]) == 1, (
        f"expected exactly 1 common control in a MaxResults=1 page, got {len(page1['CommonControls'])}"
    )
    token = page1.get("NextToken")
    assert token, "expected a NextToken since more results remain beyond the first item"

    page2 = cc.list_common_controls(MaxResults=2, NextToken=token)
    assert len(page2["CommonControls"]) == 2, (
        f"expected exactly 2 common controls in a MaxResults=2 continuation page, got {len(page2['CommonControls'])}"
    )

    stitched_arns = [c["Arn"] for c in page1["CommonControls"] + page2["CommonControls"]]
    full_arns = [c["Arn"] for c in full_items]
    assert stitched_arns == full_arns, (
        f"paginated stitching {stitched_arns} did not match unpaginated listing {full_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
