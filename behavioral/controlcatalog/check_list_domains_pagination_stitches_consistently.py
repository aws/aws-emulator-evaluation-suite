"""list-domains-pagination-stitches-consistently."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-domains-pagination-stitches-consistently"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDomains NextToken pagination stitches to the same ARNs, in the same order, as an
    unpaginated call over the same span."""
    cc = ctx.client("controlcatalog")
    full = cc.list_domains(MaxResults=3)
    full_items = full["Domains"]
    assert len(full_items) == 3, f"expected exactly 3 domains in a MaxResults=3 page, got {len(full_items)}"

    page1 = cc.list_domains(MaxResults=1)
    assert len(page1["Domains"]) == 1, f"expected exactly 1 domain in a MaxResults=1 page, got {len(page1['Domains'])}"
    token = page1.get("NextToken")
    assert token, "expected a NextToken since more results remain beyond the first item"

    page2 = cc.list_domains(MaxResults=2, NextToken=token)
    assert len(page2["Domains"]) == 2, f"expected exactly 2 domains in the MaxResults=2 second page, got {len(page2['Domains'])}"

    stitched_arns = [d["Arn"] for d in page1["Domains"] + page2["Domains"]]
    full_arns = [d["Arn"] for d in full_items]
    assert stitched_arns == full_arns, (
        f"paginated stitching {stitched_arns} did not match unpaginated listing {full_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
