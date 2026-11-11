"""list-common-controls-pagination-no-duplicate-arns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-common-controls-pagination-no-duplicate-arns"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Walking ListCommonControls to completion via NextToken yields each common control ARN exactly once."""
    cc = ctx.client("controlcatalog")

    seen: list[str] = []
    token = None
    for _ in range(500):
        kwargs = {"MaxResults": 50}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_common_controls(**kwargs)
        arns = [c["Arn"] for c in page.get("CommonControls", [])]
        for arn in arns:
            assert arn not in seen, f"common control {arn} appeared on more than one page"
        seen.extend(arns)
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListCommonControls pagination did not terminate within 500 pages")

    assert len(seen) == len(set(seen))
    assert len(seen) >= 1, "expected the Control Catalog to contain at least one common control"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
