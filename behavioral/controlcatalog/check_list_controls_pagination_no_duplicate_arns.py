"""list-controls-pagination-no-duplicate-arns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-pagination-no-duplicate-arns"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Consecutive ListControls pages (via NextToken) advance through disjoint sets of control ARNs."""
    cc = ctx.client("controlcatalog")

    seen: list[str] = []
    seen_tokens: set[str] = set()
    token = None
    pages_fetched = 0
    for _ in range(4):
        kwargs = {"MaxResults": 5}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_controls(**kwargs)
        pages_fetched += 1
        arns = [c["Arn"] for c in page.get("Controls", [])]
        assert arns, "expected a non-empty page while a NextToken chain is still active"
        for arn in arns:
            assert arn not in seen, f"control {arn} appeared on more than one page"
        seen.extend(arns)
        next_token = page.get("NextToken")
        if next_token:
            assert next_token not in seen_tokens, "NextToken repeated across pages"
            seen_tokens.add(next_token)
        token = next_token
        if not token:
            break

    assert pages_fetched >= 2, (
        f"expected the catalog to span more than one MaxResults=5 page, only fetched {pages_fetched}"
    )
    assert len(seen) > 5, "expected to accumulate results across at least two pages"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
