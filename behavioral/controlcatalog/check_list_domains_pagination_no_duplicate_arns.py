"""list-domains-pagination-no-duplicate-arns."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-domains-pagination-no-duplicate-arns"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Walking ListDomains to completion via NextToken yields each domain ARN exactly once."""
    cc = ctx.client("controlcatalog")

    seen: list[str] = []
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        arns = [d["Arn"] for d in page.get("Domains", [])]
        for arn in arns:
            assert arn not in seen, f"domain {arn} appeared on more than one page"
        seen.extend(arns)
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListDomains pagination did not terminate within 20 pages")

    assert len(seen) == len(set(seen)), f"expected {len(seen)} unique domains, found {len(seen) - len(set(seen))} duplicate(s) in {seen}"
    assert len(seen) >= 1, "expected the Control Catalog to contain at least one domain"

    full_page = cc.list_domains(MaxResults=100)
    full_arns = {d["Arn"] for d in full_page.get("Domains", [])}
    if not full_page.get("NextToken"):
        # The whole catalog fit in one page: it must be exactly the set collected via pagination.
        assert full_arns == set(seen), (
            f"single-page listing {sorted(full_arns)} did not match the set collected via "
            f"pagination {sorted(seen)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
