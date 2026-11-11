"""list-domains-pagination-matches-single-page."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-domains-pagination-matches-single-page"
GROUP = "pagination"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListDomains with a small page size yields the same set of domains as one large page."""
    cc = ctx.client("controlcatalog")

    paged_arns = set()
    page_count = 0
    token = None
    for _ in range(30):
        kwargs = {"MaxResults": 2}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        domains = page.get("Domains", [])
        assert len(domains) <= 2, (
            f"MaxResults=2 was not honored: page {page_count} returned {len(domains)} domains"
        )
        page_count += 1
        for d in domains:
            paged_arns.add(d["Arn"])
        token = page.get("NextToken")
        if not token:
            break
    else:
        raise AssertionError("ListDomains pagination did not terminate within 30 pages of size 2")

    single_arns = set()
    token = None
    for _ in range(5):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        for d in page.get("Domains", []):
            single_arns.add(d["Arn"])
        token = page.get("NextToken")
        if not token:
            break

    assert paged_arns == single_arns
    assert len(paged_arns) > 2, "expected more than 2 domains in the catalog"
    assert page_count > 1, (
        f"expected MaxResults=2 to force more than one page for {len(paged_arns)} domains, "
        f"but ListDomains returned everything in {page_count} page(s) — MaxResults may be ignored"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
