"""list-regions-pagination-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-regions-pagination-consistency"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating ListRegions with a small MaxResults collects the same set of regions, with no
    duplicates, as a single large-MaxResults call."""
    account = ctx.client("account")

    full_names: list[str] = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = account.list_regions(**kwargs)
        full_names.extend(r["RegionName"] for r in resp["Regions"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    assert len(full_names) == len(set(full_names)), "large-page call returned duplicate region names"

    paged_names: list[str] = []
    next_token = None
    page_count = 0
    while True:
        kwargs = {"MaxResults": 5}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = account.list_regions(**kwargs)
        page = resp["Regions"]
        assert len(page) <= 5, f"requested MaxResults=5 but got a page of {len(page)}"
        paged_names.extend(r["RegionName"] for r in page)
        page_count += 1
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert page_count > 1, "expected more than one page with MaxResults=5 given >5 total regions"
    assert len(paged_names) == len(set(paged_names)), "pagination returned duplicate region names"
    assert set(paged_names) == set(full_names), (
        f"paginated set {set(paged_names)} != single-large-page set {set(full_names)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
