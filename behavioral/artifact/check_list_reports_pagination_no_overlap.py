"""list-reports-pagination-no-overlap."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-reports-pagination-no-overlap"
GROUP = "data-plane"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListReports pagination returns disjoint pages of at most maxResults items each,
    and page 2 (fetched via nextToken) contains no report id already seen on page 1."""
    art = ctx.client("artifact")
    page1 = art.list_reports(maxResults=3)
    reports1 = page1["reports"]
    assert len(reports1) <= 3, f"maxResults=3 but page 1 returned {len(reports1)} reports"

    token = page1.get("nextToken")
    if not token:
        raise AssertionError(
            "report catalog has fewer than 4 entries visible to this account; "
            "cannot exercise nextToken pagination disjointness"
        )

    page2 = art.list_reports(maxResults=3, nextToken=token)
    reports2 = page2["reports"]
    assert len(reports2) <= 3, f"maxResults=3 but page 2 returned {len(reports2)} reports"

    ids1 = {r["id"] for r in reports1}
    ids2 = {r["id"] for r in reports2}
    assert ids1.isdisjoint(ids2), f"pagination returned overlapping report ids: {ids1 & ids2}"
    assert len(reports2) > 0, "second page (non-empty nextToken) returned zero reports"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
