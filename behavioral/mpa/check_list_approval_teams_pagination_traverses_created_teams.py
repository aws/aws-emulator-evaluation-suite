"""list-approval-teams-pagination-traverses-created-teams."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "list-approval-teams-pagination-traverses-created-teams"
GROUP = "state"
SERVICES = ["mpa"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPolicies with MaxResults=1 returns at most one item per page, and following NextToken visits
    every built-in managed policy exactly once, matching a single MaxResults=20 call.
    """
    # MPA is a single-Region service: it only operates in us-east-1, regardless of
    # the suite's default Region.
    mpa = ctx.client("mpa", region="us-east-1")

    all_at_once = {p["Name"] for p in mpa.list_policies(MaxResults=20)["Policies"]}
    assert all_at_once, "account has no MPA managed policies"

    seen_names = set()
    token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = mpa.list_policies(**kwargs)
        page_items = resp.get("Policies", [])
        assert len(page_items) <= 1, f"expected at most 1 item per page (MaxResults=1), got {len(page_items)}"
        for item in page_items:
            assert item["Name"] not in seen_names, "duplicate item across pages"
            seen_names.add(item["Name"])
        token = resp.get("NextToken")
        pages += 1
        if not token:
            break
        assert pages < 500, "pagination did not terminate in a reasonable number of pages"

    assert seen_names == all_at_once, "paginated traversal disagrees with a single full page"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
