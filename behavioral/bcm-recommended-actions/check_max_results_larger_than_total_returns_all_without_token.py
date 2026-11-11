"""max-results-larger-than-total-returns-all-without-token."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "max-results-larger-than-total-returns-all-without-token"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Requesting the documented maximum page size (maxResults=1000) returns
    every recommended action the account has in a single page, with no
    nextToken left to continue (the account's total is well under 1000)."""
    client = ctx.client("bcm-recommended-actions")

    baseline = _list_all(ctx)
    resp = client.list_recommended_actions(maxResults=1000)

    actions = resp["recommendedActions"]
    assert len(actions) == len(baseline), (
        f"maxResults=1000 returned {len(actions)} items, "
        f"but the full paginated walk found {len(baseline)}"
    )
    assert {a["id"] for a in actions} == {a["id"] for a in baseline}, (
        "the id set from a single maxResults=1000 call differs from the id set "
        "collected by walking every page with nextToken"
    )
    next_token = resp.get("nextToken")
    assert next_token in (None, ""), (
        f"expected no nextToken once every item fit in one page, got {next_token!r}"
    )


def _list_all(ctx, request_filter: dict | None = None, max_pages: int = 50) -> list[dict[str, Any]]:
    client = ctx.client("bcm-recommended-actions")
    items: list[dict[str, Any]] = []
    next_token = None
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {}
        if request_filter is not None:
            kwargs["filter"] = request_filter
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_recommended_actions(**kwargs)
        items.extend(resp.get("recommendedActions", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
