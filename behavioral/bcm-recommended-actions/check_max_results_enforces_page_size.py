"""max-results-enforces-page-size."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "max-results-enforces-page-size"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """maxResults=1 truncates the page to at most 1 item, and when more items
    exist beyond that page the response carries a nextToken to continue."""
    client = ctx.client("bcm-recommended-actions")

    first_page = client.list_recommended_actions(maxResults=1)
    got = len(first_page["recommendedActions"])
    assert got <= 1, f"expected at most 1 item with maxResults=1, got {got}"

    total_items = _list_all(ctx)
    if len(total_items) > 1:
        assert first_page.get("nextToken") not in (None, ""), (
            "expected a nextToken when more than 1 item exists beyond a "
            "maxResults=1 page"
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
