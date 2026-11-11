"""pagination-full-sweep-no-duplicate-ids."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "pagination-full-sweep-no-duplicate-ids"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paginating through every page with the smallest possible page size
    (maxResults=1) visits each action id exactly once, and the resulting set
    of ids is identical to a single unpaginated call's set of ids."""
    swept_items = _list_all(ctx, max_results=1)
    swept_ids = [a["id"] for a in swept_items]
    assert len(swept_ids) == len(set(swept_ids)), f"duplicate ids across pages: {swept_ids}"

    baseline_items = _list_all(ctx)
    baseline_ids = {a["id"] for a in baseline_items}
    assert len(swept_items) == len(baseline_items), (
        f"sweep visited {len(swept_items)} items but the baseline listing has "
        f"{len(baseline_items)}"
    )
    assert set(swept_ids) == baseline_ids, (swept_ids, baseline_ids)


def _list_all(
    ctx,
    request_filter: dict | None = None,
    max_results: int | None = None,
    max_pages: int = 200,
) -> list[dict[str, Any]]:
    client = ctx.client("bcm-recommended-actions")
    items: list[dict[str, Any]] = []
    next_token = None
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {}
        if request_filter is not None:
            kwargs["filter"] = request_filter
        if max_results is not None:
            kwargs["maxResults"] = max_results
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_recommended_actions(**kwargs)
        items.extend(resp.get("recommendedActions", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    else:
        raise AssertionError(f"pagination did not terminate within {max_pages} pages")
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
