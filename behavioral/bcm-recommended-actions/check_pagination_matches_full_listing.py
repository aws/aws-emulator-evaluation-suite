"""pagination-matches-full-listing."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "pagination-matches-full-listing"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Paging with maxResults=1 yields exactly the same id set as walking the
    server's default page size to completion, with no duplicates on either side."""
    client = ctx.client("bcm-recommended-actions")

    full_ids = {a["id"] for a in _list_all(ctx, maxResults=None)}

    paged_ids_seen = []
    token = None
    for _ in range(200):  # hard bound so a misbehaving emulator can't hang the check
        kwargs = {"maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        resp = client.list_recommended_actions(**kwargs)
        page = resp.get("recommendedActions", [])
        assert len(page) <= 1, "maxResults=1 must never return more than one item per page"
        paged_ids_seen.extend(a["id"] for a in page)
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("pagination did not terminate within 200 pages")

    assert len(paged_ids_seen) == len(set(paged_ids_seen)), "duplicate id observed across pages"
    assert set(paged_ids_seen) == full_ids, (
        f"paginated id set differs from the default-page-size listing: "
        f"len(full)={len(full_ids)} len(paged)={len(paged_ids_seen)} "
        f"only_in_full={full_ids - set(paged_ids_seen)} only_in_paged={set(paged_ids_seen) - full_ids}"
    )


def _list_all(ctx, maxResults: int | None, max_pages: int = 200) -> list[dict[str, Any]]:
    client = ctx.client("bcm-recommended-actions")
    items: list[dict[str, Any]] = []
    token = None
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {}
        if maxResults is not None:
            kwargs["maxResults"] = maxResults
        if token:
            kwargs["nextToken"] = token
        resp = client.list_recommended_actions(**kwargs)
        items.extend(resp.get("recommendedActions", []))
        token = resp.get("nextToken")
        if not token:
            break
    else:
        raise AssertionError("default-page-size pagination did not terminate within 200 pages")
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
