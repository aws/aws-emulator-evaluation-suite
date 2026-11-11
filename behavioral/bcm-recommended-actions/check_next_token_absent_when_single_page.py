"""next-token-absent-when-single-page."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "next-token-absent-when-single-page"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When fewer items are returned than the requested page size, there must be no nextToken to continue with."""
    client = ctx.client("bcm-recommended-actions")

    resp = client.list_recommended_actions(maxResults=1000)
    actions = resp.get("recommendedActions", [])
    assert len(actions) <= 1000, f"maxResults=1000 but got {len(actions)} items"

    if len(actions) < 1000:
        assert not resp.get("nextToken"), (
            f"nextToken present even though the page was not full: "
            f"len={len(actions)} token={resp.get('nextToken')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
