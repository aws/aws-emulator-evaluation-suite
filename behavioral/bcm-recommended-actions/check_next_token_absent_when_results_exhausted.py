"""next-token-absent-when-results-exhausted."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "next-token-absent-when-results-exhausted"
GROUP = "pagination"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After paging all the way through the result set with the smallest
    page size, the final page's nextToken is absent/empty -- a well-formed
    termination signal that a consumer can rely on to stop paginating."""
    client = ctx.client("bcm-recommended-actions")
    next_token = None
    final_token: str | None = "unset"
    for _ in range(200):
        kwargs: dict[str, Any] = {"maxResults": 1}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = client.list_recommended_actions(**kwargs)
        next_token = resp.get("nextToken")
        final_token = next_token
        if not next_token:
            break

    assert final_token in (None, ""), f"pagination never terminated, last token={final_token!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
