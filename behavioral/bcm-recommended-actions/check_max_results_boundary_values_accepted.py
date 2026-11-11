"""max-results-boundary-values-accepted."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "max-results-boundary-values-accepted"
GROUP = "boundary"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """maxResults at both ends of its documented valid range (1 and 1000) is accepted, not rejected."""
    client = ctx.client("bcm-recommended-actions")

    resp_lower = client.list_recommended_actions(maxResults=1)
    assert len(resp_lower["recommendedActions"]) <= 1, (
        f"maxResults=1 (lower documented bound) must be accepted and cap the "
        f"page at 1 item, got {len(resp_lower['recommendedActions'])}"
    )

    resp_upper = client.list_recommended_actions(maxResults=1000)
    assert len(resp_upper["recommendedActions"]) <= 1000, (
        f"maxResults=1000 (upper documented bound) must be accepted and cap "
        f"the page at 1000 items, got {len(resp_upper['recommendedActions'])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
