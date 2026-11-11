"""subscription-state-inactive-by-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "subscription-state-inactive-by-default"
GROUP = "state"
SERVICES = ["shield"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSubscriptionState reports INACTIVE for an account with no Shield Advanced subscription."""
    shield = ctx.client("shield")
    resp = shield.get_subscription_state()
    assert resp["SubscriptionState"] == "INACTIVE", (
        f"expected INACTIVE subscription state on an unsubscribed test account, "
        f"got {resp['SubscriptionState']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
