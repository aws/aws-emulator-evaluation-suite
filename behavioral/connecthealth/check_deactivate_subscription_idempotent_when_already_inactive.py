"""deactivate-subscription-idempotent-when-already-inactive."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deactivate-subscription-idempotent-when-already-inactive"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 300.0
    while True:
        try:
            return ch.create_domain(name=name, **extra)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code not in ("ServiceQuotaExceededException", "ValidationException") or "maximum limit" not in msg:
                raise
            if time.monotonic() > deadline:
                raise
            time.sleep(5.0)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Calling DeactivateSubscription on an already-INACTIVE subscription succeeds idempotently (no ConflictException is documented for this operation)."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-probe": "true"})["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]

    first = ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert first["status"] == "INACTIVE", f"expected INACTIVE after first deactivate, got {first['status']!r}"

    second = ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert second["status"] == "INACTIVE", f"expected INACTIVE after second deactivate, got {second['status']!r}"
    assert second["subscriptionId"] == subscription_id
    assert second["deactivatedAt"] == first["deactivatedAt"], (
        f"expected deactivatedAt to be unchanged by the redundant call (true idempotency), "
        f"got first={first['deactivatedAt']!r} second={second['deactivatedAt']!r}"
    )

    # Terminal read is independent of the mutating calls above
    got = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert got["status"] == "INACTIVE", f"GetSubscription disagrees with DeactivateSubscription: {got['status']!r}"
    assert got["subscriptionId"] == subscription_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
