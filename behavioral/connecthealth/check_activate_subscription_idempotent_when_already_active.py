"""activate-subscription-idempotent-when-already-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-subscription-idempotent-when-already-active"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    deadline = time.monotonic() + 240.0
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
    """Calling ActivateSubscription on a subscription that is already ACTIVE succeeds idempotently."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(
        ch, ctx.unique_name("sim2real-conh-dom-"), tags={"sim2real-probe": "true"}
    )["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]

    created = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert created["status"] == "ACTIVE", f"expected freshly created subscription to be ACTIVE, got {created['status']!r}"

    activated = ch.activate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert activated["status"] == "ACTIVE", f"expected ActivateSubscription on an already-ACTIVE subscription to stay ACTIVE, got {activated['status']!r}"
    assert activated["subscriptionId"] == subscription_id, f"expected subscriptionId {subscription_id!r}, got {activated['subscriptionId']!r}"

    got = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert got["status"] == "ACTIVE", f"expected ACTIVE at an independent read, got {got['status']!r}"
    assert got["subscriptionId"] == subscription_id, f"expected subscriptionId {subscription_id!r} at independent read, got {got['subscriptionId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
