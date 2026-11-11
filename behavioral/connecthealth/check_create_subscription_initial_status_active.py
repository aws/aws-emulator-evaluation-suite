"""create-subscription-initial-status-active."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-subscription-initial-status-active"
GROUP = "state"
SERVICES = ["connecthealth"]

_SUBSCRIPTION_ID_RE = re.compile(r"^sub-[a-zA-Z0-9]{21}$")


def _create_domain(ch, name, **extra):
    # 240s, not the check's full 300s body budget: a quota-exceeded retry loop that eats the
    # whole budget leaves zero time for the create_subscription/get_subscription this check
    # exists to prove, turning contention into an indistinguishable timeout.
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
    """CreateSubscription initializes SubscriptionStatus to ACTIVE without an explicit activation call."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))

    resp = ch.create_subscription(domainId=domain_id)
    subscription_id = resp["subscriptionId"]

    assert _SUBSCRIPTION_ID_RE.match(subscription_id), f"subscriptionId {subscription_id!r} does not match ^sub-[a-zA-Z0-9]{{21}}$"
    assert resp["domainId"] == domain_id, f"expected domainId {domain_id!r}, got {resp['domainId']!r}"
    assert resp["status"] == "ACTIVE", f"expected CreateSubscription status ACTIVE, got {resp['status']!r}"

    got = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert got["status"] == "ACTIVE", f"expected GetSubscription status ACTIVE, got {got['status']!r}"
    assert got["subscriptionId"] == subscription_id, f"expected subscriptionId {subscription_id!r}, got {got['subscriptionId']!r}"
    assert got["domainId"] == domain_id, f"expected domainId {domain_id!r}, got {got['domainId']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
