"""get-subscription-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-subscription-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]


def _error(fn):
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetSubscription with a well-formed but nonexistent subscriptionId returns ResourceNotFoundException, while the real Subscription is unaffected."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    # DeleteDomain refuses while an active subscription is inside; LIFO runs this first.
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id))

    # positive control
    control = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert control["status"] == "ACTIVE", f"expected positive control status ACTIVE, got {control['status']!r}"

    fake_sub_id = "sub-" + "0" * 21  # matches ^sub-[a-zA-Z0-9]{21}$, never created
    code, message = _error(lambda: ch.get_subscription(domainId=domain_id, subscriptionId=fake_sub_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Subscription not found: {domain_id}/{fake_sub_id}", message

    # effect isolation: the real Subscription is still reachable and unaffected
    real = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert real["subscriptionId"] == subscription_id, (
        f"expected {subscription_id!r} still gettable, got {real.get('subscriptionId')!r}"
    )
    assert real["status"] == "ACTIVE", f"expected real Subscription still ACTIVE, got {real['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
