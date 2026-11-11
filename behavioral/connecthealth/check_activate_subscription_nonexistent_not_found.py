"""activate-subscription-nonexistent-not-found."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-subscription-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["connecthealth"]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


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
    """ActivateSubscription on a nonexistent subscriptionId returns ResourceNotFoundException and does not touch the real Subscription."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id))
    ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id)

    # positive control: activating the real (deactivated) Subscription succeeds
    activated = ch.activate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert activated["status"] == "ACTIVE", f"expected ACTIVE after activating the real Subscription, got {activated['status']!r}"

    fake_sub_id = "sub-" + "1" * 21  # matches ^sub-[a-zA-Z0-9]{21}$, never created
    code, message = _client_error(lambda: ch.activate_subscription(domainId=domain_id, subscriptionId=fake_sub_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for a nonexistent subscriptionId, got {code!r}"
    expected = f"Subscription not found: {domain_id}/{fake_sub_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect isolation: the real Subscription remains ACTIVE
    real = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert real["status"] == "ACTIVE", f"expected the real Subscription to remain ACTIVE after the nonexistent-id call, got {real['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
