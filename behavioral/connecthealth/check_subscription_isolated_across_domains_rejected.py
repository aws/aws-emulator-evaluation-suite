"""subscription-isolated-across-domains-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "subscription-isolated-across-domains-rejected"
GROUP = "overly-permissive"
SERVICES = ["connecthealth"]


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so an emulator that
    accepts what AWS refuses reads as a loud failure rather than a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_domain(ch, name, **extra):
    """Create a Domain, retrying transiently on the account-wide Domain cap so this check doesn't
    spuriously fail when other concurrently-running checks are also consuming Domain slots."""
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
    """GetSubscription rejects a subscriptionId that exists, but under a different Domain than the one supplied (cross-tenant/cross-domain isolation)."""
    ch = ctx.client("connecthealth")
    domain_a = _create_domain(ch, ctx.unique_name("sim2real-conh-doma-"), tags={"sim2real-probe": "true"})["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_a))
    domain_b = _create_domain(ch, ctx.unique_name("sim2real-conh-domb-"), tags={"sim2real-probe": "true"})["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_b))

    sub_a = ch.create_subscription(domainId=domain_a)["subscriptionId"]
    ctx.on_cleanup(lambda: ch.deactivate_subscription(domainId=domain_a, subscriptionId=sub_a))

    # positive control: the subscription is reachable through its own domain
    status_a = ch.get_subscription(domainId=domain_a, subscriptionId=sub_a)["subscription"]["status"]
    assert status_a == "ACTIVE", f"expected ACTIVE for subscription under its own domain, got {status_a!r}"

    # negative: the same subscriptionId does not exist under the unrelated domain
    code, message = _client_error(lambda: ch.get_subscription(domainId=domain_b, subscriptionId=sub_a))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for cross-domain GetSubscription, got {code!r}"
    expected = f"Subscription not found: {domain_b}/{sub_a}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect isolation: the subscription is still intact under its real domain
    status_a_after = ch.get_subscription(domainId=domain_a, subscriptionId=sub_a)["subscription"]["status"]
    assert status_a_after == "ACTIVE", f"expected ACTIVE for subscription under its real domain after cross-domain probe, got {status_a_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
