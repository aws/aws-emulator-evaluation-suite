"""deactivate-then-activate-subscription-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deactivate-then-activate-subscription-lifecycle"
GROUP = "state"
SERVICES = ["connecthealth"]


def _create_domain(ch, name, **extra):
    # Leave headroom under the check's own 300s body budget (DEFAULT_TIMEOUT_S) so a
    # quota wait here cannot by itself guarantee the whole check times out.
    deadline = time.monotonic() + 200.0
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
    """DeactivateSubscription drives ACTIVE -> INACTIVE and ActivateSubscription drives INACTIVE -> ACTIVE."""
    ch = ctx.client("connecthealth")
    domain_id = _create_domain(ch, ctx.unique_name("sim2real-conh-dom-"))["domainId"]
    ctx.on_cleanup(lambda: ch.delete_domain(domainId=domain_id))
    subscription_id = ch.create_subscription(domainId=domain_id)["subscriptionId"]

    deactivated = ch.deactivate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert deactivated["status"] == "INACTIVE", f"expected INACTIVE after DeactivateSubscription, got {deactivated['status']!r}"
    assert deactivated["deactivatedAt"] is not None, "expected deactivatedAt to be set after DeactivateSubscription, got None"

    activated = ch.activate_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert activated["status"] == "ACTIVE", f"expected ACTIVE after ActivateSubscription, got {activated['status']!r}"
    assert activated["activatedAt"] is not None, "expected activatedAt to be set after ActivateSubscription, got None"
    assert activated["activatedAt"] >= deactivated["deactivatedAt"], (
        f"expected activatedAt ({activated['activatedAt']}) >= deactivatedAt ({deactivated['deactivatedAt']})"
    )

    got = ch.get_subscription(domainId=domain_id, subscriptionId=subscription_id)["subscription"]
    assert got["status"] == "ACTIVE", f"expected independent GetSubscription read to report ACTIVE, got {got['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
