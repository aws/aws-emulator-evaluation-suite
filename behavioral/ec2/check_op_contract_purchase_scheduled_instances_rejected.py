"""op-contract-purchase-scheduled-instances-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-purchase-scheduled-instances-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

MALFORMED_MESSAGE = "The specified purchase token is not valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PurchaseScheduledInstances fails with InvalidPurchaseToken.Malformed and its exact message for a
    malformed purchase token, and DescribeScheduledInstances lists the same set before and after."""
    ec2 = ctx.client("ec2")

    # DescribeScheduledInstances is the free, read-only side of the same contract surface — a
    # positive control proving ec2 permissions/connectivity are healthy, and the baseline for
    # the effect-absent check below.
    before = ec2.describe_scheduled_instances().get("ScheduledInstanceSet", [])
    assert isinstance(before, list), f"ScheduledInstanceSet must be a list, got {before!r}"

    err, message = _error(
        lambda: ec2.purchase_scheduled_instances(
            PurchaseRequests=[{"PurchaseToken": "not-a-real-purchase-token", "InstanceCount": 1}]
        )
    )
    assert err == "InvalidPurchaseToken.Malformed", (
        f"expected InvalidPurchaseToken.Malformed, got {err}"
    )
    assert message == MALFORMED_MESSAGE, f"expected message {MALFORMED_MESSAGE!r}, got {message!r}"

    after = ec2.describe_scheduled_instances().get("ScheduledInstanceSet", [])
    assert after == before, (
        f"purchase was rejected but ScheduledInstanceSet changed: {before} -> {after}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a malformed token real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
