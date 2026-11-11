"""scheduling-policy-type-immutable-after-creation-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "scheduling-policy-type-immutable-after-creation-rejected"
GROUP = "e2e"
SERVICES = ["batch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedulingPolicy cannot change a fairshare policy to quota-share (ClientException).

    The fairsharePolicy is left unchanged, and updating a field within the same type persists.
    """
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sched-immutable-")

    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={"computeReservation": 10, "shareDecaySeconds": 0},
        tags={"env": "sim2real-behav"},
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    code, message = _client_error(
        lambda: batch.update_scheduling_policy(
            arn=arn, quotaSharePolicy={"idleResourceAssignmentStrategy": "FIFO"}
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected = (
        "Cannot change scheduling policy type from fairsharePolicy to quotaSharePolicy. "
        "Create a new scheduling policy instead."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the fairsharePolicy is still there, untouched, no quotaSharePolicy appeared.
    after_negative = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert after_negative.get("quotaSharePolicy") is None, (
        "quotaSharePolicy materialized despite the rejected type-change update"
    )
    assert after_negative["fairsharePolicy"]["computeReservation"] == 10, (
        f"expected fairsharePolicy.computeReservation unchanged at 10, "
        f"got {after_negative['fairsharePolicy'].get('computeReservation')!r}"
    )

    # Positive control: mutating a field within the SAME policy type succeeds.
    batch.update_scheduling_policy(
        arn=arn, fairsharePolicy={"computeReservation": 20, "shareDecaySeconds": 0}
    )
    after_positive = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert after_positive["fairsharePolicy"]["computeReservation"] == 20, (
        "positive-control update to computeReservation did not persist"
    )


def _client_error(fn) -> Any:
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    SUCCESS raises, so accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the type-change update to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
