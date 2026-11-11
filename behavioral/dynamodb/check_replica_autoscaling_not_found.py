"""replica-autoscaling-not-found."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replica-autoscaling-not-found"
GROUP = "errors"
SERVICES = ["dynamodb"]


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses on a nonexistent table is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"real AWS rejects this call against a nonexistent table, but it SUCCEEDED and "
        f"returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTableReplicaAutoScaling and UpdateTableReplicaAutoScaling both
    return ResourceNotFoundException for a nonexistent table, rather than a
    default/empty success (overly-permissive boundary)."""
    ddb = ctx.client("dynamodb")
    missing = ctx.unique_name("sim2real-behav-no-such-table-")

    describe_code, describe_message = _error(
        lambda: ddb.describe_table_replica_auto_scaling(TableName=missing)
    )
    assert describe_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {describe_code}"
    )
    expected_describe = f"Global table with name: '{missing}' does not exist."
    assert describe_message == expected_describe, f"unexpected message {describe_message!r}"

    update_code, update_message = _error(
        lambda: ddb.update_table_replica_auto_scaling(
            TableName=missing,
            ProvisionedWriteCapacityAutoScalingUpdate={
                "MinimumUnits": 1,
                "MaximumUnits": 10,
                "ScalingPolicyUpdate": {
                    "PolicyName": "test-policy",
                    "TargetTrackingScalingPolicyConfiguration": {"TargetValue": 70.0},
                },
            },
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {update_code}"
    )
    expected_update = f"Global table with name: '{missing}' does not exist."
    assert update_message == expected_update, f"unexpected Update message {update_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
