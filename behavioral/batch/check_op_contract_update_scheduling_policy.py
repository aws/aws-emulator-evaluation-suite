"""op-contract-update-scheduling-policy."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-update-scheduling-policy"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSchedulingPolicy replaces the fairsharePolicy and DescribeSchedulingPolicies shows the
    new values; an out-of-range computeReservation (valid 0-99) fails with ClientException and the
    exact message, and leaves the applied fairsharePolicy unchanged."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 50,
            "shareDecaySeconds": 3600,
            "shareDistribution": [{"shareIdentifier": "A", "weightFactor": 1.0}],
        },
        tags=_MANAGED_TAGS,
    )
    arn = created["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    desc0 = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert desc0["fairsharePolicy"]["computeReservation"] == 50, desc0["fairsharePolicy"]

    # success path: update fairsharePolicy fields
    batch.update_scheduling_policy(
        arn=arn,
        fairsharePolicy={
            "computeReservation": 75,
            "shareDecaySeconds": 1800,
            "shareDistribution": [{"shareIdentifier": "A", "weightFactor": 2.0}],
        },
    )
    desc1 = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    fp1 = desc1["fairsharePolicy"]
    assert fp1["computeReservation"] == 75, fp1
    assert fp1["shareDecaySeconds"] == 1800, fp1
    assert fp1["shareDistribution"][0]["weightFactor"] == 2.0, fp1

    # error boundary: computeReservation must be 0-99
    code, message, request_id = _error_code(
        lambda: batch.update_scheduling_policy(arn=arn, fairsharePolicy={"computeReservation": 150})
    )
    assert code == "ClientException", code
    # Batch embeds the call's own request id in this message.
    expected = (
        "Error executing request, Exception : Scheduling policy compute reservation must be within "
        f"valid range [0, 99]., RequestId: {request_id}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # the failed update did not change the policy applied before it
    desc2 = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert desc2["fairsharePolicy"]["computeReservation"] == 75, desc2["fairsharePolicy"]


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-sp"}


def _error_code(fn) -> tuple[str, str, str]:
    """Call fn(); return its botocore (error code, error message, request id)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message"), err.response["ResponseMetadata"].get("RequestId")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
