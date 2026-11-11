"""get-delivery-destination-policy-nonexistent-fails."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-delivery-destination-policy-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeliveryDestinationPolicy returns no policy for a real destination without one, and raises
    ResourceNotFoundException with its exact message for a never-created destination name."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-ddpol").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    dest_name = ctx.unique_name("sim2real-behav-dd-")
    logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": bucket_arn},
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    # Positive control: a real destination with no policy attached succeeds and
    # reports no policy content.
    response = logs.get_delivery_destination_policy(deliveryDestinationName=dest_name)
    policy = response.get("policy") or {}
    assert not policy.get("deliveryDestinationPolicy"), (
        f"expected no policy content for a destination that never had a policy attached, got {policy!r}"
    )

    # A destination name that was never created is a different failure mode than
    # "exists but has no policy" above, and must raise the specific not-found error.
    missing_name = ctx.unique_name("sim2real-behav-nosuchdest-")
    code, message = _error(
        lambda: logs.get_delivery_destination_policy(deliveryDestinationName=missing_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for GetDeliveryDestinationPolicy against a "
        f"delivery destination that was never created, got {code!r}"
    )
    expected_message = "Requested Delivery Destination does not exist in this account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_bucket(ctx: Any, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected GetDeliveryDestinationPolicy against a nonexistent destination to raise, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
