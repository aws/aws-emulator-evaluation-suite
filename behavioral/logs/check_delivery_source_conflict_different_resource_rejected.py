"""delivery-source-conflict-different-resource-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delivery-source-conflict-different-resource-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutDeliverySource with an existing source name but a different resourceArn is
    rejected with ConflictException; a delivery source name is bound to one resource for
    its lifetime, it cannot be silently repointed at another resource."""
    logs = ctx.client("logs")
    _, bucket_arn_1 = _create_bucket(ctx)
    _, bucket_arn_2 = _create_bucket(ctx)
    source_name = ctx.unique_name("sim2real-dsrc-")

    logs.put_delivery_source(
        name=source_name, resourceArn=bucket_arn_1, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: _safe_delete_source(logs, source_name))

    code, message = _expect_error(
        lambda: logs.put_delivery_source(
            name=source_name, resourceArn=bucket_arn_2, logType="S3_SERVER_ACCESS_LOGS"
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code!r}"
    expected = "Update to existing Delivery Source with new ResourceId is not allowed. Please create a new Delivery Source instead."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # confirm the original binding to bucket_arn_1 was left untouched, and that the
    # rejected repoint did not leak bucket_arn_2 into the source's resource list
    resource_arns = logs.get_delivery_source(name=source_name)["deliverySource"]["resourceArns"]
    assert bucket_arn_1 in resource_arns and bucket_arn_2 not in resource_arns, (
        f"expected {source_name} to remain bound only to {bucket_arn_1!r} after the "
        f"rejected repoint to {bucket_arn_2!r}, got resourceArns={resource_arns!r}"
    )


def _expect_error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(
        f"expected the repoint to a different resourceArn to be rejected, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-logs-src-")
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint on
    # CreateBucket; this is an S3 API quirk, not a pin of this check's own region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return name, f"arn:aws:s3:::{name}"


def _safe_delete_source(logs_client, name: str) -> None:
    try:
        logs_client.delete_delivery_source(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
