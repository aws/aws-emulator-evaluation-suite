"""update-delivery-configuration-invalid-id-format-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "update-delivery-configuration-invalid-id-format-rejected"
GROUP = "error-semantics"
SERVICES = ["logs", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDeliveryConfiguration with a delivery id that fails the id's regular expression
    is rejected with ValidationException naming the offending member and pattern."""
    logs = ctx.client("logs")
    s3 = ctx.client("s3")
    account = ctx.account

    src_bucket = _create_bucket(ctx, s3, "udcnegsrc")
    src_bucket_arn = f"arn:aws:s3:::{src_bucket}"

    dest_bucket = _create_bucket(ctx, s3, "udcnegdst")
    dest_bucket_arn = f"arn:aws:s3:::{dest_bucket}"
    _apply_delivery_write_policy(s3, dest_bucket, dest_bucket_arn, account)

    source_name = ctx.unique_name("sim2real-udcneg-src-")
    logs.put_delivery_source(
        name=source_name, resourceArn=src_bucket_arn, logType="S3_SERVER_ACCESS_LOGS"
    )
    ctx.on_cleanup(lambda: logs.delete_delivery_source(name=source_name))

    dest_name = ctx.unique_name("sim2real-udcneg-dst-")
    dest_arn = logs.put_delivery_destination(
        name=dest_name,
        deliveryDestinationType="S3",
        deliveryDestinationConfiguration={"destinationResourceArn": dest_bucket_arn},
    )["deliveryDestination"]["arn"]
    ctx.on_cleanup(lambda: logs.delete_delivery_destination(name=dest_name))

    delivery_id = logs.create_delivery(
        deliverySourceName=source_name, deliveryDestinationArn=dest_arn
    )["delivery"]["id"]
    ctx.on_cleanup(lambda: logs.delete_delivery(id=delivery_id))

    # Positive control: updating the configuration of the real delivery by its real id succeeds.
    new_suffix = "sim2real-udcneg/{account-id}"
    logs.update_delivery_configuration(
        id=delivery_id, s3DeliveryConfiguration={"suffixPath": new_suffix}
    )
    updated = logs.get_delivery(id=delivery_id)["delivery"]
    assert updated["s3DeliveryConfiguration"]["suffixPath"] == new_suffix, (
        f"expected suffixPath={new_suffix!r} after UpdateDeliveryConfiguration, got {updated!r}"
    )

    # Negative: the delivery id's own regular expression is ^[0-9A-Za-z]+$, so a hyphen
    # (otherwise legal in many other id-shaped strings) fails it regardless of whether a
    # delivery with that id exists.
    bad_id = delivery_id + "-not-alnum"
    code, message = _error(
        lambda: logs.update_delivery_configuration(
            id=bad_id, s3DeliveryConfiguration={"suffixPath": "sim2real-udcneg-unused"}
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a delivery id failing the id pattern, got "
        f"{code!r} {message!r}"
    )
    expected_message = (
        "1 validation error detected: Value at 'id' failed to satisfy constraint: Member "
        "must satisfy regular expression pattern: ^[0-9A-Za-z]+$"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the rejected call did not touch the real delivery's configuration.
    unaffected = logs.get_delivery(id=delivery_id)["delivery"]
    assert unaffected["s3DeliveryConfiguration"]["suffixPath"] == new_suffix, (
        f"expected the real delivery's suffixPath to stay {new_suffix!r} after the "
        f"rejected call against a different (invalid) id, got {unaffected!r}"
    )


def _apply_delivery_write_policy(s3, bucket: str, bucket_arn: str, account: str) -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSLogDeliveryWrite",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"{bucket_arn}/*",
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control",
                        "aws:SourceAccount": account,
                    }
                },
            },
            {
                "Sid": "AWSLogDeliveryAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "delivery.logs.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": bucket_arn,
                "Condition": {"StringEquals": {"aws:SourceAccount": account}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _create_bucket(ctx, s3, tag: str) -> str:
    bucket = ctx.unique_name(f"sim2real-{tag}-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _empty_and_delete() -> None:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_empty_and_delete)
    return bucket


def _error(fn: Callable[[], Any]):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
