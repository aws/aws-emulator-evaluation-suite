"""delete-model-invocation-logging-configuration-idempotent."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-model-invocation-logging-configuration-idempotent"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """DeleteModelInvocationLoggingConfiguration leaves GetModelInvocationLoggingConfiguration with
    no active config, and a second delete on the empty config succeeds (no ResourceNotFound is
    documented for it)."""
    bedrock = ctx.client("bedrock")
    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket_name = ctx.unique_name("sim2real-bedlog-idem-")
    # CreateBucket rejects an explicit LocationConstraint for us-east-1; other regions need one.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]},
    )

    prefix = "sim2real-idem"
    # Bucket-wide PutObject so Bedrock's permission validation at Put time cannot fail on a
    # nested delivery-path mismatch.
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AmazonBedrockLogsWrite",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket_name}/*"],
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    original = bedrock.get_model_invocation_logging_configuration()
    original_config = original.get("loggingConfig")

    def _restore() -> None:
        if original_config:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=original_config)
        else:
            bedrock.delete_model_invocation_logging_configuration()

    ctx.on_cleanup(_restore)

    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + 40.0
    last_msg = ""
    while True:
        try:
            bedrock.put_model_invocation_logging_configuration(
                loggingConfig={
                    "s3Config": {"bucketName": bucket_name, "keyPrefix": prefix},
                    "textDataDeliveryEnabled": True,
                }
            )
            break
        except ClientError as err:
            last_msg = err.response["Error"].get("Message", "")
            if "Failed to validate permissions" in last_msg and _time.monotonic() < deadline:
                _time.sleep(5.0)  # bucket policy propagation lag
                continue
            if "Failed to validate permissions" in last_msg:
                raise AssertionError(
                    "PutModelInvocationLoggingConfiguration with an S3 destination "
                    "rejects a bucket policy matching AWS's own documented shape "
                    "(broad bedrock.amazonaws.com PutObject grant, verified via "
                    "GetBucketPolicy round trip) with 'Failed to validate permissions "
                    "for bucket' even after a 40s propagation wait -- this account "
                    "appears to have an additional restriction (e.g. an SCP) blocking "
                    "Bedrock's own internal S3-write permission validation that is not "
                    "documented and not under this check's control."
                ) from err
            raise AssertionError(last_msg[60:280]) from None
    fetched = bedrock.get_model_invocation_logging_configuration()["loggingConfig"]
    assert fetched["s3Config"]["bucketName"] == bucket_name, (
        f"expected configured bucket {bucket_name!r}, got {fetched.get('s3Config')!r}"
    )

    bedrock.delete_model_invocation_logging_configuration()
    after_first_delete = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
    assert not after_first_delete, f"expected no active logging config after delete, got {after_first_delete!r}"

    bedrock.delete_model_invocation_logging_configuration()
    after_second_delete = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")
    assert not after_second_delete, f"expected still no active logging config, got {after_second_delete!r}"


def _empty_and_delete(s3, bucket) -> None:
    """Delete the bucket after the objects in it, such as the permission-check object Bedrock
    writes when logging is configured."""
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        objects = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in (page.get("Versions") or []) + (page.get("DeleteMarkers") or [])
        ]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
