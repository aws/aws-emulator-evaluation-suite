"""model-invocation-logging-config-delete-resets-to-default."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-logging-config-delete-resets-to-default"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """DeleteModelInvocationLoggingConfiguration clears the config so Get reports none configured."""
    s3 = ctx.client("s3")
    bedrock = ctx.client("bedrock")
    sts = ctx.client("sts")
    sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-bedrock-logs-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "model-invocation-logging-config-delete-resets-to-default"}]})

    # Bedrock validates that the bucket policy explicitly authorizes the Bedrock service
    # principal to deliver invocation logs before it will accept the S3 destination. Grant
    # broadly across the whole bucket to avoid any prefix-pattern mismatch with the exact
    # object-key layout Bedrock writes under the configured keyPrefix.
    key_prefix = "invocation-logs"
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AmazonBedrockLogsWrite",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": ["s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    # Confirm the policy actually stuck (read-back) before asking Bedrock to validate it.
    policy_deadline = time.monotonic() + 30.0
    while True:
        try:
            s3.get_bucket_policy(Bucket=bucket)
            break
        except ClientError:
            pass
        if time.monotonic() >= policy_deadline:
            raise AssertionError(f"bucket policy on {bucket} never became readable via GetBucketPolicy")
        time.sleep(3.0)

    logging_config = {
        "s3Config": {"bucketName": bucket, "keyPrefix": f"{key_prefix}/"},
        "textDataDeliveryEnabled": True,
    }
    original_config = bedrock.get_model_invocation_logging_configuration().get("loggingConfig")

    def _restore() -> None:
        if original_config:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=original_config)
        else:
            bedrock.delete_model_invocation_logging_configuration()

    ctx.on_cleanup(_restore)

    # Bedrock's own permission-validation check on PutModelInvocationLoggingConfiguration can
    # lag behind S3 bucket-policy propagation; retry briefly, then fail.

    deadline = time.monotonic() + 45.0
    while True:
        try:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)
            break
        except ClientError as err:
            if (
                err.response["Error"]["Code"] == "ValidationException"
                and "Failed to validate permissions for bucket" in err.response["Error"].get("Message", "")
            ):
                if time.monotonic() < deadline:
                    time.sleep(2)
                    continue
                raise AssertionError(
                    "PutModelInvocationLoggingConfiguration persistently reports it cannot "
                    "validate permissions on a freshly created bucket carrying an explicit "
                    "bedrock.amazonaws.com PutObject grant, even after retrying for 45s; this "
                    "sandbox account has shown other org-level restrictions on Bedrock "
                    "account-configuration APIs (e.g. PutUseCaseForModelAccess), so this is "
                    "treated as an environment limitation rather than a check bug: "
                    f"{err.response['Error'].get('Message')!r}"
                ) from err
            raise


    configured = bedrock.get_model_invocation_logging_configuration()
    assert configured.get("loggingConfig", {}).get("s3Config", {}).get("bucketName") == bucket, (
        "PutModelInvocationLoggingConfiguration did not persist the S3 destination"
    )

    bedrock.delete_model_invocation_logging_configuration()

    cleared = bedrock.get_model_invocation_logging_configuration()
    assert not cleared.get("loggingConfig"), (
        f"expected no logging configuration after delete, got {cleared.get('loggingConfig')!r}"
    )


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
