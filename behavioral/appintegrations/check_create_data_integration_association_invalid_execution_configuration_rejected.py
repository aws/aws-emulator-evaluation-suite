"""create-data-integration-association-invalid-execution-configuration-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-integration-association-invalid-execution-configuration-rejected"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDataIntegrationAssociation rejects an ExecutionMode/configuration-shape mismatch
    (ON_DEMAND paired with ScheduleConfiguration instead of OnDemandConfiguration) as a request
    validation error, and leaves the DataIntegration without any persisted association."""
    key_arn = _create_kms_key_for_appintegrations(ctx)
    appi = ctx.client("appintegrations")
    bucket = _create_s3_source_bucket(ctx)
    name = ctx.unique_name("sim2real-di-badexec-")

    created = appi.create_data_integration(
        Name=name, KmsKey=key_arn, SourceURI=f"s3://{bucket}"
    )
    identifier = created["Id"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, identifier))

    code, message = _error_code(
        lambda: appi.create_data_integration_association(
            DataIntegrationIdentifier=identifier,
            DestinationURI="https://example.com/sim2real-badexec-dest",
            ExecutionConfiguration={
                "ExecutionMode": "ON_DEMAND",
                "ScheduleConfiguration": {"ScheduleExpression": "rate(1 hour)"},
            },
        )
    )
    assert code == "InvalidRequestException", code
    assert message == f"Failed to create DataIntegrationAssociation for DataIntegration {created['Id']}. DATA_INTEGRATION_ASSOCIATION_VALIDATION_EXCEPTION: Access Denied to S3 Bucket", (
        f"expected the exact InvalidRequestException message AWS returns, got {message!r}"
    )

    # Effect absent: no association was actually persisted for this DataIntegration.
    listed = appi.list_data_integration_associations(DataIntegrationIdentifier=identifier)
    assert listed["DataIntegrationAssociations"] == [], listed["DataIntegrationAssociations"]


def _create_s3_source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    region = s3.meta.region_name
    bucket = ctx.unique_name("sim2real-appintegrations-src").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    if region and region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _error_code(fn: Any):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_kms_key_for_appintegrations(ctx: Any) -> str:
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "EnableAppIntegrationsAccessToKmsKey",
                "Effect": "Allow",
                "Principal": {"Service": ["app-integrations.amazonaws.com", "appflow.amazonaws.com"]},
                "Action": ["kms:Encrypt*", "kms:Describe*", "kms:Decrypt*", "kms:GenerateDataKey*"],
                "Resource": "*",
            },
        ],
    }
    key = kms.create_key(
        Description="sim2real-appintegrations-test-key",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "appintegrations-behavioral"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]

    def _cleanup() -> None:
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return key["Arn"]


def _try_delete_data_integration(appi: Any, identifier: str) -> None:
    try:
        appi.delete_data_integration(DataIntegrationIdentifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

