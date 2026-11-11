"""delete-data-integration-nonexistent-rejected-and-real-delete-removes-resource."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-data-integration-nonexistent-rejected-and-real-delete-removes-resource"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataIntegration against a nonexistent Identifier is rejected rather than silently
    reporting success; a real DataIntegration deletes cleanly and is truly gone afterward."""
    key_arn = _create_kms_key_for_appintegrations(ctx)
    appi = ctx.client("appintegrations")
    bucket = _create_s3_source_bucket(ctx)

    bogus_identifier = "00000000-0000-0000-0000-000000000000"
    code, message = _client_error(lambda: appi.delete_data_integration(DataIntegrationIdentifier=bogus_identifier))
    assert code == "ResourceNotFoundException", code
    expected_message = f"Could not find DataIntegration with identifier: {bogus_identifier}."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Positive control: a real DataIntegration deletes cleanly, and is truly gone afterward.
    name = ctx.unique_name("sim2real-di-unblocked-")
    created = appi.create_data_integration(
        Name=name, KmsKey=key_arn, SourceURI=f"s3://{bucket}"
    )
    identifier = created["Id"]
    appi.delete_data_integration(DataIntegrationIdentifier=identifier)

    deleted_expected = f"Could not find DataIntegration with identifier: {identifier}."
    deleted_code, deleted_message = _client_error(lambda: appi.get_data_integration(Identifier=identifier))
    assert deleted_code == "ResourceNotFoundException", deleted_code
    assert deleted_message == deleted_expected, f"expected {deleted_expected!r}, got {deleted_message!r}"

    # A mutation on the dead id also fails, not just a read: deletion is not merely invisible to
    # Get while still mutable underneath.
    update_code, update_message = _client_error(
        lambda: appi.update_data_integration(Identifier=identifier, Description="sim2real-post-delete")
    )
    assert update_code == "ResourceNotFoundException", update_code
    assert update_message == deleted_expected, f"expected {deleted_expected!r}, got {update_message!r}"


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


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

