"""list-data-integration-associations-empty-for-unassociated-data-integration."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-data-integration-associations-empty-for-unassociated-data-integration"
GROUP = "data-plane"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataIntegrationAssociations returns an empty list for a freshly created DataIntegration
    with no associations; CreateDataIntegrationAssociation against a nonexistent DataIntegration
    Identifier is rejected rather than silently creating an orphaned association."""
    key_arn = _create_kms_key_for_appintegrations(ctx)
    bucket = _create_s3_source_bucket(ctx)
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-di-assoc-")

    created = appi.create_data_integration(Name=name, KmsKey=key_arn, SourceURI=f"s3://{bucket}")
    identifier = created["Id"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, identifier))

    listed = appi.list_data_integration_associations(DataIntegrationIdentifier=identifier)
    assert listed["DataIntegrationAssociations"] == []

    # Overly-permissive boundary: creating an association against a nonexistent DataIntegration
    # identifier must be rejected, not silently accepted.
    bogus_identifier = "00000000-0000-0000-0000-000000000000"
    code, message = _client_error(
        lambda: appi.create_data_integration_association(
            DataIntegrationIdentifier=bogus_identifier,
            DestinationURI="https://example.com/sim2real-dest",
        )
    )
    assert code == "ResourceNotFoundException", code
    expected_message = f"Could not find DataIntegration with identifier: {bogus_identifier}."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _client_error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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

