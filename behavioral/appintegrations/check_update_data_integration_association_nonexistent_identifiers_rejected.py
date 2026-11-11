"""update-data-integration-association-nonexistent-identifiers-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-data-integration-association-nonexistent-identifiers-rejected"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDataIntegrationAssociation rejects a nonexistent DataIntegrationAssociationIdentifier
    (scoped to a real DataIntegration) rather than silently reporting success, and also rejects
    a nonexistent parent DataIntegration Identifier."""
    key_arn = _create_kms_key_for_appintegrations(ctx)
    appi = ctx.client("appintegrations")
    bucket = _create_s3_source_bucket(ctx)
    name = ctx.unique_name("sim2real-di-updassoc-")

    created = appi.create_data_integration(
        Name=name, KmsKey=key_arn, SourceURI=f"s3://{bucket}"
    )
    identifier = created["Id"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, identifier))

    bogus_assoc_id = "00000000-0000-0000-0000-000000000000"
    # ON_DEMAND, because AWS refuses any SCHEDULED configuration before it looks up the association.
    exec_cfg = {"ExecutionMode": "ON_DEMAND", "OnDemandConfiguration": {"StartTime": str(int(time.time()) * 1000)}}

    code, message = _client_error(
        lambda: appi.update_data_integration_association(
            DataIntegrationIdentifier=identifier,
            DataIntegrationAssociationIdentifier=bogus_assoc_id,
            ExecutionConfiguration=exec_cfg,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected_message = (
        f"Could not find DataIntegrationAssociation with DataIntegrationName: {identifier} "
        f"and DataIntegrationAssociationId: {bogus_assoc_id}."
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    bogus_di_id = "11111111-1111-1111-1111-111111111111"
    code2, message2 = _client_error(
        lambda: appi.update_data_integration_association(
            DataIntegrationIdentifier=bogus_di_id,
            DataIntegrationAssociationIdentifier=bogus_assoc_id,
            ExecutionConfiguration=exec_cfg,
        )
    )
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2!r}"
    expected_message2 = (
        f"Could not find DataIntegrationAssociation with DataIntegrationName: {bogus_di_id} "
        f"and DataIntegrationAssociationId: {bogus_assoc_id}."
    )
    assert message2 == expected_message2, f"expected {expected_message2!r}, got {message2!r}"

    # Effect absent: the real DataIntegration is untouched (still retrievable, no phantom association).
    got = appi.get_data_integration(Identifier=identifier)
    assert got["Id"] == identifier, f"expected Id {identifier!r}, got {got.get('Id')!r}"
    listed = appi.list_data_integration_associations(DataIntegrationIdentifier=identifier)
    assert listed["DataIntegrationAssociations"] == [], (
        f"expected no associations on {identifier!r}, got {listed['DataIntegrationAssociations']!r}"
    )


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


def _try_delete_data_integration(appi: Any, identifier: str) -> None:
    try:
        appi.delete_data_integration(DataIntegrationIdentifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

