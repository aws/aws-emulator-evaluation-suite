"""create-data-integration-nonexistent-kms-key-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-data-integration-nonexistent-kms-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["appintegrations"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataIntegration rejects a well-formed but nonexistent KmsKey ARN rather than
    silently accepting it, and no DataIntegration is left behind."""
    appi = ctx.client("appintegrations")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = appi.meta.region_name
    bogus_key_arn = f"arn:aws:kms:{region}:{account_id}:key/00000000-0000-0000-0000-000000000000"
    name = ctx.unique_name("sim2real-di-badkms-")
    bucket = _create_s3_source_bucket(ctx)

    code, _ = _client_error(
        lambda: appi.create_data_integration(
            Name=name,
            KmsKey=bogus_key_arn,
            SourceURI=f"s3://{bucket}",
        )
    )
    assert code == "InvalidRequestException", code
    # message varies: AWS embeds the KMS request id of its own failed key lookup.

    # Effect absent: no DataIntegration with this name was actually created.
    listed = appi.list_data_integrations(MaxResults=25)
    names = [d["Name"] for d in listed.get("DataIntegrationsSummary", [])]
    assert name not in names, f"expected {name!r} absent after rejected create, found it in {names!r}"

    # Positive control: a real, accessible KMS key allows creation to succeed.
    key_arn = _create_kms_key_for_appintegrations(ctx)
    control_name = ctx.unique_name("sim2real-di-goodkms-")
    created = appi.create_data_integration(
        Name=control_name,
        KmsKey=key_arn,
        SourceURI=f"s3://{bucket}",
    )
    control_id = created["Id"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, control_id))
    got = appi.get_data_integration(Identifier=control_id)
    assert got["KmsKey"] == key_arn, (
        f"expected positive-control DataIntegration KmsKey {key_arn!r}, got {got['KmsKey']!r}"
    )

    # Delete proves gone and unusable: an independent read now 404s, and a mutation on the
    # dead id fails the same specific way.
    appi.delete_data_integration(DataIntegrationIdentifier=control_id)
    gone_message_expected = f"Could not find DataIntegration with identifier: {control_id}."
    gone_code, gone_message = _client_error(lambda: appi.get_data_integration(Identifier=control_id))
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_message == gone_message_expected, f"expected {gone_message_expected!r}, got {gone_message!r}"
    mutate_code, mutate_message = _client_error(
        lambda: appi.update_data_integration(Identifier=control_id, Description="x")
    )
    assert mutate_code == "ResourceNotFoundException", mutate_code
    assert mutate_message == gone_message_expected, f"expected {gone_message_expected!r}, got {mutate_message!r}"


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
    import json

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

