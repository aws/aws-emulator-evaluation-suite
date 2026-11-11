"""update-data-integration-persists-description."""
from __future__ import annotations

import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-data-integration-persists-description"
GROUP = "state"
SERVICES = ["appintegrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataIntegration persists a new Description, visible via GetDataIntegration."""
    key_arn = _create_kms_key_for_appintegrations(ctx)
    bucket = _create_s3_source_bucket(ctx)
    appi = ctx.client("appintegrations")
    name = ctx.unique_name("sim2real-di-upd-")

    created = appi.create_data_integration(
        Name=name,
        KmsKey=key_arn,
        Description="before-update",
        SourceURI=f"s3://{bucket}",
    )
    identifier = created["Id"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, identifier))

    appi.update_data_integration(Identifier=identifier, Description="after-update")

    got = appi.get_data_integration(Identifier=identifier)
    assert got["Description"] == "after-update", f"expected after-update, got {got.get('Description')!r}"
    assert got["Name"] == name, f"expected Name {name!r} unchanged, got {got.get('Name')!r}"
    assert got["KmsKey"] == key_arn, f"expected KmsKey {key_arn!r} unchanged, got {got.get('KmsKey')!r}"
    assert got["SourceURI"] == f"s3://{bucket}", (
        f"expected SourceURI unchanged, got {got.get('SourceURI')!r}"
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
