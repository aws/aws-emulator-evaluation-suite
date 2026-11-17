"""tag-resource-on-data-integration-list-and-get-agree-after-each-step."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-on-data-integration-list-and-get-agree-after-each-step"
GROUP = "data-plane"
SERVICES = ["appintegrations", "kms", "s3", "sts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a DataIntegration, TagResource adds a key, UntagResource removes only that key, and a
    repeated TagResource overwrites only the named key — GetDataIntegration Tags agrees with
    ListTagsForResource after creation and after each tagging step.
    """
    appi = ctx.client("appintegrations")

    key_arn = _create_kms_key_for_appintegrations(ctx)
    bucket = _create_s3_source_bucket(ctx)
    name = ctx.unique_name("sim2real-di-tags-")

    created = appi.create_data_integration(
        Name=name,
        KmsKey=key_arn,
        SourceURI=f"s3://{bucket}",
        Tags={"owner": "ops"},
    )
    data_id = created["Id"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, data_id))

    _assert_tags_agree(appi, arn, data_id, {"owner": "ops"}, "after creation")

    appi.tag_resource(resourceArn=arn, tags={"cost-center": "eng"})
    _assert_tags_agree(
        appi, arn, data_id, {"owner": "ops", "cost-center": "eng"}, "after TagResource adds a key"
    )

    appi.untag_resource(resourceArn=arn, tagKeys=["cost-center"])
    _assert_tags_agree(
        appi, arn, data_id, {"owner": "ops"}, "after UntagResource removes only that key"
    )

    appi.tag_resource(resourceArn=arn, tags={"owner": "finance"})
    _assert_tags_agree(
        appi, arn, data_id, {"owner": "finance"}, "after TagResource overwrites only that key's value"
    )


def _assert_tags_agree(appi: Any, arn: str, data_id: str, expected: dict, when: str) -> None:
    listed = appi.list_tags_for_resource(resourceArn=arn)["tags"]
    assert listed == expected, f"[{when}] expected ListTagsForResource tags {expected!r}, got {listed!r}"

    got = appi.get_data_integration(Identifier=data_id)["Tags"]
    assert got == expected, f"[{when}] expected GetDataIntegration Tags {expected!r}, got {got!r}"


def _create_s3_source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    region = s3.meta.region_name
    bucket = ctx.unique_name("sim2real-appintegrations-tags").lower().replace("_", "-")
    kwargs: dict = {"Bucket": bucket}
    if region and region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _teardown_bucket(s3, bucket))
    return bucket


def _teardown_bucket(s3: Any, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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
    ctx.on_cleanup(lambda: _teardown_key(kms, key_id))
    return key["Arn"]


def _teardown_key(kms: Any, key_id: str) -> None:
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NotFoundException", "KMSInvalidStateException"):
            raise


def _try_delete_data_integration(appi: Any, identifier: str, timeout_s: float = 60.0) -> None:
    try:
        appi.delete_data_integration(DataIntegrationIdentifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    # Wait until it is gone: the key's teardown runs next and the service may still be deleting.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            appi.get_data_integration(Identifier=identifier)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"data integration {identifier} still present after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
