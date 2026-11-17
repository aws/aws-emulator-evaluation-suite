"""tag-resource-on-nonexistent-data-integration-rejected."""
from __future__ import annotations

import json
import uuid
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-on-nonexistent-data-integration-rejected"
GROUP = "negative-classes"
SERVICES = ["appintegrations", "kms", "s3", "sts"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource and UntagResource on a DataIntegration Arn that does not exist raise
    ResourceNotFoundException naming the Arn; ListTagsForResource on the same Arn raises
    NotFoundException with a different message. Each call succeeds on a real DataIntegration.
    """
    appi = ctx.client("appintegrations")

    missing_arn = (
        f"arn:aws:app-integrations:{ctx.region}:{ctx.account}:"
        f"data-integration/{uuid.uuid4()}"
    )
    _missing_tag_or_untag = (
        "ResourceNotFoundException",
        f"Could not find resource with Arn: {missing_arn}.",
    )
    _missing_list = ("NotFoundException", "Resource was not found")

    expect_error(
        lambda: appi.tag_resource(resourceArn=missing_arn, tags={"owner": "ops"}),
        *_missing_tag_or_untag,
    )
    expect_error(
        lambda: appi.untag_resource(resourceArn=missing_arn, tagKeys=["owner"]),
        *_missing_tag_or_untag,
    )
    expect_error(
        lambda: appi.list_tags_for_resource(resourceArn=missing_arn),
        *_missing_list,
    )

    # Positive control: the same three calls succeed against a real DataIntegration.
    key_arn = _create_kms_key_for_appintegrations(ctx)
    bucket = _create_s3_source_bucket(ctx)
    name = ctx.unique_name("sim2real-di-tagerr-")
    created = appi.create_data_integration(
        Name=name,
        KmsKey=key_arn,
        SourceURI=f"s3://{bucket}",
        Tags={"owner": "ops"},
    )
    data_id = created["Id"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _try_delete_data_integration(appi, data_id))

    appi.tag_resource(resourceArn=arn, tags={"cost-center": "eng"})
    listed = appi.list_tags_for_resource(resourceArn=arn)["tags"]
    assert listed == {"owner": "ops", "cost-center": "eng"}, (
        f"positive control: expected tags {{'owner': 'ops', 'cost-center': 'eng'}}, got {listed!r}"
    )

    appi.untag_resource(resourceArn=arn, tagKeys=["cost-center"])
    after_untag = appi.list_tags_for_resource(resourceArn=arn)["tags"]
    assert after_untag == {"owner": "ops"}, (
        f"positive control: expected tags {{'owner': 'ops'}} after untag, got {after_untag!r}"
    )


def _create_s3_source_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    region = s3.meta.region_name
    bucket = ctx.unique_name("sim2real-appintegrations-tagerr").lower().replace("_", "-")
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
