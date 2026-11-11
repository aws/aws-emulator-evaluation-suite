"""bucket-metadata-annotation-table-update."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-metadata-annotation-table-update"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a base S3 Metadata configuration exists, UpdateBucketMetadataAnnotationTableConfiguration
    modifies the annotation-table settings and GetBucketMetadataConfiguration reflects the update."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    bucket = ctx.unique_name("sim2real-metaann-")
    _create_bucket(s3, ctx, bucket)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    ctx.on_cleanup(lambda: _delete_metadata_tables(ctx, bucket))
    ctx.on_cleanup(lambda: _safe(s3.delete_bucket_metadata_configuration, Bucket=bucket))

    base_cfg = {"JournalTableConfiguration": {"RecordExpiration": {"Expiration": "DISABLED"}}}
    try:
        s3.create_bucket_metadata_configuration(Bucket=bucket, MetadataConfiguration=base_cfg)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError("insufficient permissions to create S3 Metadata configuration") from exc
        raise

    before = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: "JournalTableConfigurationResult" in r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"],
        timeout_s=60,
        interval_s=3,
    )
    before_result = before["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    # A freshly created base configuration may already report a default annotation-table
    # entry (e.g. ConfigurationState DISABLED) rather than omitting the key entirely, so
    # capture whatever the current state actually is instead of assuming it is absent, and
    # drive the update to the opposite state so the effect of the update is observable.
    before_annotation = before_result.get("AnnotationTableConfigurationResult")
    before_state = before_annotation["ConfigurationState"] if before_annotation else "DISABLED"
    target_state = "ENABLED" if before_state != "ENABLED" else "DISABLED"

    annotation_cfg = {"ConfigurationState": target_state}
    role_name = None
    if target_state == "ENABLED":
        # Real AWS rejects the update with InvalidRequest ("When AnnotationTableConfiguration
        # is set to ENABLED, Role must be specified. Specify a valid Role ARN, and then try
        # again.") unless a Role S3 can assume (to manage the underlying annotation table) is
        # supplied, so provision one here and pass its ARN.
        try:
            role_name, role_arn = _create_annotation_role(iam, sts, bucket)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in ("AccessDenied", "AccessDeniedException"):
                raise AssertionError("insufficient permissions to create the annotation-table IAM role") from exc
            raise
        ctx.on_cleanup(lambda: _delete_role(iam, role_name))
        annotation_cfg["Role"] = role_arn

    # IAM role creation is eventually consistent from S3's point of view; retry a bounded
    # window on InvalidRequest rather than assuming the freshly created role is immediately
    # assumable.
    _update_annotation_table_with_retry(s3, bucket, annotation_cfg)

    after = _poll_until(
        lambda: s3.get_bucket_metadata_configuration(Bucket=bucket),
        lambda r: r["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
        .get("AnnotationTableConfigurationResult", {})
        .get("ConfigurationState")
        == target_state,
        timeout_s=60,
        interval_s=3,
    )
    after_result = after["GetBucketMetadataConfigurationResult"]["MetadataConfigurationResult"]
    after_annotation = after_result["AnnotationTableConfigurationResult"]
    assert after_annotation["ConfigurationState"] == target_state, (
        f"expected AnnotationTableConfigurationResult.ConfigurationState {target_state!r}, "
        f"got {after_annotation['ConfigurationState']!r}"
    )
    if target_state == "ENABLED":
        assert after_annotation.get("Role") == role_arn, (
            f"expected the update to echo back the supplied Role {role_arn!r}, got {after_annotation.get('Role')!r}"
        )
    assert target_state != before_state, "update should actually change the annotation table configuration state"


def _create_bucket(s3, ctx, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's one API-level exception: it is the only region for which
    # LocationConstraint must be omitted rather than supplied, regardless of ctx.region's value.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})


def _safe(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "MetadataConfigurationNotFound",
            "NoSuchBucket",
            "NoSuchEntity",
        ):
            raise


def _create_annotation_role(iam, sts, bucket: str):
    account_id = sts.get_caller_identity()["Account"]
    role_name = f"sim2real-metaann-{bucket[-24:]}"[:64]
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"},
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="sim2real: temporary role for S3 Metadata annotation table check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-metaann-policy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": ["s3tables:*", "s3:*"], "Resource": "*"}],
            }
        ),
    )
    return role_name, role["Arn"]


def _delete_role(iam, role_name: str) -> None:
    _safe(iam.delete_role_policy, RoleName=role_name, PolicyName="sim2real-metaann-policy")
    _safe(iam.delete_role, RoleName=role_name)


def _update_annotation_table_with_retry(s3, bucket, annotation_table_configuration, *, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            s3.update_bucket_metadata_annotation_table_configuration(
                Bucket=bucket, AnnotationTableConfiguration=annotation_table_configuration
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidRequest":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last result: {last!r}")


def _delete_metadata_tables(ctx, bucket: str) -> None:
    """Delete the journal and inventory tables, and their namespace, that the bucket's metadata
    configuration leaves in the account's AWS-managed table bucket: deleting the configuration
    or the bucket keeps them, and they bill. Only an already-absent table or namespace is
    tolerated."""
    from botocore.exceptions import ClientError

    tables = ctx.client("s3tables")
    arn = f"arn:aws:s3tables:{ctx.region}:{ctx.account}:bucket/aws-s3"
    namespace = f"b_{bucket}"
    try:
        for page in tables.get_paginator("list_tables").paginate(
            tableBucketARN=arn, namespace=namespace
        ):
            for table in page.get("tables", []):
                tables.delete_table(tableBucketARN=arn, namespace=namespace, name=table["name"])
        tables.delete_namespace(tableBucketARN=arn, namespace=namespace)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

