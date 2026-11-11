"""classification-export-configuration-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "classification-export-configuration-round-trip"
GROUP = "data-plane"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """PutClassificationExportConfiguration persists the S3 destination bucket and KMS key exactly."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_scratch_bucket(ctx)
    key_arn = _create_kms_key(ctx, account_id, ctx.region)
    _apply_export_bucket_policy(ctx, bucket, account_id, ctx.region, key_arn)

    original = macie.get_classification_export_configuration().get("configuration", {})
    ctx.on_cleanup(lambda: _restore(macie, original))

    macie.put_classification_export_configuration(
        configuration={
            "s3Destination": {
                "bucketName": bucket,
                "kmsKeyArn": key_arn,
                "keyPrefix": "sim2real-macie-exports/",
            }
        }
    )

    fetched = macie.get_classification_export_configuration()["configuration"]["s3Destination"]
    assert fetched["bucketName"] == bucket, f"expected bucketName {bucket!r}, got {fetched['bucketName']!r}"
    assert fetched["kmsKeyArn"] == key_arn, f"expected kmsKeyArn {key_arn!r}, got {fetched['kmsKeyArn']!r}"
    assert fetched["keyPrefix"] == "sim2real-macie-exports/", (
        f"expected keyPrefix 'sim2real-macie-exports/', got {fetched['keyPrefix']!r}"
    )


def _apply_export_bucket_policy(ctx, bucket, account_id, region, key_arn) -> None:
    import json

    s3 = ctx.client("s3")
    export_arn_base = f"arn:aws:macie2:{region}:{account_id}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowMacieGetBucketLocation",
                "Effect": "Allow",
                "Principal": {"Service": "macie.amazonaws.com"},
                "Action": "s3:GetBucketLocation",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": [
                            f"{export_arn_base}:export-configuration:*",
                            f"{export_arn_base}:classification-job/*",
                        ]
                    },
                },
            },
            {
                "Sid": "AllowMaciePutObject",
                "Effect": "Allow",
                "Principal": {"Service": "macie.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket}/sim2real-macie-exports/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": [
                            f"{export_arn_base}:export-configuration:*",
                            f"{export_arn_base}:classification-job/*",
                        ]
                    },
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

def _restore(macie, original) -> None:
    from botocore.exceptions import ClientError

    try:
        macie.put_classification_export_configuration(configuration=original or {})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-macie-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "macie2-behavioral"}]})

    def _empty_and_delete() -> None:
        from botocore.exceptions import ClientError

        try:
            for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
                objs = [
                    {"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if objs:
                    failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_empty_and_delete)
    return name


def _create_kms_key(ctx, account_id, region) -> str:
    import json

    kms = ctx.client("kms")
    export_arn_base = f"arn:aws:macie2:{region}:{account_id}"
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowMacieToUseTheKey",
                "Effect": "Allow",
                "Principal": {"Service": "macie.amazonaws.com"},
                "Action": ["kms:GenerateDataKey", "kms:Encrypt"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": [
                            f"{export_arn_base}:export-configuration:*",
                            f"{export_arn_base}:classification-job/*",
                        ]
                    },
                },
            },
        ],
    }
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-macie-key-"),
        Policy=json.dumps(key_policy),
        Tags=[{"TagKey": "sim2real", "TagValue": "macie2-behavioral"}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key["Arn"]



def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
