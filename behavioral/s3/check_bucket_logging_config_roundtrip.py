"""bucket-logging-config-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bucket-logging-config-roundtrip"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Server access logging target/prefix set via PutBucketLogging is reflected exactly by
    GetBucketLogging, and disabling logging (empty status) reverts GetBucketLogging to empty."""
    s3 = ctx.client("s3")

    target = ctx.unique_name("sim2real-logtarget-")
    _create_bucket(ctx, s3, target, ObjectOwnership="BucketOwnerPreferred")
    _grant_log_delivery(ctx, s3, target)

    source = ctx.unique_name("sim2real-logsrc-")
    _create_bucket(ctx, s3, source)

    s3.put_bucket_logging(
        Bucket=source,
        BucketLoggingStatus={
            "LoggingEnabled": {"TargetBucket": target, "TargetPrefix": "logs/"}
        },
    )
    got = s3.get_bucket_logging(Bucket=source)
    enabled = got["LoggingEnabled"]
    assert enabled["TargetBucket"] == target, enabled
    assert enabled["TargetPrefix"] == "logs/", enabled

    # Disabling logging (empty status document) reverts to no logging configuration.
    s3.put_bucket_logging(Bucket=source, BucketLoggingStatus={})
    got_after = s3.get_bucket_logging(Bucket=source)
    assert "LoggingEnabled" not in got_after, got_after


def _create_bucket(ctx, s3, name, **kwargs):
    params = {"Bucket": name}
    if getattr(ctx, "region", None) and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]},
    )


def _grant_log_delivery(ctx, s3, bucket):
    """Grant the S3 LogDelivery group WRITE + READ_ACP so PutBucketLogging accepts this
    bucket as a valid logging target (this is not a public grant, so account-level
    Block Public Access settings do not interfere with it)."""
    acl = s3.get_bucket_acl(Bucket=bucket)
    owner = acl["Owner"]
    grants = [{"Grantee": {"Type": "CanonicalUser", "ID": owner["ID"]}, "Permission": "FULL_CONTROL"}]
    for perm in ("WRITE", "READ_ACP"):
        grants.append(
            {
                "Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery"},
                "Permission": perm,
            }
        )
    s3.put_bucket_acl(Bucket=bucket, AccessControlPolicy={"Owner": owner, "Grants": grants})


def _empty_and_delete_bucket(ctx, s3, name):
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": d["Key"], "VersionId": d["VersionId"]} for d in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        for u in s3.list_multipart_uploads(Bucket=name).get("Uploads", []):
            s3.abort_multipart_upload(Bucket=name, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
