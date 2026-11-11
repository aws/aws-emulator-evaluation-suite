"""create-session-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "create-session-roundtrip"
GROUP = "directory_buckets"
SERVICES = ["s3"]

# S3 Express One Zone Availability-Zone ids keyed by region (directory buckets are Zonal).
EXPRESS_ZONE_IDS = {
    "us-east-1": "use1-az4",
    "us-east-2": "use2-az1",
    "us-west-2": "usw2-az1",
    "ap-south-1": "aps1-az1",
    "ap-northeast-1": "apne1-az1",
    "eu-central-1": "euc1-az1",
    "eu-west-1": "euw1-az1",
    "eu-north-1": "eun1-az1",
}


def _delete_directory_bucket(client, bucket):
    """Delete every object + abort lingering multipart uploads in a directory bucket, then delete it.

    Directory buckets have no versioning/delete-markers, so this is simpler than a general bucket empty.
    """
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []) or []:
                try:
                    client.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        resp = client.list_multipart_uploads(Bucket=bucket)
        for u in resp.get("Uploads", []) or []:
            try:
                client.abort_multipart_upload(
                    Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"]
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "NoSuchBucket",
                    "NoSuchKey",
                    "NoSuchUpload",
                ):
                    raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_directory_bucket(ctx, s3):
    """Create an S3 Express One Zone directory bucket, register teardown, return its name.

    Non-ctx capability inlined faithfully: Express One Zone Zonal bucket creation. Skips when
    the region has no known Express AZ or the installed botocore lacks the directory-bucket shape.
    """
    zone_id = EXPRESS_ZONE_IDS.get(ctx.region)
    if not zone_id:
        raise AssertionError(
            f"no known S3 Express One Zone Availability Zone for region {ctx.region!r}"
        )
    name = f"{ctx.unique_name('sim2real-dir-')}--{zone_id}--x-s3"
    try:
        s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": zone_id},
                "Bucket": {
                    "Type": "Directory",
                    "DataRedundancy": "SingleAvailabilityZone",
                },
            },
        )
    except Exception as exc:
        raise AssertionError(
            f"directory bucket creation not supported here: {exc}"
        ) from exc
    ctx.on_cleanup(lambda: _delete_directory_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSession on a directory bucket returns full temporary credentials for both SessionMode
    values, with distinct access keys, and an object written afterwards reads back byte for byte through
    a separate GetObject."""
    s3 = ctx.client("s3")
    name = _new_directory_bucket(ctx, s3)

    try:
        rw = s3.create_session(Bucket=name)
        ro = s3.create_session(Bucket=name, SessionMode="ReadOnly")
    except AttributeError as exc:
        raise AssertionError(
            f"installed botocore lacks CreateSession support: {exc}"
        ) from exc

    rw_creds = rw["Credentials"]
    ro_creds = ro["Credentials"]
    for label, creds in (("ReadWrite", rw_creds), ("ReadOnly", ro_creds)):
        assert {
            "AccessKeyId",
            "SecretAccessKey",
            "SessionToken",
            "Expiration",
        } <= creds.keys(), (
            f"{label} CreateSession response missing a credential field, got {sorted(creds.keys())}"
        )
    assert ro_creds["AccessKeyId"] != rw_creds["AccessKeyId"], (
        "CreateSession(SessionMode='ReadOnly') must mint a session distinct from the default "
        "ReadWrite session, not echo the same credentials back"
    )

    # The independent read: PutObject (mutation) followed by a separate GetObject call proves the
    # directory bucket is genuinely usable for session-authorized data-plane calls right after
    # minting -- not just a shape-valid CreateSession response with credentials nothing exercises.
    key = "roundtrip-obj.txt"
    payload = b"create-session-roundtrip-payload"
    s3.put_object(Bucket=name, Key=key, Body=payload)
    assert s3.get_object(Bucket=name, Key=key)["Body"].read() == payload, (
        "directory bucket did not round-trip an object written right after CreateSession"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
