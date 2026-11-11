"""get-object-acl-no-such-key."""

from __future__ import annotations
from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "get-object-acl-no-such-key"
GROUP = 'acls_policies'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Positive control: GetObjectAcl on a key that exists succeeds and reports an owner.
    GetObjectAcl on a key that was never written raises the specific NoSuchKey error."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "exists.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"acl-positive-control")

    acl = s3.get_object_acl(Bucket=bucket, Key=key)
    owner_id = acl.get("Owner", {}).get("ID")
    assert owner_id, f"expected an owner ID on the positive control, got {acl.get('Owner')!r}"

    err = _err(lambda: s3.get_object_acl(Bucket=bucket, Key="never-existed.txt"), "GetObjectAcl on a never-written key")
    assert err.get("Code") == "NoSuchKey", f"expected NoSuchKey, got {err}"
    assert err.get("Message") == "The specified key does not exist.", err.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
