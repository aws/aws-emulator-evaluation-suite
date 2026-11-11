"""list-objects-v2-delimiter."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-objects-v2-delimiter"
GROUP = 'lifecycle'
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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListObjectsV2 with Delimiter returns CommonPrefixes for 'directories'."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="a/1.txt", Body=b"1")
    s3.put_object(Bucket=bucket, Key="a/2.txt", Body=b"2")
    s3.put_object(Bucket=bucket, Key="b/1.txt", Body=b"3")
    s3.put_object(Bucket=bucket, Key="root.txt", Body=b"r")
    resp = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    prefixes = sorted(p["Prefix"] for p in resp.get("CommonPrefixes", []))
    assert prefixes == ["a/", "b/"], f"expected ['a/', 'b/'], got {prefixes}"
    root_keys = [obj["Key"] for obj in resp.get("Contents", [])]
    assert root_keys == ["root.txt"], f"expected ['root.txt'], got {root_keys}"
    assert resp["KeyCount"] == 3, f"KeyCount must count CommonPrefixes and Contents together (2 + 1 = 3), got {resp['KeyCount']!r}"
    assert resp["IsTruncated"] is False, f"a 3-entry stream under the default MaxKeys is not truncated, got {resp['IsTruncated']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
