"""object-tagging-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-tagging-roundtrip"
GROUP = 'tagging'
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
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutObjectTagging then GetObjectTagging returns the same tags, and a second
    PutObjectTagging call REPLACES the tag set rather than merging into it."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="tagged.txt", Body=b"data")
    tags = {"TagSet": [{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "sim2real"}]}
    s3.put_object_tagging(Bucket=bucket, Key="tagged.txt", Tagging=tags)
    resp = s3.get_object_tagging(Bucket=bucket, Key="tagged.txt")
    got = {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    assert got == {"env": "test", "team": "sim2real"}, f"tag mismatch: {got}"

    replacement = {"TagSet": [{"Key": "stage", "Value": "prod"}]}
    s3.put_object_tagging(Bucket=bucket, Key="tagged.txt", Tagging=replacement)
    resp2 = s3.get_object_tagging(Bucket=bucket, Key="tagged.txt")
    got2 = {t["Key"]: t["Value"] for t in resp2.get("TagSet", [])}
    assert got2 == {"stage": "prod"}, f"expected PutObjectTagging to replace, not merge: {got2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
