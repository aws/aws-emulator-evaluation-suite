"""object-tagging-delete."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-tagging-delete"
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
    """DeleteObjectTagging removes all tags."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="tag-del.txt", Body=b"data")
    tags = {"TagSet": [{"Key": "remove-me", "Value": "yes"}]}
    s3.put_object_tagging(Bucket=bucket, Key="tag-del.txt", Tagging=tags)
    before = s3.get_object_tagging(Bucket=bucket, Key="tag-del.txt")
    assert before["TagSet"] == [{"Key": "remove-me", "Value": "yes"}], (
        f"expected the tag to be set before delete, got {before['TagSet']!r}"
    )
    s3.delete_object_tagging(Bucket=bucket, Key="tag-del.txt")
    resp = s3.get_object_tagging(Bucket=bucket, Key="tag-del.txt")
    assert resp["TagSet"] == [], f"expected empty TagSet, got {resp['TagSet']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
