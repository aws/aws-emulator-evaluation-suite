"""bucket-tagging-roundtrip."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "bucket-tagging-roundtrip"
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
        # us-east-1 is CreateBucket's implicit default: passing a matching explicit
        # LocationConstraint there is the one case S3 rejects, so it is skipped, not pinned.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketTagging then GetBucketTagging returns the same tags, byte-for-byte, at the
    documented bounds: 50 tags (the fixed per-bucket maximum), a 0-length value (the documented
    minimum), and non-ASCII/punctuation characters the tag charset explicitly allows.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    tag_set = [
        {"Key": "project", "Value": "sim2real"},
        {"Key": "unicode-éè-中文", "Value": "üñ-日本語"},
        {"Key": "special.chars_test:val/1+2=3@x", "Value": ""},
    ]
    tag_set += [{"Key": f"filler-key-{i}", "Value": f"filler-value-{i}"} for i in range(47)]
    assert len(tag_set) == 50, f"test setup bug: built {len(tag_set)} tags, want 50"

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})
    resp = s3.get_bucket_tagging(Bucket=bucket)
    got = {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
    want = {t["Key"]: t["Value"] for t in tag_set}
    assert len(got) == 50, f"expected all 50 tags to roundtrip, got {len(got)}"
    assert got == want, f"tag mismatch: {got}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
