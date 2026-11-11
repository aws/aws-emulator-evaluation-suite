"""object-user-metadata-keys-lowercased."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "object-user-metadata-keys-lowercased"
GROUP = 'data_integrity'
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
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """User metadata keys are normalised to lower case (they travel as HTTP headers) while values are preserved verbatim."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "usermeta.txt"
    s3.put_object(
        Bucket=bucket, Key=key, Body=b"x",
        Metadata={"MixedCase": "PreservedValue", "another-KEY": "v2"},
    )

    meta = s3.head_object(Bucket=bucket, Key=key)["Metadata"]
    assert set(meta) == {"mixedcase", "another-key"}, f"expected lower-cased metadata keys, got {sorted(meta)}"
    assert meta["mixedcase"] == "PreservedValue", "metadata values must NOT be case-folded"
    assert meta["another-key"] == "v2", f"expected value 'v2' preserved verbatim, got {meta['another-key']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
