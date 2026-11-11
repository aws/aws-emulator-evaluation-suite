"""range-read-open-end."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "range-read-open-end"
GROUP = 'range_reads'
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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject with Range='bytes=10-' returns from byte 10 to end."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"0123456789ABCDEF"
    s3.put_object(Bucket=bucket, Key="range-open.bin", Body=body)
    resp = s3.get_object(Bucket=bucket, Key="range-open.bin", Range="bytes=10-")
    got = resp["Body"].read()
    assert got == b"ABCDEF", f"expected b'ABCDEF', got {got!r}"
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 206, (
        f"an open-ended satisfiable range must be 206, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert resp["ContentLength"] == 6, f"expected ContentLength 6, got {resp['ContentLength']}"
    assert resp.get("ContentRange") == f"bytes 10-{len(body) - 1}/{len(body)}", (
        f"unexpected ContentRange: {resp.get('ContentRange')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
