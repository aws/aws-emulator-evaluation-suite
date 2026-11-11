"""if-none-match."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "if-none-match"
GROUP = 'conditional'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject with If-None-Match matching the ETag returns 304 Not Modified; a
    non-matching value still serves the object, and an unconditional read afterward
    is unaffected."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"none-match-test"
    put_resp = s3.put_object(Bucket=bucket, Key="nm.txt", Body=body)
    etag = put_resp["ETag"]

    control = s3.get_object(Bucket=bucket, Key="nm.txt", IfNoneMatch='"not-the-etag"')
    assert control["Body"].read() == body, "positive control: mismatching If-None-Match must still serve the object"

    try:
        s3.get_object(Bucket=bucket, Key="nm.txt", IfNoneMatch=etag)
        raise AssertionError("expected 304 but request succeeded")
    except ClientError as exc:
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert status == 304, f"expected 304, got status {status}"

    after = s3.get_object(Bucket=bucket, Key="nm.txt")
    assert after["Body"].read() == body, "unconditional GetObject must still succeed after the 304"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
