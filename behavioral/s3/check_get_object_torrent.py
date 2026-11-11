"""get-object-torrent."""

from __future__ import annotations
from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "get-object-torrent"
GROUP = 'torrent'
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
    """S3 has withdrawn BitTorrent delivery: GetObjectTorrent on a small unencrypted object fails
    with MethodNotAllowed, while plain GetObject works and the object is unchanged."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    key = "torrent-me.bin"
    body = b"T" * 4096
    s3.put_object(Bucket=name, Key=key, Body=body)

    # Positive control: plain reads of the same object work.
    control = s3.get_object(Bucket=name, Key=key)
    assert control["Body"].read() == body, "positive control: plain GetObject must return what PutObject wrote"

    try:
        resp = s3.get_object_torrent(Bucket=name, Key=key)
        raw = resp.get("Body")
        data = raw.read() if raw is not None else b""
        raise AssertionError(
            f"GetObjectTorrent unexpectedly succeeded and returned {len(data)} bytes; "
            "real AWS has withdrawn BitTorrent delivery and must reject this call"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "MethodNotAllowed", (
            f"expected MethodNotAllowed (BitTorrent delivery retired), got {code!r}: {exc}"
        )
        message = exc.response.get("Error", {}).get("Message")
        assert message == "The specified method is not allowed against this resource.", (
            f"expected the exact MethodNotAllowed message, got {message!r}"
        )

    # Effect-absent: the rejected call must not have touched the object itself.
    after = s3.get_object(Bucket=name, Key=key)
    assert after["Body"].read() == body, "object must be unchanged after the rejected GetObjectTorrent call"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
