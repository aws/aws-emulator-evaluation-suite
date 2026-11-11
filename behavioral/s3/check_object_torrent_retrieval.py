"""object-torrent-retrieval."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "object-torrent-retrieval"
GROUP = "state-machine"
SERVICES = ["s3"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObjectTorrent (BitTorrent delivery) has been retired: S3 now rejects every request for
    it with MethodNotAllowed, even for a real, freshly-stored object."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "media/sample.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"torrent-source-bytes" * 100)

    code, message = _error_code(lambda: s3.get_object_torrent(Bucket=bucket, Key=key))
    assert code == "MethodNotAllowed", f"expected MethodNotAllowed (BitTorrent delivery retired), got {code}"
    assert message == "The specified method is not allowed against this resource.", (
        f"expected the exact MethodNotAllowed message, got {message!r}"
    )

    # The rejected call had no side effect: the object itself is still retrievable untouched.
    got = s3.get_object(Bucket=bucket, Key=key)
    body = got["Body"].read()
    assert body == b"torrent-source-bytes" * 100, (
        f"expected the rejected GetObjectTorrent to leave the object untouched, got {len(body)} bytes back"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError("expected get_object_torrent to raise, but it returned a body")


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-s3-behav-").lower()
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
