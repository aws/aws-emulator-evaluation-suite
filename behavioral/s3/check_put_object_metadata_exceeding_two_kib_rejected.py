"""put-object-metadata-exceeding-two-kib-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-metadata-exceeding-two-kib-rejected"
GROUP = "lifecycle"
SERVICES = ["s3"]

# AWS limits the user-defined metadata (header names + values together) on an object to 2 KiB.
_OVER_LIMIT_VALUE = "v" * 3000

_METADATA_TOO_LARGE = ("MetadataTooLarge", "Your metadata headers exceed the maximum allowed metadata size")
_NOT_FOUND = ("404", "Not Found")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject rejects user-defined metadata over 2 KiB and leaves the key absent; a small
    metadata set on the same key succeeds and is readable back from HeadObject.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "lifecycle/metadata-target.bin"

    expect_error(
        lambda: s3.put_object(
            Bucket=bucket, Key=key, Body=b"x", Metadata={"sim2real-big": _OVER_LIMIT_VALUE}
        ),
        *_METADATA_TOO_LARGE,
    )
    expect_error(lambda: s3.head_object(Bucket=bucket, Key=key), *_NOT_FOUND)

    # --- Control: metadata well under the limit, on the same key, succeeds.
    s3.put_object(Bucket=bucket, Key=key, Body=b"x", Metadata={"sim2real-small": "ok"})
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["Metadata"].get("sim2real-small") == "ok", (
        f"HeadObject metadata {head['Metadata']!r} must carry the small value that was put"
    )


def expect_error(fn, code: str, message: str) -> None:
    """Call fn(); assert its exact (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err.get('Code')!r}"
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected ({code}, {message!r}), but the call succeeded: {result!r}")


def _new_bucket(ctx, s3) -> str:
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-metasz-")
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _delete_bucket(client, bucket: str) -> None:
    """Empty the bucket then delete it. Tolerates only NoSuchBucket; any other error raises."""
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                out = client.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
