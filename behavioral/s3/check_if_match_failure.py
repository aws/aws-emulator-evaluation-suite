"""if-match-failure."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "if-match-failure"
GROUP = 'conditional'
SERVICES = ['s3']

ERR_PRECONDITION_FAILED = "PreconditionFailed"

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


def _client_error(fn):
    """Call fn(); return the ClientError's Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject with If-Match NOT matching returns PreconditionFailed (412); the identical
    call with the object's actual current ETag succeeds, proving the rejection tracks the
    mismatch and is not a blanket refusal of every conditional GetObject."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    body = b"original"
    put_resp = s3.put_object(Bucket=bucket, Key="cond.txt", Body=body)
    current_etag = put_resp["ETag"]

    # Positive control: the correct current ETag must be accepted.
    control = s3.get_object(Bucket=bucket, Key="cond.txt", IfMatch=current_etag)
    assert control["Body"].read() == body, "expected the matching If-Match GetObject to succeed"

    # Break exactly one thing: a mismatched ETag must be rejected.
    err = _client_error(lambda: s3.get_object(Bucket=bucket, Key="cond.txt", IfMatch='"bogus-etag"'))
    assert err.get("Code") == ERR_PRECONDITION_FAILED, f"expected {ERR_PRECONDITION_FAILED}, got {err!r}"
    assert err.get("Message") == "At least one of the pre-conditions you specified did not hold", err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
