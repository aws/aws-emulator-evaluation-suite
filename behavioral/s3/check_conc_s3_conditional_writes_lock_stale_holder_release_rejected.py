"""conc-s3-conditional-writes-lock-stale-holder-release-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-lock-stale-holder-release-rejected"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_PRECONDITION_FAILED = ("PreconditionFailed", 'At least one of the pre-conditions you specified did not hold')
_NO_SUCH_KEY = ("NoSuchKey", 'The specified key does not exist.')


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


def _message(exc):
    return exc.response.get("Error", {}).get("Message")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _refusal(exc):
    """(code, message) of a refused call."""
    return _code(exc), _message(exc)


def _holder(s3, bucket, key):
    got = s3.get_object(Bucket=bucket, Key=key)
    return got["Body"].read(), got["ETag"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 as a lock (If-None-Match:* acquire, If-Match renew/release): once A's lock passes to B,
    A's stale ETag is refused with 412 for both release and renew, so B keeps the lock.
    Controls: A's own release and B's renew and release with B's current ETag succeed.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    lock = ctx.unique_name("locks/job-")
    token_a = ctx.unique_name("holder-a-").encode()
    token_b = ctx.unique_name("holder-b-").encode()

    # A acquires.
    etag_a = s3.put_object(Bucket=bucket, Key=lock, Body=token_a, IfNoneMatch="*")["ETag"]

    # B contends and is refused; A still holds.
    contend = _client_error(lambda: s3.put_object(Bucket=bucket, Key=lock, Body=token_b,
                                                  IfNoneMatch="*"),
                            "B's acquire of a held lock SUCCEEDED")
    assert _refusal(contend) == _PRECONDITION_FAILED, (
        f"B's acquire of a held lock returned {_refusal(contend)!r}; want {_PRECONDITION_FAILED!r}"
    )
    assert _holder(s3, bucket, lock) == (token_a, etag_a), "B's refused acquire changed the lock"

    # POSITIVE CONTROL: A releases its own lock with its own ETag.
    released = s3.delete_object(Bucket=bucket, Key=lock, IfMatch=etag_a)
    assert released["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"A's release returned {released['ResponseMetadata']['HTTPStatusCode']!r}; want 204"
    )
    free = _client_error(lambda: s3.get_object(Bucket=bucket, Key=lock),
                         "after A's release the lock is still readable")
    assert _refusal(free) == _NO_SUCH_KEY, (
        f"after A's release the lock read gave {_refusal(free)!r}; want {_NO_SUCH_KEY!r}"
    )

    # B acquires the now-free lock.
    etag_b = s3.put_object(Bucket=bucket, Key=lock, Body=token_b, IfNoneMatch="*")["ETag"]
    assert etag_b != etag_a, f"B's lock has A's ETag {etag_a!r}; tokens must differ"

    # --- NEGATIVE: A's stale release is refused and B keeps the lock.
    stale_release = _client_error(lambda: s3.delete_object(Bucket=bucket, Key=lock,
                                                           IfMatch=etag_a),
                                  "A's stale release SUCCEEDED and deleted B's lock: two holders "
                                  "can now run concurrently")
    assert _refusal(stale_release) == _PRECONDITION_FAILED, (
        f"A's stale release returned {_refusal(stale_release)!r}; want {_PRECONDITION_FAILED!r}"
    )
    assert stale_release.response["ResponseMetadata"]["HTTPStatusCode"] == 412, (
        f"stale release HTTP status {stale_release.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert _holder(s3, bucket, lock) == (token_b, etag_b), (
        "A's refused release changed B's lock"
    )

    # --- NEGATIVE: A's stale renew is refused and B keeps the lock.
    stale_renew = _client_error(lambda: s3.put_object(Bucket=bucket, Key=lock,
                                                      Body=token_a + b"-renewed", IfMatch=etag_a),
                                "A's stale renew SUCCEEDED and overwrote B's lock")
    assert _refusal(stale_renew) == _PRECONDITION_FAILED, (
        f"A's stale renew returned {_refusal(stale_renew)!r}; want {_PRECONDITION_FAILED!r}"
    )
    assert _holder(s3, bucket, lock) == (token_b, etag_b), "A's refused renew changed B's lock"

    # POSITIVE CONTROL: B renews with its own ETag, then releases with the renewed ETag.
    renewed = token_b + b"-renewed"
    etag_b2 = s3.put_object(Bucket=bucket, Key=lock, Body=renewed, IfMatch=etag_b)["ETag"]
    assert _holder(s3, bucket, lock) == (renewed, etag_b2), "B's renew did not land"
    old_b = _client_error(lambda: s3.delete_object(Bucket=bucket, Key=lock, IfMatch=etag_b),
                          "release with B's pre-renew ETag SUCCEEDED")
    assert _refusal(old_b) == _PRECONDITION_FAILED, (
        f"release with B's pre-renew ETag returned {_refusal(old_b)!r}; "
        f"want {_PRECONDITION_FAILED!r}"
    )
    s3.delete_object(Bucket=bucket, Key=lock, IfMatch=etag_b2)
    end = _client_error(lambda: s3.get_object(Bucket=bucket, Key=lock),
                        "after B's release the lock is still readable")
    assert _refusal(end) == _NO_SUCH_KEY, (
        f"after B's release the lock read gave {_refusal(end)!r}; want {_NO_SUCH_KEY!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
