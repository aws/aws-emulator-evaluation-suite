"""delete-objects-conditional-etag-mismatch-survives."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-objects-conditional-etag-mismatch-survives"
GROUP = "conditional"
SERVICES = ["s3"]

_WRONG_ETAG = '"deadbeefdeadbeefdeadbeefdeadbeef"'
_PRECONDITION_MSG = "At least one of the pre-conditions you specified did not hold"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch DeleteObjects evaluates each entry's ETag independently: the matching
    entry lands in Deleted and is gone, the mismatching one lands in Errors with
    PreconditionFailed and its object survives untouched."""
    s3 = ctx.client("s3")
    bucket = _make_bucket(ctx, "sim2real-behav-delcond-")

    match_key, mismatch_key = "match.txt", "mismatch.txt"
    match_etag = s3.put_object(Bucket=bucket, Key=match_key, Body=b"delete-me")["ETag"]
    mismatch_etag = s3.put_object(Bucket=bucket, Key=mismatch_key, Body=b"keep-me")["ETag"]

    resp = s3.delete_objects(
        Bucket=bucket,
        Delete={
            "Objects": [
                {"Key": match_key, "ETag": match_etag},
                {"Key": mismatch_key, "ETag": _WRONG_ETAG},
            ]
        },
    )

    deleted = [d["Key"] for d in resp.get("Deleted", [])]
    assert deleted == [match_key], f"expected only {match_key!r} deleted, got {deleted!r}"

    errors = [{"Key": e["Key"], "Code": e["Code"], "Message": e["Message"]}
              for e in resp.get("Errors", [])]
    want_errors = [{"Key": mismatch_key, "Code": "PreconditionFailed", "Message": _PRECONDITION_MSG}]
    assert errors == want_errors, f"expected {want_errors!r}, got {errors!r}"

    match_absent = _error(lambda: s3.head_object(Bucket=bucket, Key=match_key))
    assert match_absent[0] == "404", f"the matching key must be gone, got {match_absent!r}"

    survivor = s3.head_object(Bucket=bucket, Key=mismatch_key)
    assert survivor["ETag"] == mismatch_etag, (
        f"the mismatched key must survive unchanged; ETag {survivor['ETag']!r} != {mismatch_etag!r}"
    )


def _make_bucket(ctx, prefix: str) -> str:
    """A bucket under ctx.unique_name; cleanup is registered before any other call."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; raises itself on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
