"""virtual-hosted-and-path-style-putobject-if-match-preconditions-agree."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "virtual-hosted-and-path-style-putobject-if-match-preconditions-agree"
GROUP = "addressing"
SERVICES = ["s3"]

KEY = "cross-addr/conditional.bin"


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    s3.delete_bucket(Bucket=bucket)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutObject If-Match naming an ETag a sibling addressing style already superseded is
    refused PreconditionFailed and leaves the object unchanged, while an If-Match naming the
    current ETag succeeds across the two addressing styles.
    """
    plain = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-bkt-")
    create = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    plain.create_bucket(**create)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete_bucket(plain, bucket), "NoSuchBucket"))

    vhost = ctx.client("s3", config=Config(s3={"addressing_style": "virtual"}, retries={"max_attempts": 1}))
    pstyle = ctx.client("s3", config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))

    v1 = b"first version, written virtual-hosted"
    put1 = vhost.put_object(Bucket=bucket, Key=KEY, Body=v1)
    etag1 = put1["ETag"]

    # positive control: a path-style client's If-Match naming the virtual-hosted client's ETag
    # is accepted, proving the two addressing styles see the same ETag for the same write.
    v2 = b"second version, written path-style under If-Match of the first"
    put2 = pstyle.put_object(Bucket=bucket, Key=KEY, Body=v2, IfMatch=etag1)
    etag2 = put2["ETag"]
    assert etag2 != etag1, f"second PutObject ETag {etag2!r} did not change from {etag1!r}"
    seen = vhost.get_object(Bucket=bucket, Key=KEY)
    assert seen["Body"].read() == v2, "virtual-hosted client did not observe the path-style write"
    assert seen["ETag"] == etag2, f"virtual-hosted client saw ETag {seen['ETag']!r}, expected {etag2!r}"

    # negative: retrying If-Match against the now-stale first ETag is refused from the virtual-
    # hosted client, and the object is left exactly as the path-style write left it.
    v3 = b"third version, must never be written"
    precondition_failed = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
    code, message = _error(lambda: vhost.put_object(Bucket=bucket, Key=KEY, Body=v3, IfMatch=etag1))
    assert (code, message) == precondition_failed, (
        f"stale If-Match PutObject: expected {precondition_failed}, got {(code, message)!r}"
    )

    unchanged = pstyle.get_object(Bucket=bucket, Key=KEY)
    assert unchanged["Body"].read() == v2, "the object changed despite the refused PutObject"
    assert unchanged["ETag"] == etag2, (
        f"path-style client saw ETag {unchanged['ETag']!r} after the refusal, expected {etag2!r} unchanged"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
