"""tag-resource-nonexistent-bucket-rejected."""
from __future__ import annotations

import time


from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-bucket-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an ARN for a vector bucket that does not exist
    returns NotFoundException rather than silently accepting the tag."""
    s3v = ctx.client("s3vectors")

    # Manufacture a well-formed but definitely-nonexistent bucket ARN: create
    # a real bucket to learn the correct ARN shape/partition, then delete it
    # and poll until the control plane confirms it is gone.
    throwaway_name = ctx.unique_name("sim2real-s3v-gone-")
    stale_arn = s3v.create_vector_bucket(vectorBucketName=throwaway_name)["vectorBucketArn"]
    s3v.delete_vector_bucket(vectorBucketName=throwaway_name)
    _poll_until_bucket_gone(s3v, throwaway_name)

    # (a) the specific error code against the now-nonexistent bucket ARN.
    err = _error(lambda: s3v.tag_resource(resourceArn=stale_arn, tags={"k": "v"}))
    assert err["Code"] == "NotFoundException", f"expected NotFoundException tagging a deleted bucket, got {err!r}"
    assert err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {err.get('Message')!r}"
    )

    # (b) the effect is absent: no tags exist to list on a resource that
    # isn't there.
    list_err = _error(lambda: s3v.list_tags_for_resource(resourceArn=stale_arn))
    assert list_err["Code"] == "NotFoundException", f"expected NotFoundException listing tags on a deleted bucket, got {list_err!r}"
    assert list_err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {list_err.get('Message')!r}"
    )

    # (c) positive control: tagging a real, existing bucket succeeds and the
    # tag is actually persisted.
    live_name = ctx.unique_name("sim2real-s3v-live-")
    live_arn = s3v.create_vector_bucket(vectorBucketName=live_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=live_name))
    s3v.tag_resource(resourceArn=live_arn, tags={"k": "v"})
    live_tags = s3v.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert live_tags.get("k") == "v", f"expected tag k=v on the live bucket, got {live_tags!r}"


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until_bucket_gone(s3v, bucket_name: str, timeout_s: float = 30.0, interval_s: float = 1.5) -> None:
    """Bounded poll until GetVectorBucket reports NotFoundException; raises on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = "the bucket still exists"
    while time.monotonic() < deadline:
        try:
            s3v.get_vector_bucket(vectorBucketName=bucket_name)
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last == "NotFoundException":
                return
        time.sleep(interval_s)
    raise AssertionError(f"bucket never became NotFoundException after delete, last saw {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
