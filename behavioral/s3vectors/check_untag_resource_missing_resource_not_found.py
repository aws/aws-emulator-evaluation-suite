"""untag-resource-missing-resource-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "untag-resource-missing-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource against a vector bucket ARN that was already deleted returns
    NotFoundException rather than a silent no-op, while untagging a live resource
    (positive control) still works."""
    s3v = ctx.client("s3vectors")

    gone_name = ctx.unique_name("sim2real-s3v-gone-")
    s3v.create_vector_bucket(vectorBucketName=gone_name)
    gone_arn = s3v.get_vector_bucket(vectorBucketName=gone_name)["vectorBucket"]["vectorBucketArn"]
    s3v.tag_resource(resourceArn=gone_arn, tags={"Team": "ephemeral"})
    s3v.delete_vector_bucket(vectorBucketName=gone_name)
    _poll_until_bucket_gone(s3v, gone_name)

    err = _error(lambda: s3v.untag_resource(resourceArn=gone_arn, tagKeys=["Team"]))
    assert err["Code"] == "NotFoundException", f"expected NotFoundException untagging a deleted bucket, got {err!r}"
    assert err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {err.get('Message')!r}"
    )

    # the resource is genuinely gone, not just missing the one tag key
    list_err = _error(lambda: s3v.list_tags_for_resource(resourceArn=gone_arn))
    assert list_err["Code"] == "NotFoundException", f"expected NotFoundException listing tags on a deleted bucket, got {list_err!r}"
    assert list_err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact bucket not-found message, got {list_err.get('Message')!r}"
    )

    # positive control in the same file: untagging a live, tagged bucket succeeds and the
    # tag is actually removed
    live_name = ctx.unique_name("sim2real-s3v-live-")
    s3v.create_vector_bucket(vectorBucketName=live_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=live_name))
    live_arn = s3v.get_vector_bucket(vectorBucketName=live_name)["vectorBucket"]["vectorBucketArn"]
    s3v.tag_resource(resourceArn=live_arn, tags={"Team": "live"})
    tags_before = s3v.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert tags_before.get("Team") == "live", f"expected tag Team=live before untagging, got {tags_before!r}"
    s3v.untag_resource(resourceArn=live_arn, tagKeys=["Team"])
    tags_after = s3v.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert "Team" not in tags_after, f"expected Team tag removed, still present in {tags_after!r}"


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
