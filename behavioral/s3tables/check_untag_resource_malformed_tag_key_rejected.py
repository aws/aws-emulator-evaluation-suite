"""untag-resource-malformed-tag-key-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-malformed-tag-key-rejected"
GROUP = "error-semantics"
SERVICES = ["s3tables"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with a 200-character tag key (the limit is 128) is ValidationException with the exact
    length-constraint message and leaves the existing tag in place, while untagging that well-formed key
    removes it."""
    s3t = ctx.client("s3tables")
    arn = _create_table_bucket(ctx)
    s3t.tag_resource(resourceArn=arn, tags={"env": "sim2real"})

    malformed_key = "k" * 200  # exceeds the documented 128-character max length for a tag key
    code, message = _error(lambda: s3t.untag_resource(resourceArn=arn, tagKeys=[malformed_key]))
    assert code == "ValidationException", f"expected ValidationException for over-length tag key, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must have length less than or equal to 128, "
        "Member must have length greater than or equal to 1]"
    ), message

    # Effect absent: the real tag that was already applied is untouched by the rejected call.
    tags = s3t.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags.get("env") == "sim2real"

    # Positive control: untagging the real, well-formed key succeeds and actually removes it.
    s3t.untag_resource(resourceArn=arn, tagKeys=["env"])
    tags_after = s3t.list_tags_for_resource(resourceArn=arn)["tags"]
    assert "env" not in tags_after


def _ignore_not_found(fn) -> None:
    """Run a teardown call; NotFoundException (already gone) is the only refusal it accepts."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn() expecting a refusal; return (code, message). An unexpected
    success raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_create_table_bucket(s3t, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return s3t.create_table_bucket(name=name)["arn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "BadRequestException" and "more buckets than are allowed" in err.get(
                "Message", ""
            ):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(interval_s)
                continue
            raise


def _create_table_bucket(ctx) -> str:
    s3t = ctx.client("s3tables")
    arn = _retry_create_table_bucket(s3t, ctx.unique_name("sim2real-s3t-bkt-"))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3t.delete_table_bucket(tableBucketARN=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
