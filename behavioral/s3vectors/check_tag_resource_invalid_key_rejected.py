"""tag-resource-invalid-key-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-invalid-key-rejected"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a reserved 'aws:' prefixed tag key with ValidationException
    instead of silently accepting it, and a normal tag key still works (positive control)."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
    bucket_arn = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    err = _error(lambda: s3v.tag_resource(resourceArn=bucket_arn, tags={"aws:Reserved": "x"}))
    assert err["Code"] == "ValidationException", f"expected ValidationException for reserved key, got {err!r}"
    assert err.get("Message") == "System tags cannot be added/updated by requester", (
        f"expected the exact reserved-key message, got {err.get('Message')!r}"
    )

    # effect absent: the reserved key was never stored
    tags = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert "aws:Reserved" not in tags, f"reserved key must not be stored, saw tags={tags!r}"

    # positive control in the same file: an ordinary tag key/value is accepted and visible
    s3v.tag_resource(resourceArn=bucket_arn, tags={"Environment": "test"})
    tags_after = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_after.get("Environment") == "test", f"expected Environment=test, got {tags_after!r}"


def _error(fn) -> dict:
    """Call fn() and return the botocore error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
