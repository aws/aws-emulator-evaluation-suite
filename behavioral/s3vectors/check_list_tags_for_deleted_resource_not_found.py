"""list-tags-for-deleted-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-deleted-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["s3vectors"]

MSG_BUCKET_NOT_FOUND = "The specified vector bucket could not be found"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a vector bucket ARN removed via DeleteVectorBucket returns
    NotFoundException rather than an empty tag set, while the same call on a live tagged
    bucket (positive control) still returns the tags."""
    s3v = ctx.client("s3vectors")

    gone_name = ctx.unique_name("sim2real-s3v-gone-")
    s3v.create_vector_bucket(vectorBucketName=gone_name)
    ctx.on_cleanup(lambda: _delete_if_present(s3v, gone_name))
    gone_arn = s3v.get_vector_bucket(vectorBucketName=gone_name)["vectorBucket"]["vectorBucketArn"]
    s3v.tag_resource(resourceArn=gone_arn, tags={"Stage": "prod"})
    s3v.delete_vector_bucket(vectorBucketName=gone_name)

    code, code_msg = _error(lambda: s3v.list_tags_for_resource(resourceArn=gone_arn))
    assert code == "NotFoundException", (
        f"expected NotFoundException reading tags for a deleted vector bucket, got {code!r}"
    )
    assert code_msg == MSG_BUCKET_NOT_FOUND, f"unexpected {code!r} message {code_msg!r}"

    # a mutation on the same dead id also fails, not just the read: gone means unusable
    tag_code, tag_code_msg = _error(lambda: s3v.tag_resource(resourceArn=gone_arn, tags={"Retry": "1"}))
    assert tag_code == "NotFoundException", (
        f"expected NotFoundException tagging a deleted vector bucket, got {tag_code!r}"
    )
    assert tag_code_msg == MSG_BUCKET_NOT_FOUND, f"unexpected {tag_code!r} message {tag_code_msg!r}"

    # positive control in the same file: a live, tagged bucket still returns its tags
    live_name = ctx.unique_name("sim2real-s3v-live-")
    s3v.create_vector_bucket(vectorBucketName=live_name)
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=live_name))
    live_arn = s3v.get_vector_bucket(vectorBucketName=live_name)["vectorBucket"]["vectorBucketArn"]
    s3v.tag_resource(resourceArn=live_arn, tags={"Stage": "prod"})
    tags = s3v.list_tags_for_resource(resourceArn=live_arn)["tags"]
    assert tags.get("Stage") == "prod", f"expected live bucket tags to include Stage=prod, got {tags!r}"


def _delete_if_present(s3v, name: str) -> None:
    """Teardown for a bucket the check itself deletes: a second delete may find it gone."""
    from botocore.exceptions import ClientError

    try:
        s3v.delete_vector_bucket(vectorBucketName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
