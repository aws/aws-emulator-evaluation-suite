"""tag-resource-conflict-under-concurrent-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-conflict-under-concurrent-updates"
GROUP = "concurrency"
SERVICES = ["s3vectors"]

_CONFLICT_MESSAGE = "The resource tags were modified by another request. Please retry the operation."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource/UntagResource calls on one vector bucket: a refused call gets only
    ConflictException with its exact message, and the final tags hold exactly the keys of the
    accepted TagResource calls, without the seed keys once any UntagResource was accepted."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3vec-")
    bucket_arn = s3v.create_vector_bucket(vectorBucketName=bucket_name)["vectorBucketArn"]
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))

    # Seed tags for the UntagResource racers; TagResource racers add disjoint keys, so the final
    # set does not depend on the order the service applies the calls in.
    seed = {"seed-a": "1", "seed-b": "1"}
    s3v.tag_resource(resourceArn=bucket_arn, tags=seed)

    def _racer(i: int) -> Optional[tuple[str, str | None]]:
        try:
            if i % 2 == 0:
                s3v.tag_resource(resourceArn=bucket_arn, tags={f"race-{i}": "v"})
            else:
                s3v.untag_resource(resourceArn=bucket_arn, tagKeys=list(seed))
            return None
        except ClientError as exc:
            return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=12) as pool:
        errors = list(pool.map(_racer, range(12)))

    refused = [error for error in errors if error is not None]
    # Overlapping mutations may conflict; serialized ones are all accepted.
    assert all(error == ("ConflictException", _CONFLICT_MESSAGE) for error in refused), (
        f"a refused tag mutation must get ConflictException with its exact message, got {refused}"
    )
    tagged = {f"race-{i}" for i in range(0, 12, 2) if errors[i] is None}
    untagged = any(errors[i] is None for i in range(1, 12, 2))
    expected = {key: "v" for key in tagged} | ({} if untagged else seed)
    tags_after = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_after == expected, f"expected tags {expected!r} after the concurrent mutations, got {tags_after!r}"

    # Positive control: the resource is still fully functional for tagging after the storm.
    s3v.tag_resource(resourceArn=bucket_arn, tags={"post-storm": "ok"})
    tags_after = s3v.list_tags_for_resource(resourceArn=bucket_arn)["tags"]
    assert tags_after.get("post-storm") == "ok", (
        f"expected post-storm tag to be applied and visible via an independent read, "
        f"got tags={tags_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
