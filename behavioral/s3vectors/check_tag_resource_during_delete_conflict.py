"""tag-resource-during-delete-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "tag-resource-during-delete-conflict"
GROUP = "concurrency"
SERVICES = ["s3vectors"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResource racing DeleteVectorBucket never tags a vanished bucket: the delete always succeeds,
    TagResource either succeeds first or fails with NotFoundException and the exact not-found message,
    and ListTagsForResource on the deleted bucket fails with NotFoundException."""
    s3v = ctx.client("s3vectors")
    bucket_name = ctx.unique_name("sim2real-s3v-race-")
    s3v.create_vector_bucket(vectorBucketName=bucket_name)
    bucket_arn = s3v.get_vector_bucket(vectorBucketName=bucket_name)["vectorBucket"]["vectorBucketArn"]

    def _cleanup() -> None:
        outcome = _outcome(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name))
        if not outcome["succeeded"] and outcome["code"] != "NotFoundException":
            raise AssertionError(f"unexpected cleanup failure deleting race bucket: {outcome}")

    ctx.on_cleanup(_cleanup)

    barrier = threading.Barrier(2)
    tag_result: dict[str, object] = {}
    delete_result: dict[str, object] = {}

    def _do_tag() -> None:
        barrier.wait()
        tag_result.update(
            _outcome(lambda: s3v.tag_resource(resourceArn=bucket_arn, tags={"Race": "condition"}))
        )

    def _do_delete() -> None:
        barrier.wait()
        delete_result.update(_outcome(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket_name)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        f_tag = pool.submit(_do_tag)
        f_delete = pool.submit(_do_delete)
        f_tag.result(timeout=30)
        f_delete.result(timeout=30)

    # invariant 1: the delete always wins eventually -- the bucket ends up gone
    _poll_until(
        lambda: _outcome(lambda: s3v.get_vector_bucket(vectorBucketName=bucket_name)),
        lambda outcome: outcome.get("code") == "NotFoundException",
        timeout_s=30.0,
        interval_s=1.0,
        description="the raced bucket reads as NotFoundException",
    )

    # invariant 2: exactly one coherent story for the tag call -- it either happened-before
    # the delete (in which case the delete itself must have reported success, since a
    # newly-tagged-but-still-empty bucket is still deletable) or it lost the race outright
    if tag_result["succeeded"]:
        assert delete_result["succeeded"], (
            "TagResource reported success but the racing DeleteVectorBucket did not -- "
            "the tag was applied to a bucket that the delete call itself disagreed existed"
        )
    else:
        # message varies: ConflictException only appears when the tag lands mid-delete, a
        # timing window no single run can pin, so only its code is graded.
        if tag_result["code"] != "ConflictException":
            assert tag_result["code"] == "NotFoundException", (
                f"expected TagResource to lose the race with ConflictException or "
                f"NotFoundException, got {tag_result!r}"
            )
            assert tag_result["message"] == "The specified vector bucket could not be found", (
                f"expected the exact bucket not-found message, got {tag_result['message']!r}"
            )
        assert delete_result["succeeded"], (
            "TagResource was rejected as losing the race, but DeleteVectorBucket did not "
            "actually win it"
        )

    # invariant 3: no ghost tag entry survives independently of the deleted resource
    tags_err = _error(lambda: s3v.list_tags_for_resource(resourceArn=bucket_arn))
    assert tags_err["Code"] == "NotFoundException", (
        f"expected ListTagsForResource on the deleted bucket to report NotFoundException, "
        f"got {tags_err!r}"
    )
    assert tags_err.get("Message") == "The specified vector bucket could not be found", (
        f"expected the exact ListTagsForResource not-found message, got {tags_err.get('Message')!r}"
    )


def _outcome(fn) -> dict:
    """Run one side of the race: either outcome is legitimate, so success is a flag, not a code."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return {
            "succeeded": False,
            "code": err.response["Error"]["Code"],
            "message": err.response["Error"].get("Message"),
        }
    return {"succeeded": True}


def _error(fn) -> dict:
    """Call fn() and return the botocore error; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Bounded poll that raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not reached within {timeout_s}s (last: {last!r})")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
