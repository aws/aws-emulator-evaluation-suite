"""untag-queue-of-fresh-keys-restores-the-tags-listed-before."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-queue-of-fresh-keys-restores-the-tags-listed-before"
GROUP = "tagging"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"


def _wait_cap(ctx, cap_s: float) -> float:
    """cap_s, shortened when the runner stops the check sooner, keeping 5 s for the failure."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _drop_queue(sqs, url: str):
    """A cleanup deleting the queue; only the queue's own not-found code counts as already gone."""

    def undo() -> None:
        try:
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != _GONE:
                raise

    return undo


def _tags_until(ctx, sqs, url: str, want: dict) -> dict:
    """ListQueueTags repeated until it lists exactly want or the wait runs out; the last map read."""
    deadline = time.monotonic() + _wait_cap(ctx, 60.0)
    while True:
        got = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagQueue of two keys the queue did not carry, then UntagQueue of those keys, leaves
    ListQueueTags with exactly the tags it listed before, creation tags included.
    """
    sqs = ctx.client("sqs")
    created = {"sim2real": CHECK, "owner": "lab"}
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-uqf-"), tags=created)["QueueUrl"]
    ctx.on_cleanup(_drop_queue(sqs, url))

    before = _tags_until(ctx, sqs, url, created)
    assert before == created, f"a queue created with tags {created!r} lists {before!r}"

    fresh = {"extra-a": "one", "extra-b": "two"}
    sqs.tag_queue(QueueUrl=url, Tags=fresh)
    tagged = {**before, **fresh}
    got = _tags_until(ctx, sqs, url, tagged)
    assert got == tagged, f"after tagging {sorted(fresh)!r} the queue lists {got!r}, expected {tagged!r}"

    sqs.untag_queue(QueueUrl=url, TagKeys=sorted(fresh))
    got = _tags_until(ctx, sqs, url, before)
    assert got == before, f"untagging {sorted(fresh)!r} left {got!r}, expected the earlier set {before!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
