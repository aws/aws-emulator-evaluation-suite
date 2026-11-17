"""untag-queue-after-retagging-a-present-key-removes-the-key."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-queue-after-retagging-a-present-key-removes-the-key"
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
    """Re-tagging a key the queue already carries and then untagging it removes the key outright:
    the earlier value does not come back.
    """
    sqs = ctx.client("sqs")
    created = {"sim2real": CHECK, "env": "first"}
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-uqr-"), tags=created)["QueueUrl"]
    ctx.on_cleanup(_drop_queue(sqs, url))

    got = _tags_until(ctx, sqs, url, created)
    assert got == created, f"a queue created with tags {created!r} lists {got!r}"

    sqs.tag_queue(QueueUrl=url, Tags={"env": "second"})
    replaced = {"sim2real": CHECK, "env": "second"}
    got = _tags_until(ctx, sqs, url, replaced)
    assert got == replaced, f"re-tagging env left the queue listing {got!r}, expected {replaced!r}"

    sqs.untag_queue(QueueUrl=url, TagKeys=["env"])
    rest = {"sim2real": CHECK}
    got = _tags_until(ctx, sqs, url, rest)
    assert got == rest, f"untagging the re-tagged env left {got!r}, expected {rest!r} with env gone"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
