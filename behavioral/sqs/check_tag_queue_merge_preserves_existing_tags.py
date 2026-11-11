"""tag-queue-merge-preserves-existing-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-queue-merge-preserves-existing-tags"
GROUP = "state"
SERVICES = ["sqs"]


def _poll_tags(sqs, url, want):
    """ListQueueTags can lag a preceding write; poll up to 10s for it to
    settle, returning whatever was last observed so the caller's own assert
    still names expected vs actual."""
    deadline = time.monotonic() + 10
    seen = {}
    while time.monotonic() < deadline:
        seen = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if seen == want:
            break
        time.sleep(0.5)
    return seen


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagQueue merges into the existing tag set (unspecified keys are preserved,
    specified keys are overwritten/added); UntagQueue removes only the named keys."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-sqs-tags-"),
        tags={"env": "test", "team": "alpha"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    initial = _poll_tags(sqs, url, {"env": "test", "team": "alpha"})
    assert initial == {"env": "test", "team": "alpha"}, initial

    sqs.tag_queue(QueueUrl=url, Tags={"team": "beta", "extra": "x"})
    merged = _poll_tags(sqs, url, {"env": "test", "team": "beta", "extra": "x"})
    assert merged == {"env": "test", "team": "beta", "extra": "x"}, merged

    sqs.untag_queue(QueueUrl=url, TagKeys=["extra"])
    after_untag = _poll_tags(sqs, url, {"env": "test", "team": "beta"})
    assert after_untag == {"env": "test", "team": "beta"}, after_untag


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
