"""tag-queue-roundtrip."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "tag-queue-roundtrip"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagQueue / ListQueueTags / UntagQueue round-trip.

    Tag reads can lag the write; poll before asserting.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    token = uuid.uuid4().hex[:8]
    sqs.tag_queue(QueueUrl=url, Tags={"env": f"test-{token}", "team": "sim2real"})
    tags_now: dict = {}
    for _ in range(10):
        tags_now = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if tags_now.get("env") == f"test-{token}" and tags_now.get("team") == "sim2real":
            break
        time.sleep(0.5)
    else:
        raise AssertionError(f"tags did not round-trip: {tags_now!r}")
    sqs.untag_queue(QueueUrl=url, TagKeys=["team"])
    for _ in range(10):
        tags2 = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
        if "team" not in tags2 and tags2.get("env") == f"test-{token}":
            return
        time.sleep(0.5)
    raise AssertionError(f"untag did not remove only 'team': {tags2!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
