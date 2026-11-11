"""concurrent-tag-queue-no-lost-updates."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-queue-no-lost-updates"
GROUP = "concurrency"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagQueue merges tags rather than replacing the whole tag set. Firing concurrent
    TagQueue calls that each add a disjoint tag key must all persist -- ListQueueTags
    afterward shows every key with no lost updates."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-ctag-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    tag_pairs = {f"racer-{i}": f"value-{i}" for i in range(8)}

    def _tag(item):
        key, value = item
        sqs.tag_queue(QueueUrl=url, Tags={key: value})
        return key

    with ThreadPoolExecutor(max_workers=len(tag_pairs)) as pool:
        done_keys = list(pool.map(_tag, tag_pairs.items()))
    assert set(done_keys) == set(tag_pairs.keys()), (
        f"expected TagQueue to complete for every key {sorted(tag_pairs.keys())}, "
        f"got {sorted(done_keys)}"
    )

    final_tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    for key, value in tag_pairs.items():
        assert key in final_tags, f"tag {key!r} lost under concurrent TagQueue calls"
        assert final_tags[key] == value, f"tag {key!r} has wrong value {final_tags[key]!r}"
    assert len(final_tags) == len(tag_pairs), (
        f"expected exactly {len(tag_pairs)} tags, found {len(final_tags)}: {final_tags}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
