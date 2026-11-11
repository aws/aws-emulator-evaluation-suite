"""concurrent-set-queue-attributes-last-writer-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-set-queue-attributes-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["sqs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent SetQueueAttributes on VisibilityTimeout converges to one of the submitted values.

    All five calls complete, and the value read back is exactly one of them, as an integer string.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-cset-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    candidate_values = [str(v) for v in (11, 22, 33, 44, 55)]

    def _set(value):
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"VisibilityTimeout": value})
        return value

    with ThreadPoolExecutor(max_workers=len(candidate_values)) as pool:
        results = list(pool.map(_set, candidate_values))
    assert len(results) == len(candidate_values), (
        f"expected all {len(candidate_values)} concurrent SetQueueAttributes calls to "
        f"complete, got {len(results)} results: {results!r}"
    )

    final = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])[
        "Attributes"
    ]["VisibilityTimeout"]

    assert final in candidate_values, (
        f"final VisibilityTimeout {final!r} is not one of the racing writers' values "
        f"{candidate_values} -- indicates a corrupted/partial merge"
    )
    assert final.isdigit(), f"final VisibilityTimeout {final!r} is not a clean integer string"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
