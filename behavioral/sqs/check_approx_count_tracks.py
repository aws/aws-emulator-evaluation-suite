"""approx-count-tracks."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "approx-count-tracks"
GROUP = 'state'
SERVICES = ['sqs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ApproximateNumberOfMessages eventually reflects sent messages.

    LENIENT: eventually consistent on real AWS. Best-effort bounded poll.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    for i in range(2):
        sqs.send_message(QueueUrl=url, MessageBody=f"count-{i}")
    count = -1
    for _ in range(15):
        attrs = sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]
        count = int(attrs["ApproximateNumberOfMessages"])
        if count == 2:
            return
        if count > 2:
            raise AssertionError(f"ApproximateNumberOfMessages overcounted: sent 2, saw {count}")
        time.sleep(0.4)
    raise AssertionError(f"ApproximateNumberOfMessages never reached 2 (last={count})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
