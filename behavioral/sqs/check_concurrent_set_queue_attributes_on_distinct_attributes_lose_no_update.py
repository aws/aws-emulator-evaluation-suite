"""concurrent-set-queue-attributes-on-distinct-attributes-lose-no-update."""
from __future__ import annotations

import concurrent.futures
import threading
import time

from behavioral_harness import tags

CHECK = "concurrent-set-queue-attributes-on-distinct-attributes-lose-no-update"
GROUP = "concurrency"
SERVICES = ["sqs"]

_SETTLE_S = 75.0
_TAGS = {"sim2real": "concurrent-set-queue-attributes-on-distinct-attributes-lose-no-update"}

_ROUNDS = (
    {"VisibilityTimeout": "77", "DelaySeconds": "7", "MaximumMessageSize": "200000",
     "MessageRetentionPeriod": "7777", "ReceiveMessageWaitTimeSeconds": "7"},
    {"VisibilityTimeout": "88", "DelaySeconds": "8", "MaximumMessageSize": "300000",
     "MessageRetentionPeriod": "8888", "ReceiveMessageWaitTimeSeconds": "8"},
)


def _converge(sqs, url: str, want: dict[str, str]) -> dict[str, str]:
    got: dict[str, str] = {}
    deadline = time.monotonic() + _SETTLE_S
    while time.monotonic() < deadline:
        got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=sorted(want))["Attributes"]
        if got == want:
            return got
        time.sleep(3)
    return got


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Five simultaneous SetQueueAttributes calls on distinct attributes all take effect, over two
    rounds: no concurrent write overwrites another's attribute with a stale value.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-conc-attrs-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for want in _ROUNDS:
        barrier = threading.Barrier(len(want))

        def write(item: tuple[str, str]) -> None:
            barrier.wait(timeout=30)
            sqs.set_queue_attributes(QueueUrl=url, Attributes={item[0]: item[1]})

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(want)) as ex:
            list(ex.map(write, sorted(want.items())))

        got = _converge(sqs, url, want)
        lost = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
        assert not lost, (
            f"{len(lost)} of {len(want)} concurrent single-attribute writes did not survive "
            f"(attribute: (written, read back)) {lost!r} within {_SETTLE_S}s"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
