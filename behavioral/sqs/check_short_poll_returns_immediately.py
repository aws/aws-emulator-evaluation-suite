"""short-poll-returns-immediately."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "short-poll-returns-immediately"
GROUP = 'state'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "short-poll-returns-immediately"}

@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ReceiveMessage(WaitTimeSeconds=0) on an empty queue returns promptly (<1s).

    Guards the opposite failure mode from long-poll: an emulator that always
    blocks (or sleeps a fixed amount) regardless of WaitTimeSeconds.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    start = time.monotonic()
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=0)
    elapsed = time.monotonic() - start
    messages = resp.get("Messages", [])
    if messages:
        raise AssertionError(f"expected empty receive on an empty queue, got {len(messages)} message(s)")
    # elapsed-bound: a short poll (WaitTimeSeconds=0) does not wait; returning promptly is the claim.
    if elapsed > 1.0:
        raise AssertionError(f"short poll (WaitTimeSeconds=0) took {elapsed:.3f}s; expected <1s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
