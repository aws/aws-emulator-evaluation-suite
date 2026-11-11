"""concurrent-receive-no-duplicate-delivery."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-receive-no-duplicate-delivery"
GROUP = 'concurrency'
SERVICES = ['sqs']


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _poll(fn, pred, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent ReceiveMessage calls on a FIFO queue (exactly-once processing) never hand out
    the same in-flight message to more than one caller."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"VisibilityTimeout": "60", "FifoQueue": "true"},
        tags={"sim2real-check": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    n = 20
    for i in range(n):
        # One message group per message, so every message is receivable concurrently.
        sqs.send_message(QueueUrl=url, MessageBody=f"m{i}", MessageGroupId=f"g{i}", MessageDeduplicationId=f"d{i}")

    # ApproximateNumberOfMessages is eventually consistent on real AWS; let it settle first.
    _poll(
        lambda: int(
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"])[
                "Attributes"
            ].get("ApproximateNumberOfMessages", "0")
        ),
        lambda c: c >= n,
        timeout_s=30,
        interval_s=2,
    )

    def receiver():
        return sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
            "Messages", []
        )

    results = _run_concurrent([receiver for _ in range(6)], timeout_s=90)
    errs = _concurrent_error_codes(results)
    assert not errs, f"concurrent receives raised: {errs}"

    all_msgs = [m for batch in results if not isinstance(batch, BaseException) for m in batch]
    ids = [m["MessageId"] for m in all_msgs]

    assert len(ids) == len(set(ids)), "the same message was concurrently delivered to more than one receiver"
    assert len(ids) <= n, f"received more messages ({len(ids)}) than were sent ({n})"
    assert len(ids) > 0, "no messages were delivered at all"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
