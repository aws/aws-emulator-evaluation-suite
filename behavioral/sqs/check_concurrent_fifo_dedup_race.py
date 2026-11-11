"""concurrent-fifo-dedup-race."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-fifo-dedup-race"
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


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _receive_messages(sqs, url, *, min_count, max_batch=10, attempts=15):
    received = []
    _seen = set()
    _idle = 0
    for _ in range(attempts):
        _resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_batch, WaitTimeSeconds=1)
        _msgs = _resp.get("Messages", [])
        if not _msgs:
            _idle += 1
            if received and _idle >= 3:
                break
            continue
        _idle = 0
        for _m in _msgs:
            if _m["MessageId"] not in _seen:
                _seen.add(_m["MessageId"])
                received.append(_m)
        if len(received) >= min_count:
            break
    return received


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """N racing SendMessage calls sharing a MessageDeduplicationId collapse to exactly one delivered message."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + ".fifo",
        Attributes={"FifoQueue": "true"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    dedup_id = "race-dedup-1"
    group = "race-group"
    body = "race-body"
    n = 6

    def racer():
        return sqs.send_message(
            QueueUrl=url, MessageBody=body, MessageGroupId=group, MessageDeduplicationId=dedup_id
        )

    results = _run_concurrent([racer for _ in range(n)], timeout_s=90)
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == n, f"racing sends raised: {codes}"

    message_ids = {r["MessageId"] for r in results if not isinstance(r, BaseException)}
    assert len(message_ids) == 1, f"dedup id produced {len(message_ids)} distinct message ids"

    received = _receive_messages(sqs, url, min_count=1, attempts=20)
    assert len(received) == 1, f"expected exactly 1 deduplicated message, got {len(received)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
