"""concurrent-put-events-unique-event-ids."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-events-unique-event-ids"
GROUP = 'put-events'
SERVICES = ['events']


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """N concurrent PutEvents calls are all accepted with distinct EventIds, and every one of the N
    events arrives at the rule's SQS target: no lost accepts, collisions or dropped deliveries."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    source = ctx.unique_name("sim2real.behav.source.")
    detail_type = "ConcurrencyCheck"
    n = 10

    rule_name = ctx.unique_name("sim2real-evb-rule-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [source], "detail-type": [detail_type]}),
        State="ENABLED",
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    queue_url, queue_arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)

    events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-target"]))

    # A freshly created rule/target drops events until the path goes live and EventBridge never
    # retries a dropped event, so the path must be proven live before the concurrent burst -- a
    # shortfall measured against a cold path is indistinguishable from warm-up.
    _settle_delivery_path(ctx, source, detail_type, queue_url, consecutive=3)

    def send(marker):
        return ctx.client("events").put_events(
            Entries=[
                {
                    "Source": source,
                    "DetailType": detail_type,
                    "Detail": json.dumps({"marker": marker}),
                }
            ]
        )

    markers = [ctx.unique_name(f"marker-{i}-") for i in range(n)]
    results = _run_concurrent([lambda m=m: send(m) for m in markers], timeout_s=90)

    n_ok = _concurrent_successes(results)
    assert n_ok == n, (
        f"expected all {n} PutEvents calls to succeed, got {n_ok}; "
        f"errors={_concurrent_error_codes(results)}"
    )

    event_ids = set()
    for resp in results:
        assert resp.get("FailedEntryCount", 0) == 0, f"unexpected per-entry failure: {resp}"
        event_ids.add(resp["Entries"][0]["EventId"])
    assert len(event_ids) == n, f"EventIds must be unique per accepted event, got {event_ids}"

    # PutEvents' response is not proof of delivery, so drain the target queue.
    published = set(markers)
    delivered: set[str] = set()
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline and delivered < published:
        for msg in _drain(sqs, queue_url, window_s=10.0):
            body = _body(msg)
            if isinstance(body, dict) and isinstance(body.get("detail"), dict):
                marker = body["detail"].get("marker")
                if marker in published:
                    delivered.add(marker)

    missing = sorted(published - delivered)
    assert missing == [], (
        f"rule {rule_name} lost {len(missing)} of {n} concurrently published events; "
        f"missing markers {missing!r}"
    )


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-evb-queue-")
    queue_url = sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    return queue_url, queue_arn


def _body(msg: dict):
    raw = msg.get("Body", "")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _drain(sqs, queue_url: str, *, window_s: float) -> list:
    """Long-poll the queue for up to window_s and return every message seen, deleting each."""
    seen = []
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        wait = min(5, max(1, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        msgs = resp.get("Messages", [])
        if not msgs:
            break
        for msg in msgs:
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _settle_delivery_path(ctx, source: str, detail_type: str, queue_url: str, *, consecutive: int) -> None:
    """Emit single control events until `consecutive` of them round-trip back to back.

    A rule and its target become effective progressively on real EventBridge, and a dropped event is
    never retried, so one arrival proves only that SOME path is live. Requiring several consecutive
    round trips is the barrier that makes a later shortfall attributable to loss rather than warm-up.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    streak = 0
    for _ in range(15):
        nonce = ctx.unique_name("ctl-")
        events.put_events(
            Entries=[{"Source": source, "DetailType": detail_type, "Detail": json.dumps({"marker": nonce})}]
        )
        got = False
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline and not got:
            for msg in _drain(sqs, queue_url, window_s=min(5.0, deadline - time.monotonic())):
                body = _body(msg)
                if isinstance(body, dict) and isinstance(body.get("detail"), dict) and body["detail"].get("marker") == nonce:
                    got = True
        streak = streak + 1 if got else 0
        if streak >= consecutive:
            return
    raise AssertionError(
        f"the rule -> {queue_url} delivery path never round-tripped {consecutive} consecutive "
        f"control events (longest streak reached: {streak})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
