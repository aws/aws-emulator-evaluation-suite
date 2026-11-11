"""put-events-trace-header-into-archived-bus-absent-on-replay."""
from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-events-trace-header-into-archived-bus-absent-on-replay"
GROUP = "put-events"
SERVICES = ["events", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A PutEvents TraceHeader reaches the live SQS delivery as the AWSTraceHeader attribute, but
    is absent from the same event's redelivery once it is replayed from an archive.
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus_name = ctx.unique_name("sim2real-eb-bus-")
    rule_name = ctx.unique_name("sim2real-eb-rule-")
    archive_name = ctx.unique_name("sim2real-eb-arc-")
    replay_name = ctx.unique_name("sim2real-eb-replay-")
    source_name = ctx.unique_name("sim2real.archtrace.src.").replace("-", ".")
    marker = ctx.unique_name("marker-")

    tags_kv = [{"Key": "sim2real:managed", "Value": "true"}]

    bus = events.create_event_bus(Name=bus_name, Tags=tags_kv)
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-eb-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    rule_arn = events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps({"source": [source_name]}),
        State="ENABLED",
        Tags=tags_kv,
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name, EventBusName=bus_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowEventBridgeSend",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": "1", "Arn": queue_arn}],
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, EventBusName=bus_name, Ids=["1"]))

    archive_arn = events.create_archive(
        ArchiveName=archive_name,
        EventSourceArn=bus_arn,
        EventPattern=json.dumps({"source": [source_name]}),
    )["ArchiveArn"]
    ctx.on_cleanup(lambda: events.delete_archive(ArchiveName=archive_name))

    _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name)["State"],
        lambda state: state == "ENABLED",
        timeout_s=_budget_s(ctx, 60),
        interval_s=1,
        ctx=ctx,
    )

    trace = (
        f"Root=1-{int(time.time()):08x}-{secrets.token_hex(12)};"
        f"Parent={secrets.token_hex(8)};Sampled=1"
    )
    put_time = datetime.now(timezone.utc)
    resp = events.put_events(
        Entries=[
            {
                "Time": put_time,
                "Source": source_name,
                "DetailType": "sim2real-archive-trace-test",
                "Detail": json.dumps({"marker": marker}),
                "EventBusName": bus_name,
                "TraceHeader": trace,
            }
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"PutEvents rejected the traced entry: {resp!r}"

    # Direct delivery first: drain it so the later replayed copy is unambiguous.
    first = _wait_for_marker(ctx, queue_url, marker, timeout_s=_budget_s(ctx, 60))
    assert "replay-name" not in first["body"], "direct delivery must not carry a replay-name marker"
    assert first["trace_header"] == trace, (
        f"the live SQS delivery must carry AWSTraceHeader {trace!r}, got "
        f"{first['trace_header']!r}"
    )

    # Archive ingestion lags PutEvents with no documented bound; it can exceed 15 minutes.
    _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name)["EventCount"],
        lambda count: count >= 1,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=1,
        ctx=ctx,
    )

    replay_start = put_time - timedelta(minutes=15)
    replay_end = put_time + timedelta(minutes=15)
    events.start_replay(
        ReplayName=replay_name,
        EventSourceArn=archive_arn,
        EventStartTime=replay_start,
        EventEndTime=replay_end,
        Destination={"Arn": bus_arn, "FilterArns": [rule_arn]},
    )

    final_state = _poll_until(
        lambda: events.describe_replay(ReplayName=replay_name)["State"],
        lambda state: state in ("COMPLETED", "FAILED", "CANCELLED"),
        timeout_s=_budget_s(ctx, 180),
        interval_s=1,
        ctx=ctx,
    )
    assert final_state == "COMPLETED", f"replay ended in {final_state}"

    replayed = _wait_for_marker(ctx, queue_url, marker, timeout_s=_budget_s(ctx, 120))
    assert replayed["body"].get("replay-name") == replay_name, (
        f"redelivered event carries replay-name={replayed['body'].get('replay-name')!r}, "
        f"expected {replay_name!r} -- without that field it is indistinguishable from a "
        f"leftover live delivery: {replayed['body']!r}"
    )
    assert replayed["body"]["detail"]["marker"] == marker, (
        f"redelivered event's detail.marker={replayed['body']['detail'].get('marker')!r} does "
        f"not match the published marker {marker!r}: {replayed['body']!r}"
    )
    assert replayed["trace_header"] is None, (
        f"the replayed SQS delivery must not carry AWSTraceHeader, got "
        f"{replayed['trace_header']!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float,
                interval_s: float, ctx=None) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(max(0.0, min(interval_s, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _wait_for_marker(ctx, queue_url: str, marker: str, *, timeout_s: float) -> dict:
    """The first SQS message whose detail.marker matches, as {"body", "trace_header"}."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait_s = max(0, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s,
            AttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if body.get("detail", {}).get("marker") == marker:
                return {"body": body, "trace_header": msg.get("Attributes", {}).get(
                    "AWSTraceHeader")}
    if _budget_spent(ctx):
        raise TimeoutError(f"marker {marker!r} on the queue: the run budget ended first; not graded")
    raise AssertionError(f"marker {marker!r} never arrived on queue within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
