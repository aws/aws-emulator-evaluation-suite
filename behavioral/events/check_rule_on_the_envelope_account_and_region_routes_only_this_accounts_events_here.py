"""rule-on-the-envelope-account-and-region-routes-only-this-accounts-events-here."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rule-on-the-envelope-account-and-region-routes-only-this-accounts-events-here"
GROUP = "telemetry"
SERVICES = ["events"]

DETAIL_TYPE = "sim2real-envelope-route"


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule matching the envelope's account and region delivers each of this account's events with
    those fields, while rules matching anything but this account, or anything but this region,
    deliver none, graded after a source-only twin receives a fence entry sent last.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
    """
    events = ctx.client("events")
    source = ctx.unique_name("sim2real.envelope.")
    patterns = {
        "here": {"source": [source], "account": [ctx.account], "region": [ctx.region]},
        "other-account": {"source": [source], "account": [{"anything-but": ctx.account}]},
        "other-region": {"source": [source], "region": [{"anything-but": ctx.region}]},
        "twin": {"source": [source]},
    }
    queues = {}
    for key, pattern in patterns.items():
        rule_name = ctx.unique_name(f"sim2real-evb-{key}-")
        rule_arn = events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps(pattern),
            State="ENABLED",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["RuleArn"]
        ctx.on_cleanup(lambda n=rule_name: _ignore_not_found(lambda: events.delete_rule(Name=n)))
        url, arn = _create_queue_with_eventbridge_policy(ctx, rule_arn)
        resp = events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": arn}])
        assert resp["FailedEntryCount"] == 0, f"put_targets failed: {resp}"
        ctx.on_cleanup(
            lambda n=rule_name: _ignore_not_found(
                lambda: events.remove_targets(Rule=n, Ids=["sim2real-target"])
            )
        )
        queues[key] = url

    # Positive control: re-emitted until the rule under test and the twin both deliver it.
    warm = _warm_up(ctx, events, source, {queues["here"], queues["twin"]})

    graded = [ctx.unique_name("m-a-"), ctx.unique_name("m-b-")]
    resp = events.put_events(
        Entries=[
            {"Source": source, "DetailType": DETAIL_TYPE, "Detail": json.dumps({"marker": m})}
            for m in graded
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"put_events rejected an entry: {resp}"
    ids = dict(zip(graded, (e["EventId"] for e in resp["Entries"]), strict=True))
    fence = ctx.unique_name("fence-")
    resp = events.put_events(
        Entries=[
            {"Source": source, "DetailType": DETAIL_TYPE, "Detail": json.dumps({"marker": fence})}
        ]
    )
    assert resp["FailedEntryCount"] == 0, f"put_events rejected the fence: {resp}"

    _collect(ctx, queues["twin"], {*graded, fence}, timeout_s=40.0)
    here = _collect(ctx, queues["here"], {*graded, fence}, timeout_s=40.0)
    here.pop(warm, None)
    assert sorted(here) == sorted([*graded, fence]), (
        f"the account-and-region rule delivered {sorted(here)}"
    )
    for m in graded:
        env = here[m]
        got = (env["id"], env["account"], env["region"], env["source"])
        assert got == (ids[m], ctx.account, ctx.region, source), (
            f"entry {m} arrived as (id, account, region, source) {got!r}"
        )
    for key in ("other-account", "other-region"):
        stray = _drain(ctx, queues[key])
        assert not stray, (
            f"the {key} rule delivered {sorted(str(m) for m in stray)}, expected nothing"
        )


def _warm_up(ctx, events, source: str, queue_urls: set, timeout_s: float = 40.0) -> str:
    """Re-emit one event until each queue in ``queue_urls`` received it; return its marker."""
    warm = ctx.unique_name("warm-")
    entry = {"Source": source, "DetailType": DETAIL_TYPE, "Detail": json.dumps({"marker": warm})}
    sqs = ctx.client("sqs")
    pending = set(queue_urls)
    last: dict = {}
    deadline = time.monotonic() + timeout_s
    while pending:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{len(pending)} rule queue(s) never received the warm-up within {timeout_s}s; "
                f"last markers per pending queue {[last.get(u) for u in pending]!r}"
            )
        resp = events.put_events(Entries=[entry])
        assert resp["FailedEntryCount"] == 0, f"put_events rejected the warm-up: {resp}"
        for url in list(pending):
            msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
                "Messages", []
            )
            for msg in msgs:
                sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            last[url] = [_marker_of(json.loads(m["Body"])) for m in msgs]
            if warm in last[url]:
                pending.discard(url)
    return warm


def _marker_of(body: dict):
    return body["detail"].get("marker") if isinstance(body.get("detail"), dict) else None


def _collect(ctx, queue_url: str, wanted: set, timeout_s: float) -> dict:
    """Drain until every marker in `wanted` has arrived; return marker -> envelope of all drained."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and not wanted <= set(seen):
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            seen[_marker_of(body)] = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    assert wanted <= set(seen), (
        f"queue received {sorted(m for m in seen if m)} within {timeout_s}s, expected {sorted(wanted)}"
    )
    return seen


def _drain(ctx, queue_url: str) -> dict:
    """Receive until one empty long poll; return marker -> envelope of every message drained."""
    sqs = ctx.client("sqs")
    seen: dict = {}
    while True:
        msgs = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", [])
        if not msgs:
            return seen
        for msg in msgs:
            body = json.loads(msg["Body"])
            seen[_marker_of(body)] = body
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])


def _create_queue_with_eventbridge_policy(ctx, rule_arn: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-evb-queue-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
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


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
