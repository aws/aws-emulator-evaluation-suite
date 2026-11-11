"""input-transformer-unsupported-input-path-forms-rejected-and-targets-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "input-transformer-unsupported-input-path-forms-rejected-and-targets-unchanged"
GROUP = "input-transformer"
SERVICES = ["events"]

_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "plane:control")
def run(ctx) -> None:
    """PutTargets refuses InputPaths with a negative index or bracketed quoted member, naming the
    target, and a mixed request installs neither; existing delivery and an accepted `[1]` path keep
    working.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html
    """
    events = ctx.client("events")

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.paths.")
    rule = _create_rule(ctx, events, bus, {"source": [source]}).rsplit("/", 1)[1]
    queue_url, queue_arn = _create_queue(ctx)
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "raw", "Arn": queue_arn}])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    def _transformer(target_id: str, path: str) -> dict:
        return {"Id": target_id, "Arn": queue_arn, "InputTransformer": {
            "InputPathsMap": {"v": path, "m": "$.detail.m"},
            "InputTemplate": '{"m": <m>, "id": "%s", "v": <v>}' % target_id,
        }}

    # `[1]` and `a-b` are supported path forms; a negative index and `['k.k']` are not.
    for target_id, path in (("negative-index", "$.detail.items[-1]"),
                            ("bracket-member", "$.detail['k.k']")):
        code, message = _error(lambda t=target_id, p=path: events.put_targets(
            Rule=rule, EventBusName=bus, Targets=[_transformer(t, p)]))
        assert (code, message) == ("ValidationException", f"InputPath for target {target_id} is invalid."), (
            f"InputPath {path!r} must be refused with ValidationException 'InputPath for target "
            f"{target_id} is invalid.', got {code!r}: {message!r}"
        )

    code, message = _error(lambda: events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        _transformer("valid-member", "$.detail.a-b"),
        _transformer("negative-index", "$.detail.items[-1]"),
    ]))
    assert (code, message) == ("ValidationException", "InputPath for target negative-index is invalid."), (
        f"a request carrying one invalid target must be refused naming it, got {code!r}: {message!r}"
    )
    listed = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"])
    assert listed == ["raw"], (
        f"refused PutTargets calls must install nothing, not even the valid target of a mixed "
        f"request; the rule lists {listed!r}"
    )

    ok = events.put_targets(Rule=rule, EventBusName=bus, Targets=[_transformer("index", "$.detail.items[1]")])
    assert ok["FailedEntryCount"] == 0, (
        f"positive control: the supported index path was refused: {ok['FailedEntries']!r}"
    )
    listed = sorted(t["Id"] for t in events.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"])
    assert listed == ["index", "raw"], f"after the accepted PutTargets the rule lists {listed!r}"

    live = ctx.unique_name("live-")
    _publish_until_live(ctx, events, queue_url, {
        "EventBusName": bus, "Source": source, "DetailType": "live",
        "Detail": json.dumps({"m": live, "items": [0, 0]}),
    }, lambda msgs: sum(live in m["Body"] for m in msgs) >= 2)

    marker = ctx.unique_name("path-")
    resp = events.put_events(Entries=[{
        "EventBusName": bus, "Source": source, "DetailType": "paths",
        "Detail": json.dumps({"m": marker, "items": [10, 20, 30], "a-b": "dashed", "k.k": "dotted"}),
    }])
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused the event: {resp['Entries']!r}"

    def _ours(msgs: list[dict]) -> list[dict]:
        out = []
        for msg in msgs:
            body = json.loads(msg["Body"])
            if body.get("m") == marker or (isinstance(body.get("detail"), dict)
                                           and body["detail"].get("m") == marker):
                out.append(body)
        return out

    bodies = _ours(_drain(ctx, queue_url, until=lambda ms: len(_ours(ms)) >= 2,
                          timeout_s=_DELIVERY_TIMEOUT_S, description=f"event {marker} on both targets"))
    shaped = [b for b in bodies if "detail" not in b]
    raw = [b for b in bodies if "detail" in b]
    assert shaped == [{"m": marker, "id": "index", "v": 20}], (
        f"the accepted `[1]` target must render the second element and be the only transformed "
        f"delivery; got {shaped!r}"
    )
    assert len(raw) == 1 and raw[0]["detail"]["m"] == marker, (
        f"the pre-existing raw target must still deliver the event once, got {raw!r}"
    )


def _create_bus(ctx, events) -> str:
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))
    return bus


def _create_rule(ctx, events, bus: str, pattern: dict) -> str:
    """A rule whose teardown first removes whatever targets it still carries."""
    name = ctx.unique_name("sim2real-behav-rule-")
    arn = events.put_rule(
        Name=name, EventBusName=bus, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]

    def _delete() -> None:
        ids = [t["Id"] for t in events.list_targets_by_rule(Rule=name, EventBusName=bus)["Targets"]]
        if ids:
            events.remove_targets(Rule=name, EventBusName=bus, Ids=ids)
        events.delete_rule(Name=name, EventBusName=bus)

    ctx.on_cleanup(_delete)
    return arn


def _create_queue(ctx, **attributes: str) -> tuple[str, str]:
    """A queue EventBridge may send to, as (url, arn)."""
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-q-")
    url = sqs.create_queue(QueueName=name, Attributes=attributes, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"StringEquals": {"aws:SourceAccount": ctx.account}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps(policy)})
    return url, arn


def _drain(ctx, queue_url: str, *, until, timeout_s: float, description: str) -> list[dict]:
    """Receive (and delete) until ``until(messages_so_far)`` holds; raise on timeout."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5,
            AttributeNames=["All"], MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if until(seen):
            return seen
    raise AssertionError(
        f"{description}: not met within {timeout_s}s; received {len(seen)} message(s): "
        f"{[m['Body'][:300] for m in seen]!r}"
    )


def _publish_until_live(ctx, events, queue_url: str, entry: dict, arrived) -> None:
    """Re-publish ``entry`` until the queue shows it: a just-created rule can drop events until
    its routing is live. Bounded; raises naming the timeout."""
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + _LIVENESS_TIMEOUT_S
    while time.monotonic() < deadline:
        events.put_events(Entries=[entry])
        window = time.monotonic() + 15.0
        while time.monotonic() < window:
            resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
            for msg in resp.get("Messages", []):
                seen.append(msg)
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if arrived(seen):
                return
    raise AssertionError(
        f"the rule never delivered a liveness event within {_LIVENESS_TIMEOUT_S}s; "
        f"{len(seen)} other message(s) seen"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
