"""input-transformer-plain-text-template-does-not-escape-strings-and-dead-letters-invalid-json."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "input-transformer-plain-text-template-does-not-escape-strings-and-dead-letters-invalid-json"
GROUP = "input-transformer"
SERVICES = ["events"]

_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 120.0

_TRICKY = {
    "quote": 'say "hi"',
    "newline": "line1\nline2\tend",
    "backslash": "a\\z",
    "unicode": "café ☃",
    "markup": "<a>&'",
}


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A JSON InputTemplate escapes the strings it splices so they reach the target intact; a
    plain-text template splices them raw, so a quote or newline renders invalid JSON that is
    dead-lettered with ERROR_CODE=INVALID_JSON until the target is re-put with a JSON template."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.escape.")
    rule_arn = _create_rule(ctx, events, bus, {"source": [source]})
    rule = rule_arn.rsplit("/", 1)[1]
    good_url, good_arn = _create_queue(ctx)
    broken_url, broken_arn = _create_queue(ctx)
    dlq_url, dlq_arn = _create_queue(ctx)

    paths = {k: f"$.detail.{k}" for k in _TRICKY}
    paths["m"] = "$.detail.m"
    json_template = (
        '{"m": <m>, "quote": <quote>, "newline": <newline>, "backslash": <backslash>, '
        '"unicode": <unicode>, "markup": <markup>, "quoteText": "q=<quote>", '
        '"newlineText": "n=<newline>"}'
    )
    failure = {"DeadLetterConfig": {"Arn": dlq_arn}, "RetryPolicy": {"MaximumRetryAttempts": 0}}
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "raw", "Arn": good_arn},
        {"Id": "json", "Arn": good_arn,
         "InputTransformer": {"InputPathsMap": paths, "InputTemplate": json_template}},
        {"Id": "text-quote", "Arn": broken_arn, **failure, "InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m", "v": "$.detail.quote"},
            "InputTemplate": '"<m> q=<v>"'}},
        {"Id": "text-newline", "Arn": broken_arn, **failure, "InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m", "v": "$.detail.newline"},
            "InputTemplate": '"<m> n=<v>"'}},
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    live = ctx.unique_name("live-")
    _publish_until_live(ctx, events, good_url, {
        "EventBusName": bus, "Source": source, "DetailType": "live",
        "Detail": json.dumps({"m": live, "quote": "", "newline": "", "backslash": "",
                              "unicode": "", "markup": ""}),
    }, lambda msgs: any(live in m["Body"] for m in msgs))
    _purge_until_empty(ctx, broken_url)

    marker = ctx.unique_name("esc-")
    resp = events.put_events(Entries=[{
        "EventBusName": bus, "Source": source, "DetailType": "escape",
        "Detail": json.dumps({**_TRICKY, "m": marker}),
    }])
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused the event: {resp['Entries']!r}"

    def _good(msgs: list[dict]) -> dict[str, dict]:
        out = {}
        for msg in msgs:
            body = json.loads(msg["Body"])
            if body.get("m") == marker:
                out["json"] = body
            elif isinstance(body.get("detail"), dict) and body["detail"].get("m") == marker:
                out["raw"] = body
        return out

    good = _good(_drain(ctx, good_url, until=lambda ms: len(_good(ms)) == 2,
                        timeout_s=_DELIVERY_TIMEOUT_S, description="the JSON and raw targets"))
    assert good["raw"]["detail"] == {**_TRICKY, "m": marker}, (
        f"control: the raw target received detail {good['raw']['detail']!r}"
    )
    expected = {**_TRICKY, "m": marker, "quoteText": f"q={_TRICKY['quote']}",
                "newlineText": f"n={_TRICKY['newline']}"}
    assert good["json"] == expected, (
        f"the JSON template must escape every spliced string so the body parses back to the "
        f"source values: expected {expected!r}, got {good['json']!r}"
    )

    def _ours(msgs: list[dict]) -> list[dict]:
        return [m for m in msgs if marker in m["Body"]]

    letters = _ours(_drain(ctx, dlq_url, until=lambda ms: len(_ours(ms)) >= 2,
                           timeout_s=_DELIVERY_TIMEOUT_S,
                           description="both plain-text targets dead-lettering the event"))
    bodies = sorted(m["Body"] for m in letters)
    assert bodies == sorted([f'"{marker} n={_TRICKY["newline"]}"', f'"{marker} q={_TRICKY["quote"]}"']), (
        f"the dead letters must hold the rendered, unescaped plain-text bodies; got {bodies!r}"
    )
    for msg in letters:
        attrs = {k: v.get("StringValue") for k, v in msg.get("MessageAttributes", {}).items()}
        assert attrs.get("ERROR_CODE") == "INVALID_JSON", f"dead letter attributes: {attrs!r}"
        assert attrs.get("ERROR_MESSAGE") == "Invalid input for target.", (
            f"dead letter ERROR_MESSAGE was {attrs.get('ERROR_MESSAGE')!r}"
        )
        assert (attrs.get("RULE_ARN"), attrs.get("TARGET_ARN")) == (rule_arn, broken_arn), (
            f"the dead letter names rule {attrs.get('RULE_ARN')!r} / target "
            f"{attrs.get('TARGET_ARN')!r}, expected {rule_arn!r} / {broken_arn!r}"
        )

    leaked = _ours(_receive_for(ctx, broken_url, 10.0))
    assert leaked == [], (
        f"the plain-text targets rendered invalid JSON, yet their queue received "
        f"{[m['Body'] for m in leaked]!r}"
    )

    # Repair the one broken thing: the same target Id, now with a JSON template.
    repaired = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "text-quote", "Arn": broken_arn, **failure, "InputTransformer": {
            "InputPathsMap": {"m": "$.detail.m", "v": "$.detail.quote"},
            "InputTemplate": '{"m": <m>, "q": <v>}'}},
    ])
    assert repaired["FailedEntryCount"] == 0, f"PutTargets failed: {repaired['FailedEntries']!r}"
    fixed = ctx.unique_name("fix-")
    _publish_until_live(ctx, events, broken_url, {
        "EventBusName": bus, "Source": source, "DetailType": "escape",
        "Detail": json.dumps({**_TRICKY, "m": fixed}),
    }, lambda msgs: any(_is_json(m["Body"]) and json.loads(m["Body"]).get("m") == fixed
                        for m in msgs))


def _is_json(text: str) -> bool:
    try:
        json.loads(text)
    except ValueError:
        return False
    return True


def _receive_for(ctx, queue_url: str, seconds: float) -> list[dict]:
    sqs = ctx.client("sqs")
    seen: list[dict] = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            seen.append(msg)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return seen


def _purge_until_empty(ctx, queue_url: str) -> None:
    """Drop the liveness traffic so only this event's outcome is read later."""
    _receive_for(ctx, queue_url, 5.0)


# ===== helpers =====

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
