"""input-transformer-array-paths-render-elements-slices-and-null-exactly."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "input-transformer-array-paths-render-elements-slices-and-null-exactly"
GROUP = "input-transformer"
SERVICES = ["events"]

_LIVENESS_TIMEOUT_S = 120.0
_DELIVERY_TIMEOUT_S = 90.0

_DETAIL = {
    "items": [10, 20, 30],
    "grid": [[1, 2], [3, 4]],
    "objs": [{"id": "o1", "v": 1}, {"id": "o2"}],
    "empty": [],
    "nul": None,
}
_PATHS = {
    "items": "$.detail.items",
    "second": "$.detail.items[1]",
    "beyond": "$.detail.items[7]",
    "cell": "$.detail.grid[1][0]",
    "grid": "$.detail.grid",
    "firstId": "$.detail.objs[0].id",
    "ids": "$.detail.objs[*].id",
    "objs": "$.detail.objs",
    "empty": "$.detail.empty",
    "nul": "$.detail.nul",
}
_JSON_TEMPLATE = (
    '{"whole": <items>, "wholeText": "<items>", "second": <second>, "beyond": <beyond>, '
    '"cell": <cell>, "grid": <grid>, "firstId": <firstId>, "ids": <ids>, "empty": <empty>, '
    '"nul": <nul>, "nulText": "<nul>", "m": <m>}'
)
_EXPECTED_JSON = {
    "whole": [10, 20, 30], "wholeText": "[10,20,30]", "second": 20, "beyond": "", "cell": 3,
    "grid": [[1, 2], [3, 4]], "firstId": "o1", "ids": ["o1", "o2"], "empty": [], "nul": None,
    "nulText": "null",
}
_TEXT_TEMPLATE = '"<m> ids=<ids> objs=<objs> second=<second> empty=<empty>"'


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:eventing",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """InputTransformer array paths (whole array, index, nested index, out-of-range index, [*]
    projection, empty array, JSON null) render exactly as EventBridge does in JSON and plain-text
    templates.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html
    """
    events = ctx.client("events")

    bus = _create_bus(ctx, events)
    source = ctx.unique_name("sim2real.arrays.")
    rule = _create_rule(ctx, events, bus, {"source": [source]}).rsplit("/", 1)[1]
    queue_url, queue_arn = _create_queue(ctx)
    paths = {**_PATHS, "m": "$.detail.m"}
    put = events.put_targets(Rule=rule, EventBusName=bus, Targets=[
        {"Id": "raw", "Arn": queue_arn},
        {"Id": "json", "Arn": queue_arn,
         "InputTransformer": {"InputPathsMap": paths, "InputTemplate": _JSON_TEMPLATE}},
        {"Id": "text", "Arn": queue_arn,
         "InputTransformer": {"InputPathsMap": paths, "InputTemplate": _TEXT_TEMPLATE}},
    ])
    assert put["FailedEntryCount"] == 0, f"PutTargets failed: {put['FailedEntries']!r}"

    live = ctx.unique_name("live-")
    _publish_until_live(ctx, events, queue_url, {
        "EventBusName": bus, "Source": source, "DetailType": "live",
        "Detail": json.dumps({**_DETAIL, "m": live}),
    }, lambda msgs: any(live in m["Body"] for m in msgs))

    marker = ctx.unique_name("arr-")
    resp = events.put_events(Entries=[{
        "EventBusName": bus, "Source": source, "DetailType": "arrays",
        "Detail": json.dumps({**_DETAIL, "m": marker}),
    }])
    assert resp["FailedEntryCount"] == 0, f"PutEvents refused the event: {resp['Entries']!r}"

    def _forms(msgs: list[dict]) -> dict[str, object]:
        out: dict[str, object] = {}
        for msg in msgs:
            body = json.loads(msg["Body"])
            if isinstance(body, str):
                if body.startswith(marker + " "):
                    out["text"] = body
            elif body.get("m") == marker:
                out["json"] = body
            elif isinstance(body.get("detail"), dict) and body["detail"].get("m") == marker:
                out["raw"] = body
        return out

    msgs = _drain(ctx, queue_url, until=lambda ms: len(_forms(ms)) == 3,
                  timeout_s=_DELIVERY_TIMEOUT_S, description=f"event {marker} reaching all 3 targets")
    forms = _forms(msgs)

    assert forms["raw"]["detail"] == {**_DETAIL, "m": marker}, (
        f"control: the raw target received detail {forms['raw']['detail']!r}"
    )
    rendered = dict(forms["json"])
    rendered.pop("m")
    assert rendered == _EXPECTED_JSON, (
        f"the JSON template rendered {rendered!r}; expected {_EXPECTED_JSON!r}"
    )
    expected_text = f"{marker} ids=[o1,o2] objs=[{{id:o1,v:1}},{{id:o2}}] second=20 empty=[]"
    assert forms["text"] == expected_text, (
        f"the plain-text template rendered {forms['text']!r}; expected {expected_text!r}"
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
