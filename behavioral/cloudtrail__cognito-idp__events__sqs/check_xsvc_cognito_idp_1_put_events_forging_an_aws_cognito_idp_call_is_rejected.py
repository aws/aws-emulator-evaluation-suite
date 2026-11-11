"""xsvc-cognito-idp-1-put-events-forging-an-aws-cognito-idp-call-is-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-1-put-events-forging-an-aws-cognito-idp-call-is-rejected"
GROUP = "eventing"
SERVICES = ["cloudtrail", "cognito-idp", "events", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_DETAIL_TYPE = "AWS API Call via CloudTrail"
_RESERVED_SOURCE = "aws.cognito-idp"
# PutEvents delivery involves no CloudTrail trail warm-up, so a short budget suffices.
_DELIVERY_BUDGET_S = 120.0
_ABSENCE_HOLD_S = 30.0
_LONG_POLL_S = 5

def _error_code(exc):
    return exc.response.get("Error", {}).get("Code")


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if "NonExistentQueue" not in str(_error_code(exc)):
            raise


def _collect(sqs, url, sink, wait_s):
    """Long-poll once for up to wait_s, then drain the queue, deleting each message read.

    Deleting on read keeps a message from resurfacing into the later absence assertion.
    """
    wait = wait_s
    for _ in range(20):
        msgs = sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait, VisibilityTimeout=60
        ).get("Messages", [])
        if not msgs:
            return
        for m in msgs:
            sink.append(m["Body"])
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])
        wait = 0


def _with_marker(raws, marker):
    out = []
    for r in raws:
        try:
            env = json.loads(r)
        except ValueError:
            continue
        if marker in json.dumps(env.get("detail") or {}):
            out.append(env)
    return out


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutEvents refuses an entry with the reserved aws.cognito-idp source and the matching rule
    never delivers it, while the custom-source twin in the same call is accepted and delivered.

    Reference: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html
    """
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    custom_source = ctx.unique_name("sim2real.xsvc-ctidp-")
    marker = ctx.unique_name("sim2real-forge-")

    q_name = ctx.unique_name("sim2real-xsvc-ctidp-forge-")
    q_url = sqs.create_queue(QueueName=q_name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    rule = ctx.unique_name("sim2real-xsvc-ctidp-forge-")
    rule_arn = events.put_rule(
        Name=rule,
        EventPattern=json.dumps(
            {
                "source": [_RESERVED_SOURCE, custom_source],
                "detail-type": [_DETAIL_TYPE],
                "detail": {
                    "eventSource": ["cognito-idp.amazonaws.com"],
                    "eventName": ["AdminCreateUser"],
                },
            }
        ),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule, Force=True))
    events.put_targets(Rule=rule, Targets=[{"Id": "sink", "Arn": q_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule, Ids=["sink"], Force=True))
    sqs.set_queue_attributes(
        QueueUrl=q_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ThisRuleOnly",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": q_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )

    detail = json.dumps(
        {
            "eventSource": "cognito-idp.amazonaws.com",
            "eventName": "AdminCreateUser",
            "requestParameters": {"userPoolId": marker, "username": "forged"},
        }
    )

    # The rule target and queue policy are eventually consistent: re-send the pair until the
    # control copy arrives, asserting the forged entry is refused on every send.
    sends = 0
    seen = []
    started = time.monotonic()
    deadline = started + _DELIVERY_BUDGET_S
    next_send = started
    while not [e for e in _with_marker(seen, marker) if e.get("source") == custom_source]:
        now = time.monotonic()
        if now >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: the custom-source control entry (source {custom_source!r}, "
                f"marker {marker!r}) never reached rule {rule}'s sink within "
                f"{_DELIVERY_BUDGET_S:.0f}s over {sends} PutEvents call(s); expected >=1, actual 0 "
                f"of {len(seen)} messages seen. Without it the forged entry's absence proves nothing"
            )
        if now >= next_send:
            sends += 1
            resp = events.put_events(
                Entries=[
                    {"Source": _RESERVED_SOURCE, "DetailType": _DETAIL_TYPE, "Detail": detail},
                    {"Source": custom_source, "DetailType": _DETAIL_TYPE, "Detail": detail},
                ]
            )
            entries = resp.get("Entries") or []
            assert len(entries) == 2, (
                f"PutEvents returns one result per entry, in order: expected 2, actual "
                f"{len(entries)} ({entries!r})"
            )
            assert resp.get("FailedEntryCount") == 1, (
                f"exactly the aws.cognito-idp entry fails: expected FailedEntryCount 1, actual "
                f"{resp.get('FailedEntryCount')!r} with entries {entries!r}"
            )
            assert entries[0].get("ErrorCode") == "NotAuthorizedForSourceException", (
                f"the forged entry (Source {_RESERVED_SOURCE!r}) is refused for its source: "
                f"expected ErrorCode 'NotAuthorizedForSourceException', actual "
                f"{entries[0].get('ErrorCode')!r} ({entries[0].get('ErrorMessage')!r})"
            )
            assert entries[0].get("ErrorMessage") == "Not authorized for the source.", (
                f"unexpected ErrorMessage for the forged entry: {entries[0].get('ErrorMessage')!r}"
            )
            assert "EventId" not in entries[0], (
                f"a refused entry is not assigned an EventId: actual {entries[0].get('EventId')!r}"
            )
            assert entries[1].get("EventId") and "ErrorCode" not in entries[1], (
                f"the custom-source entry in the SAME call is accepted: expected an EventId and "
                f"no ErrorCode, actual {entries[1]!r}"
            )
            next_send = time.monotonic() + 20.0
        _collect(sqs, q_url, seen, _LONG_POLL_S)
    control_latency_s = time.monotonic() - started

    control = [e for e in _with_marker(seen, marker) if e.get("source") == custom_source][0]
    assert control.get("detail-type") == _DETAIL_TYPE and (control.get("detail") or {}).get(
        "eventName"
    ) == "AdminCreateUser", (
        f"the control envelope carries the detail-type and detail that were sent: actual "
        f"{control.get('detail-type')!r} / {(control.get('detail') or {}).get('eventName')!r}"
    )

    hold_until = time.monotonic() + _ABSENCE_HOLD_S
    while time.monotonic() < hold_until:
        _collect(sqs, q_url, seen, _LONG_POLL_S)
    forged = [e for e in _with_marker(seen, marker) if e.get("source") == _RESERVED_SOURCE]
    assert forged == [], (
        f"a PutEvents entry with Source {_RESERVED_SOURCE!r} must never be delivered: expected 0 "
        f"envelopes carrying marker {marker!r} with that source, actual {len(forged)}, e.g. "
        f"{json.dumps(forged[:1])[:300]!r}. The same rule delivered the custom-source twin from "
        f"the same call after {control_latency_s:.0f}s, so the rule and its sink were live"
    )
    others = [e.get("source") for e in _with_marker(seen, marker)]
    assert set(others) == {custom_source}, (
        f"every delivered copy of this run's detail must carry the custom source: actual sources "
        f"{sorted(set(map(str, others)))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
