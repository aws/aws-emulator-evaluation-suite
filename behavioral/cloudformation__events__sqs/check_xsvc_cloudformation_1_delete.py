"""xsvc-cloudformation-1-delete."""
# On AWS, DeleteStack with a ClientRequestToken delivers, on
# the default bus, stack DELETE_IN_PROGRESS ("User Initiated") and DELETE_COMPLETE plus each
# resource's DELETE_IN_PROGRESS/DELETE_COMPLETE, all carrying the DELETE's token and the physical id
# the resource had before deletion. Arrival order at the queue is shuffled.
from __future__ import annotations

import json
import time
from datetime import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cloudformation-1-delete"
GROUP = "eventing"
SERVICES = ["cloudformation", "events", "sqs"]

STACK_TIMEOUT_S = 420.0
DELIVERY_TIMEOUT_S = 120.0
_RESOURCE_DT = "CloudFormation Resource Status Change"
_STACK_DT = "CloudFormation Stack Status Change"
_LOGICAL = ("Base", "Dependent")


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:eventing",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """DeleteStack delivers on the default bus the stack's and every resource's DELETE_IN_PROGRESS ->
    DELETE_COMPLETE, each carrying the delete's ClientRequestToken and the resource's pre-delete
    physical id.
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    ident = ctx.client("sts").get_caller_identity()
    partition = ident["Arn"].split(":")[1]

    stack = ctx.unique_name("sim2real-xsvc-cfn1-del-")
    prefix = f"arn:{partition}:cloudformation:{ctx.region}:{ident['Account']}:stack/{stack}/"
    create_token = ctx.unique_name("sim2real-xsvc-cfn1-ct-")
    delete_token = ctx.unique_name("sim2real-xsvc-cfn1-dt-")

    # The delivery path is proven LIVE by a canary before the subject act (see _eb_channels).
    q_url = _eb_channels(ctx, events, sqs, ident, {"dq": {
        "source": ["aws.cloudformation"],
        "detail-type": [_RESOURCE_DT, _STACK_DT],
        "detail": {"stack-id": [{"prefix": prefix}]},
    }})["dq"]

    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template("/" + stack),
        ClientRequestToken=create_token,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_id))
    status = _poll_status(cfn, stack_id, why="create")
    assert status == "CREATE_COMPLETE", f"create: expected CREATE_COMPLETE, got {status!r}"
    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }
    assert set(physical) == set(_LOGICAL), f"setup: expected resources {_LOGICAL!r}, got {sorted(physical)!r}"

    cfn.delete_stack(StackName=stack_id, ClientRequestToken=delete_token)
    status = _poll_status(cfn, stack_id, why="delete")
    assert status == "DELETE_COMPLETE", f"delete: expected DELETE_COMPLETE, got {status!r}"
    recorded = [e for e in _stack_events(cfn, stack_id) if e.get("ClientRequestToken") == delete_token]
    start_rec = [e for e in recorded if e["LogicalResourceId"] == stack and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
    assert len(start_rec) == 1, f"setup: expected one stack DELETE_IN_PROGRESS under the delete token, got {len(start_rec)}"

    seen: list[dict] = []
    _drain_until(
        sqs,
        q_url,
        seen,
        want=lambda evs: _find(evs, _STACK_DT, "DELETE_IN_PROGRESS", delete_token)
        and _find(evs, _STACK_DT, "DELETE_COMPLETE", delete_token)
        and all(
            _find(evs, _RESOURCE_DT, s, delete_token, lid)
            for lid in _LOGICAL
            for s in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")
        ),
        why="stack and per-resource DELETE_IN_PROGRESS/DELETE_COMPLETE under the delete token",
    )

    started = _find(seen, _STACK_DT, "DELETE_IN_PROGRESS", delete_token)[0]
    assert started["detail"]["status-details"]["status-reason"] == start_rec[0].get("ResourceStatusReason"), (
        f"stack DELETE_IN_PROGRESS status-reason: event={started['detail']['status-details']['status-reason']!r} "
        f"recorded={start_rec[0].get('ResourceStatusReason')!r}"
    )
    finished = _find(seen, _STACK_DT, "DELETE_COMPLETE", delete_token)
    assert {e["detail"]["stack-id"] for e in finished} == {stack_id}, (
        f"DELETE_COMPLETE must name the deleted stack {stack_id!r}; got {sorted({e['detail']['stack-id'] for e in finished})!r}"
    )
    _assert_ordered("stack", _t(started), max(_t(e) for e in finished))

    for lid in _LOGICAL:
        gone = _find(seen, _RESOURCE_DT, "DELETE_COMPLETE", delete_token, lid)
        assert {e["detail"]["physical-resource-id"] for e in gone} == {physical[lid]}, (
            f"{lid} DELETE_COMPLETE must carry its pre-delete physical id {physical[lid]!r}; got "
            f"{sorted({e['detail']['physical-resource-id'] for e in gone})!r}"
        )
        assert {e["detail"]["resource-type"] for e in gone} == {"AWS::SSM::Parameter"}, (
            f"{lid} DELETE_COMPLETE resource-type: got {sorted({e['detail']['resource-type'] for e in gone})!r}"
        )
        first = min(_t(e) for e in _find(seen, _RESOURCE_DT, "DELETE_IN_PROGRESS", delete_token, lid))
        _assert_ordered(lid, first, max(_t(e) for e in gone))

    mine = [e for e in seen if e["detail"].get("client-request-token") == delete_token]
    wrong = [e for e in mine if not _status(e).startswith("DELETE_")]
    assert not wrong, (
        f"the delete token may appear only on DELETE_* statuses; got "
        f"{[(e['detail'].get('logical-resource-id'), _status(e)) for e in wrong]!r}"
    )


# ===== helpers =====

_CANARY_SOURCE = "sim2real.canary"
_CANARY_MARK = "sim2real.canary "
WARMUP_TIMEOUT_S = 120.0


def _queue_with_policy(ctx, sqs, ident, prefix: str, principal: str, source_arns: list[str]) -> tuple[str, str]:
    """Create a queue whose send policy is set IN CreateQueue, not by a later SetQueueAttributes.

    Measured: a policy set right before the subject act propagates eventually, and EventBridge
    deliveries refused meanwhile were retried with backoff — 10 of 15 events had not arrived 120 s
    later. The ARN is deterministic, so the policy can name it before the queue exists.
    """
    name = ctx.unique_name(prefix)
    arn = f"arn:{ident['Arn'].split(':')[1]}:sqs:{ctx.region}:{ident['Account']}:{name}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": principal},
            "Action": "sqs:SendMessage",
            "Resource": arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": source_arns}},
        }],
    }
    url = sqs.create_queue(
        QueueName=name, Attributes={"Policy": json.dumps(policy)}, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: sqs.delete_queue(QueueUrl=url)))
    real = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert real == arn, f"setup: queue ARN {real!r} differs from the ARN its policy names {arn!r}"
    return url, arn


def _put_rule(ctx, events, name: str, pattern: dict, targets: list[dict]) -> str:
    rule_arn = events.put_rule(
        Name=name, State="ENABLED", EventPattern=json.dumps(pattern),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: events.delete_rule(Name=name)))
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: events.remove_targets(Rule=name, Ids=[t["Id"] for t in targets])))
    resp = events.put_targets(Rule=name, Targets=targets)
    assert resp["FailedEntryCount"] == 0, f"PutTargets on {name!r} failed: {resp!r}"
    return rule_arn


def _eb_channels(ctx, events, sqs, ident, patterns: dict[str, dict]) -> dict[str, str]:
    """One default-bus rule -> queue per pattern, plus ONE canary rule targeting every queue.

    The canary is a bounded warm-up barrier on an observable condition: the subject act starts only
    once a canary PutEvents has actually landed in every queue, so a delivery path that is not yet
    live cannot masquerade as a dropped (or a correctly withheld) CloudFormation event.
    """
    partition = ident["Arn"].split(":")[1]
    rule_arn = lambda n: f"arn:{partition}:events:{ctx.region}:{ident['Account']}:rule/{n}"  # noqa: E731
    canary_rule = ctx.unique_name("sim2real-xsvc-cfn1-canary-")
    canary_id = ctx.unique_name("canary-")
    urls: dict[str, str] = {}
    arns: dict[str, str] = {}
    for key, pattern in patterns.items():
        rule = ctx.unique_name(f"sim2real-xsvc-cfn1-{key}-")
        urls[key], arns[key] = _queue_with_policy(
            ctx, sqs, ident, f"sim2real-xsvc-cfn1-{key}-", "events.amazonaws.com",
            [rule_arn(rule), rule_arn(canary_rule)],
        )
        made = _put_rule(ctx, events, rule, pattern, [{"Id": "q", "Arn": arns[key]}])
        assert made == rule_arn(rule), f"setup: rule ARN {made!r} != predicted {rule_arn(rule)!r}"
    _put_rule(
        ctx, events, canary_rule,
        {"source": [_CANARY_SOURCE], "detail": {"run": [canary_id]}},
        [{"Id": key, "Arn": arn} for key, arn in arns.items()],
    )
    pending = set(urls)
    deadline = time.monotonic() + WARMUP_TIMEOUT_S
    next_put = 0.0
    while pending and time.monotonic() < deadline:
        if time.monotonic() >= next_put:
            resp = events.put_events(Entries=[{
                "Source": _CANARY_SOURCE, "DetailType": "sim2real canary",
                "Detail": json.dumps({"run": canary_id}),
            }])
            assert resp["FailedEntryCount"] == 0, f"canary PutEvents failed: {resp!r}"
            next_put = time.monotonic() + 15.0
        for key in sorted(pending):
            got = sqs.receive_message(QueueUrl=urls[key], MaxNumberOfMessages=10, WaitTimeSeconds=1)
            for msg in got.get("Messages", []):
                sqs.delete_message(QueueUrl=urls[key], ReceiptHandle=msg["ReceiptHandle"])
                if _is_canary(msg["Body"]):
                    pending.discard(key)
    assert not pending, (
        f"warm-up: the EventBridge->SQS path never delivered a canary to {sorted(pending)!r} within "
        f"{WARMUP_TIMEOUT_S}s, so the wiring under test is not live"
    )
    return urls


def _is_canary(body: str) -> bool:
    if body.startswith(_CANARY_MARK):
        return True
    try:
        doc = json.loads(body)
    except ValueError:
        return False
    return isinstance(doc, dict) and doc.get("source") == _CANARY_SOURCE



def _template(base: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Base": {"Type": "AWS::SSM::Parameter",
                     "Properties": {"Name": f"{base}/base", "Type": "String", "Value": "ok"}},
            "Dependent": {"Type": "AWS::SSM::Parameter", "DependsOn": "Base",
                          "Properties": {"Name": f"{base}/dependent", "Type": "String", "Value": "ok"}},
        },
    })




def _poll_status(cfn, stack_id: str, *, why: str) -> str:
    """Bounded poll to a non-IN_PROGRESS status; RAISES on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not last.endswith("_IN_PROGRESS"):
            return last
        time.sleep(3.0)
    raise AssertionError(f"stack {stack_id!r} still {last!r} after {STACK_TIMEOUT_S}s [{why}]")


def _stack_events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _drain_until(sqs, url: str, seen: list, *, want, why: str) -> None:
    """Accumulate into `seen` until want(seen); RAISES on timeout."""
    deadline = time.monotonic() + DELIVERY_TIMEOUT_S
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=2, VisibilityTimeout=60)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
            if not _is_canary(msg["Body"]):
                seen.append(json.loads(msg["Body"]))
        if want(seen):
            return
    raise AssertionError(
        f"queue never yielded [{why}] within {DELIVERY_TIMEOUT_S}s; got "
        f"{[(e['detail'].get('logical-resource-id'), _status(e)) for e in seen]!r}"
    )


def _status(e: dict) -> str:
    return e.get("detail", {}).get("status-details", {}).get("status") or ""


def _find(evs: list[dict], detail_type: str, status: str, token: str, logical: str | None = None) -> list[dict]:
    return [
        e for e in evs
        if e.get("detail-type") == detail_type and _status(e) == status
        and e["detail"].get("client-request-token") == token
        and (logical is None or e["detail"].get("logical-resource-id") == logical)
    ]


def _t(e: dict) -> datetime:
    return datetime.fromisoformat(e["time"].replace("Z", "+00:00"))


def _assert_ordered(subject: str, began: datetime, ended: datetime) -> None:
    # EventBridge `time` is second-granular, so per-resource order is non-strict.
    assert began <= ended, (
        f"per-resource causal order violated for {subject}: DELETE_IN_PROGRESS at {began.isoformat()} "
        f"after DELETE_COMPLETE at {ended.isoformat()}"
    )


def _ignore_missing(fn) -> None:
    """Teardown helper: tolerate a resource already gone, and nothing else."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
