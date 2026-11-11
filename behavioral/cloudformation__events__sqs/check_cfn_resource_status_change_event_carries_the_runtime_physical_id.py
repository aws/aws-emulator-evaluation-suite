"""cfn-resource-status-change-event-carries-the-runtime-physical-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-resource-status-change-event-carries-the-runtime-physical-id"
GROUP = "eventing"
SERVICES = ["cloudformation", "events", "sqs"]

STACK_TIMEOUT_S = 240.0
DELIVERY_TIMEOUT_S = 180.0
_RESOURCE_DT = "CloudFormation Resource Status Change"
_STACK_DT = "CloudFormation Stack Status Change"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CreateStack must land real CloudFormation events on the default bus whose payload carries
    the runtime physical resource id and the caller's client request token."""
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    tag = [{"Key": "sim2real-check", "Value": CHECK}]

    token = ctx.unique_name("sim2realcfnebtok-")
    other_token = ctx.unique_name("sim2realcfnebother-")

    # --- Consumer wiring, created in-check and independent of the subject stack ------------------
    queue_name = ctx.unique_name("sim2real-cfn-eb-q-")
    queue_url = sqs.create_queue(
        QueueName=queue_name, tags={"sim2real-check": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    rule_name = ctx.unique_name("sim2real-cfn-eb-r-")
    rule_arn = events.put_rule(
        Name=rule_name,
        State="ENABLED",
        # Filtering on the client request token is a STRUCTURAL barrier for the negative leg below:
        # a stack created with a different token cannot match this pattern by construction, so the
        # absence needs no wait.
        EventPattern=json.dumps(
            {
                "source": ["aws.cloudformation"],
                "detail-type": [_RESOURCE_DT, _STACK_DT],
                "detail": {"client-request-token": [token]},
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["RuleArn"]
    # LIFO teardown: RemoveTargets (registered second) runs before DeleteRule, which is the order
    # EventBridge requires.
    ctx.on_cleanup(lambda: _ignore_missing(lambda: events.delete_rule(Name=rule_name)))
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: events.remove_targets(Rule=rule_name, Ids=["sim2real-target"]))
    )

    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    failed = events.put_targets(Rule=rule_name, Targets=[{"Id": "sim2real-target", "Arn": queue_arn}])
    assert failed["FailedEntryCount"] == 0, (
        f"PutTargets must attach the queue: expected FailedEntryCount 0, got {failed!r}"
    )

    # --- The subject: one ordinary stack, created with a token this check chose ------------------
    param_name = "/" + ctx.unique_name("sim2real-cfn-eb-p-")
    subject = ctx.unique_name("sim2real-cfn-eb-s-")
    stack_id = cfn.create_stack(
        StackName=subject,
        TemplateBody=_template(param_name),
        ClientRequestToken=token,
        Tags=tag,
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=subject))
    created = _poll_status(
        cfn, subject, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="subject create"
    )
    assert created == "CREATE_COMPLETE", f"stack {subject!r}: expected CREATE_COMPLETE, got {created!r}"

    physical_id = cfn.describe_stack_resource(StackName=subject, LogicalResourceId="Subject")[
        "StackResourceDetail"
    ]["PhysicalResourceId"]

    # --- The terminal read is AT THE CONSUMER, not at CloudFormation ----------------------------
    started = time.monotonic()
    collected = _drain_until(
        sqs,
        queue_url,
        want=lambda evs: _find(evs, _RESOURCE_DT, "CREATE_COMPLETE") is not None
        and _find(evs, _STACK_DT, "CREATE_COMPLETE") is not None,
        timeout_s=DELIVERY_TIMEOUT_S,
        why="a resource CREATE_COMPLETE and a stack CREATE_COMPLETE event for this token",
    )
    latency_s = time.monotonic() - started

    resource_event = _find(collected, _RESOURCE_DT, "CREATE_COMPLETE")
    assert resource_event is not None, (
        f"no {_RESOURCE_DT!r} event with status CREATE_COMPLETE arrived within {DELIVERY_TIMEOUT_S}s; "
        f"saw detail-types {sorted({e.get('detail-type') for e in collected})!r}"
    )
    detail = resource_event["detail"]
    assert resource_event["source"] == "aws.cloudformation", (
        f"event source: expected 'aws.cloudformation', got {resource_event['source']!r}"
    )
    assert resource_event["account"] == account, (
        f"event account: expected {account!r}, got {resource_event['account']!r}"
    )
    assert resource_event["region"] == ctx.region, (
        f"event region: expected {ctx.region!r}, got {resource_event['region']!r}"
    )
    assert detail["stack-id"] == stack_id, (
        f"detail.stack-id: expected the StackId CreateStack returned {stack_id!r}, got "
        f"{detail['stack-id']!r}"
    )
    assert detail["client-request-token"] == token, (
        f"detail.client-request-token: expected {token!r}, got {detail['client-request-token']!r}"
    )
    assert detail["resource-type"] == "AWS::SSM::Parameter", (
        f"detail.resource-type: expected 'AWS::SSM::Parameter', got {detail['resource-type']!r}"
    )
    # The join no recording can carry: the physical id is minted at runtime, and the event and the
    # control plane must agree on it.
    assert detail["physical-resource-id"] == physical_id, (
        f"detail.physical-resource-id: expected the id DescribeStackResource reports "
        f"({physical_id!r}), got {detail['physical-resource-id']!r}"
    )

    stack_event = _find(collected, _STACK_DT, "CREATE_COMPLETE")
    assert stack_event is not None, (
        f"no {_STACK_DT!r} event with status CREATE_COMPLETE arrived; a target that emits only "
        "resource events is missing half the documented surface"
    )
    assert stack_event["detail"]["stack-id"] == stack_id, (
        f"stack event detail.stack-id: expected {stack_id!r}, got {stack_event['detail']['stack-id']!r}"
    )

    # --- Negative leg: a stack outside the pattern must produce nothing (structural) -------------
    # The control is the delivery just proven on this exact wiring, measured at latency_s; the
    # barrier is the pattern itself, which cannot match a different token.
    other = ctx.unique_name("sim2real-cfn-eb-o-")
    other_param = "/" + ctx.unique_name("sim2real-cfn-eb-op-")
    cfn.create_stack(
        StackName=other,
        TemplateBody=_template(other_param),
        ClientRequestToken=other_token,
        Tags=tag,
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=other))
    other_status = _poll_status(
        cfn, other, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"}, why="control-group create"
    )
    assert other_status == "CREATE_COMPLETE", (
        f"control-group stack {other!r}: expected CREATE_COMPLETE, got {other_status!r}"
    )
    stray = _drain_for(sqs, queue_url, seconds=max(2.0 * latency_s, 20.0))
    off_pattern = [e for e in stray if e.get("detail", {}).get("client-request-token") == other_token]
    assert not off_pattern, (
        f"the rule filters on client-request-token {token!r}, so no event for {other_token!r} may be "
        f"delivered; got {len(off_pattern)} (first={off_pattern[:1]!r})"
    )


# ===== helpers =====


def _template(param_name: str) -> str:
    """One resource whose physical id is a value the check picks, so the event's
    physical-resource-id can be compared against something known and non-generic."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Subject": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": param_name, "Type": "String", "Value": "sim2real"},
                }
            },
        }
    )


def _poll_status(cfn, stack_name: str, terminal: set[str], *, why: str) -> str:
    """Bounded retry with a deadline; RAISES on timeout rather than returning the last value."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(4.0)
    raise AssertionError(
        f"stack {stack_name!r} did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"[{why}] (last={last!r})"
    )


def _receive(sqs, queue_url: str, *, wait_s: int = 5) -> list[dict]:
    """One long-poll receive, returning parsed EventBridge envelopes and deleting what it read."""
    resp = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s, VisibilityTimeout=30
    )
    out = []
    for msg in resp.get("Messages", []):
        out.append(json.loads(msg["Body"]))
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _drain_until(sqs, queue_url: str, *, want, timeout_s: float, why: str) -> list[dict]:
    """Accumulate events until want(events); RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    seen: list[dict] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
        if want(seen):
            return seen
    raise AssertionError(
        f"queue never yielded [{why}] within {timeout_s}s; collected {len(seen)} events with "
        f"detail-types {sorted({e.get('detail-type') for e in seen})!r}"
    )


def _drain_for(sqs, queue_url: str, *, seconds: float) -> list[dict]:
    """Drain for a fixed window, calibrated by the caller against measured delivery latency."""
    deadline = time.monotonic() + seconds
    seen: list[dict] = []
    while time.monotonic() < deadline:
        seen.extend(_receive(sqs, queue_url))
    return seen


def _find(events_seen: list[dict], detail_type: str, status: str) -> dict | None:
    for event in events_seen:
        if event.get("detail-type") != detail_type:
            continue
        if event.get("detail", {}).get("status-details", {}).get("status") == status:
            return event
    return None


def _ignore_missing(fn) -> None:
    """Teardown helper: tolerate a resource already gone, and nothing else."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in {"ResourceNotFoundException", "AWS.SimpleQueueService.NonExistentQueue"}:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
