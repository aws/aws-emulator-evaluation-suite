"""cfn-redshift-cluster-event-sqs-queue-arn-resolution-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-redshift-cluster-event-sqs-queue-arn-resolution-positive"
GROUP = "arn-resolution"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rule target ARN built with Fn::GetAtt on the queue equals the queue's real QueueArn in both
    the stack output and ListTargetsByRule, and that queue receives the Redshift-shaped event."""
    queue_name = _xname(ctx, "q")
    rule_name = _xname(ctx, "rule")
    redshift_source = "sim2real.redshift"

    template = {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_name},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [redshift_source]},
                    "Targets": [
                        {"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["Queue", "Arn"]}}
                    ],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    queue_url = stack["outputs"]["QueueUrl"]
    stack_reported_arn = stack["outputs"]["QueueArn"]

    sqs = ctx.client("sqs")
    actual_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    assert stack_reported_arn == actual_arn, (
        f"stack Output QueueArn {stack_reported_arn!r} != queue's real arn {actual_arn!r}"
    )

    events = ctx.client("events")
    target_arn = events.list_targets_by_rule(Rule=rule_name)["Targets"][0]["Arn"]
    # This is the core assertion: the Fn::GetAtt-resolved Arn that EventBridge actually stored
    # on the rule's target equals the queue's real arn, not a stub/echoed value.
    assert target_arn == actual_arn, (
        f"rule target arn {target_arn!r} (Fn::GetAtt-resolved) != queue's real arn {actual_arn!r}"
    )

    entry = {
        "Source": redshift_source,
        "DetailType": "Redshift Cluster Event Notification",
        "Detail": json.dumps({"eventId": "SIM2REAL-ARN-RESOLUTION"}),
    }
    # The queue policy granting events.amazonaws.com send permission was just created by the
    # same stack and can take a while to propagate; resend the event periodically while polling
    # so a propagation-delayed first attempt does not sink the whole check.
    message = _send_until_received(
        events, sqs, queue_url, entry,
        timeout_s=120.0, resend_interval_s=15.0,
        description="event delivered via GetAtt-resolved target arn",
    )
    body = json.loads(message["Body"])
    # EventBridge delivers "detail" as an already-parsed JSON object in the SQS envelope
    # (it is the parsed form of PutEvents' Detail string), not a JSON-encoded string --
    # double-decoding it raises TypeError.
    delivered_event_id = body["detail"]["eventId"]
    assert delivered_event_id == "SIM2REAL-ARN-RESOLUTION", (
        f"delivered detail.eventId {delivered_event_id!r} != sent eventId 'SIM2REAL-ARN-RESOLUTION'"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _send_until_received(
    events_client, sqs_client, queue_url, entry, *,
    timeout_s=120.0, resend_interval_s=15.0, description="message received",
) -> dict[str, Any]:
    """Send entry via put_events, polling the queue for it -- re-sending periodically so a
    resource-policy propagation delay on the very first attempt does not fail the check.
    """
    deadline = time.monotonic() + timeout_s
    next_send = 0.0
    last = None
    while time.monotonic() < deadline:
        now = time.monotonic()
        if now >= next_send:
            resp = events_client.put_events(Entries=[entry])
            if resp.get("FailedEntryCount"):
                raise AssertionError(f"put_events rejected entry: {resp['Entries']!r}")
            next_send = now + resend_interval_s
        resp = sqs_client.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        msgs = resp.get("Messages")
        if msgs:
            return msgs[0]
        last = msgs
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
