"""cfn-stack-update-redshift-event-categories-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-redshift-event-categories-positive"
GROUP = "deployment-order"
SERVICES = ["redshift", "sqs"]


def _template(rule_name: str, queue_ref_name: str, severities: list[str], source: str) -> dict:
    return {
        "Resources": {
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_ref_name},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {
                        "source": [source],
                        "detail": {"severity": severities},
                    },
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
        },
    }


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event category excluded by a stack's original rule pattern is not delivered to SQS, and after
    UpdateStack reaches UPDATE_COMPLETE with that category included, the identical event is."""
    queue_name = _xname(ctx, "q")
    rule_name = _xname(ctx, "rule")
    redshift_source = "sim2real.redshift"

    stack = _deploy_cfn(ctx, json.dumps(_template(rule_name, queue_name, ["ERROR"], redshift_source)))
    queue_url = stack["outputs"]["QueueUrl"]
    stack_name = stack["stack_name"]

    events = ctx.client("events")
    sqs = ctx.client("sqs")

    # Phase 1: pattern only matches ERROR -> an INFO event must NOT reach the queue. Rather than
    # bound the absence with a bare sleep, send a matching ERROR control alongside the INFO
    # subject on the identical rule/queue wiring, time how long the control actually takes to
    # arrive right now, then hold the absence for >=3x that live latency (floored) -- a twin
    # control in the same instant, so a target with no delivery path at all cannot score green.
    control_id = "SIM2REAL-CATEGORY-CONTROL"
    subject_id = "SIM2REAL-CATEGORY-BEFORE"
    t_send = time.monotonic()
    events.put_events(
        Entries=[
            {
                "Source": redshift_source,
                "DetailType": "Redshift Cluster Event Notification",
                "Detail": json.dumps({"severity": "ERROR", "eventId": control_id}),
            },
            {
                "Source": redshift_source,
                "DetailType": "Redshift Cluster Event Notification",
                "Detail": json.dumps({"severity": "INFO", "eventId": subject_id}),
            },
        ]
    )

    control_latency_s = None
    calibrate_deadline = time.monotonic() + 60.0
    while control_latency_s is None and time.monotonic() < calibrate_deadline:
        for msg in _receive_and_delete(sqs, queue_url):
            event_id = _event_id(msg)
            assert event_id != subject_id, (
                "INFO event unexpectedly delivered before pattern update (during control "
                "calibration, before any absence window even started)"
            )
            if event_id == control_id:
                control_latency_s = time.monotonic() - t_send
    assert control_latency_s is not None, (
        "the ERROR control event (matching the ORIGINAL pattern) was never delivered within 60s "
        "on this same rule/queue wiring, so an absence measured for the excluded INFO event would "
        "prove nothing about the pattern doing the excluding"
    )

    hold_window_s = max(control_latency_s * 3.0, 15.0)
    hold_deadline = time.monotonic() + hold_window_s
    while time.monotonic() < hold_deadline:
        for msg in _receive_and_delete(sqs, queue_url):
            event_id = _event_id(msg)
            assert event_id != subject_id, (
                f"INFO event unexpectedly delivered before pattern update, within a {hold_window_s:.1f}s "
                f"hold window calibrated from a live control latency of {control_latency_s:.1f}s"
            )

    # Phase 2: update the rule's pattern to also include INFO.
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_template(rule_name, queue_name, ["ERROR", "INFO"], redshift_source)),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert status == "UPDATE_COMPLETE", f"stack update ended in {status}"

    # Phase 3: the identical category of event now matches the updated pattern. The updated
    # rule pattern (and any policy re-evaluation) can take a moment to fully propagate, so
    # resend the event periodically while polling rather than relying on a single attempt.
    message = _send_until_received(
        events, sqs, queue_url,
        {
            "Source": redshift_source,
            "DetailType": "Redshift Cluster Event Notification",
            "Detail": json.dumps({"severity": "INFO", "eventId": "SIM2REAL-CATEGORY-AFTER"}),
        },
        timeout_s=120.0, resend_interval_s=15.0,
        description="INFO event delivered after pattern update",
    )
    delivered_id = _event_id(message)
    assert delivered_id == "SIM2REAL-CATEGORY-AFTER", (
        f"expected the resent INFO event's id after the pattern update, got {delivered_id!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _event_id(message: dict) -> str:
    # EventBridge delivers the full event envelope as the SQS message body, where "detail" is
    # already a nested JSON object -- not a JSON-encoded string -- so it must not be re-parsed.
    return json.loads(message["Body"])["detail"]["eventId"]


def _receive_and_delete(sqs_client, queue_url: str, *, max_messages: int = 10, wait_s: int = 5) -> list[dict]:
    resp = sqs_client.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=wait_s
    )
    msgs = resp.get("Messages", [])
    for m in msgs:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return msgs


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
            events_client.put_events(Entries=[entry])
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
