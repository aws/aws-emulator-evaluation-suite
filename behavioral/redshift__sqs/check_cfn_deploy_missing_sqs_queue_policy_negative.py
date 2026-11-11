"""cfn-deploy-missing-sqs-queue-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-missing-sqs-queue-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose rule targets one queue with no policy granting events.amazonaws.com and one queue
    with that grant deploys; only the granted queue receives the matching event, and the other
    stays empty with ApproximateNumberOfMessages "0"."""
    rule_name = _xname(ctx, "rule")
    queue_no_policy_name = _xname(ctx, "q-nopolicy")
    queue_with_policy_name = _xname(ctx, "q-withpolicy")
    redshift_source = "sim2real.redshift"

    template = {
        "Resources": {
            "QueueNoPolicy": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_no_policy_name},
            },
            "QueueWithPolicy": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": queue_with_policy_name},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [redshift_source]},
                    "Targets": [
                        {
                            "Id": "no-policy-target",
                            "Arn": {"Fn::GetAtt": ["QueueNoPolicy", "Arn"]},
                        },
                        {
                            "Id": "with-policy-target",
                            "Arn": {"Fn::GetAtt": ["QueueWithPolicy", "Arn"]},
                        },
                    ],
                },
            },
            "QueueWithPolicyPolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "QueueWithPolicy"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["QueueWithPolicy", "Arn"]},
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
            "QueueNoPolicyUrl": {"Value": {"Ref": "QueueNoPolicy"}},
            "QueueWithPolicyUrl": {"Value": {"Ref": "QueueWithPolicy"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    no_policy_url = stack["outputs"]["QueueNoPolicyUrl"]
    with_policy_url = stack["outputs"]["QueueWithPolicyUrl"]

    events = ctx.client("events")
    sqs = ctx.client("sqs")
    entry = {
        "Source": redshift_source,
        "DetailType": "Redshift Cluster Event Notification",
        "Detail": json.dumps({"eventId": "SIM2REAL-MISSING-POLICY"}),
    }

    # Positive control: the properly-policied sibling queue on the same rule DOES receive it.
    # The queue policy was just created by the same stack and can take a while to propagate, so
    # resend the event periodically while polling rather than relying on a single attempt.
    positive_start = time.monotonic()
    message = _send_until_received(
        events, sqs, with_policy_url, entry,
        timeout_s=120.0, resend_interval_s=15.0,
        description="event delivered to correctly-policied queue",
    )
    positive_latency_s = time.monotonic() - positive_start
    # EventBridge->SQS delivery already parses "detail" into the event object; the body is
    # not double-encoded, so a single json.loads recovers it.
    body = json.loads(message["Body"])
    assert body["detail"]["eventId"] == "SIM2REAL-MISSING-POLICY", (
        f"expected eventId SIM2REAL-MISSING-POLICY, got {body.get('detail')!r}"
    )

    # Negative: the queue lacking a resource policy never receives the same event. This is a twin
    # control on the SAME rule at the SAME instant (the positive control above), so absence is
    # bounded by that live control rather than a fixed guess -- hold for >=3x its measured
    # delivery latency, polling instead of sleeping so a correct-but-slower target never scores as
    # blocked.
    absence_window_s = max(15.0, positive_latency_s * 3)
    deadline = time.monotonic() + absence_window_s
    leftover: list[dict[str, Any]] = []
    while time.monotonic() < deadline and not leftover:
        resp = sqs.receive_message(
            QueueUrl=no_policy_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        leftover.extend(resp.get("Messages", []))
    assert not leftover, f"unpolicied queue unexpectedly received a message: {leftover}"

    # Second independent observable: the queue's own reported backlog, not just an empty receive.
    attrs = sqs.get_queue_attributes(
        QueueUrl=no_policy_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"unpolicied queue reports {attrs['ApproximateNumberOfMessages']} pending messages, expected 0"
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

    # Deleting the stack's resources can take minutes, and a delete can fail on a dependency
    # that clears moments later; retry it twice.
    for _ in range(3):
        cfn.delete_stack(StackName=stack_name)
        status = _poll_until(
            _status,
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=600,
            interval_s=10.0,
            description=f"delete stack {stack_name}",
        )
        if status != "DELETE_FAILED":
            return
        time.sleep(15.0)
    raise AssertionError(f"stack {stack_name} is still DELETE_FAILED after three deletes")


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
