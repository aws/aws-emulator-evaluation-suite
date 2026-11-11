"""cfn-deploy-eventbridge-rule-wrong-arn-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-wrong-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["redshift", "sqs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:eventing", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose EventBridge rule targets a well-formed ARN of a nonexistent SQS queue deploys
    anyway, GetQueueUrl answers AWS.SimpleQueueService.NonExistentQueue for that name, and a
    correctly targeted queue on the same rule receives the matching event."""
    sqs = ctx.client("sqs")
    events = ctx.client("events")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    rule_name = _xname(ctx, "rule")
    good_queue_name = _xname(ctx, "q-good")
    bogus_queue_name = _xname(ctx, "q-bogus-doesnotexist")
    bogus_arn = f"arn:aws:sqs:{ctx.region}:{account_id}:{bogus_queue_name}"
    redshift_source = "sim2real.redshift"

    template = {
        "Resources": {
            "GoodQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": good_queue_name},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {"source": [redshift_source]},
                    "Targets": [
                        {"Id": "good-target", "Arn": {"Fn::GetAtt": ["GoodQueue", "Arn"]}},
                        {"Id": "bogus-target", "Arn": bogus_arn},
                    ],
                },
            },
            "GoodQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "GoodQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["GoodQueue", "Arn"]},
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
            "GoodQueueUrl": {"Value": {"Ref": "GoodQueue"}},
        },
    }

    stack = _deploy_cfn(ctx, json.dumps(template))
    good_queue_url = stack["outputs"]["GoodQueueUrl"]

    # Prove the mistyped target is genuinely not a real queue -- there is nothing that could
    # ever have received a message through it.
    code, msg = _client_error(lambda: sqs.get_queue_url(QueueName=bogus_queue_name))
    assert code == "AWS.SimpleQueueService.NonExistentQueue", (
        f"expected AWS.SimpleQueueService.NonExistentQueue for the bogus target queue, got {code!r}"
    )
    assert msg == "The specified queue does not exist.", msg

    # Positive control: the correctly-targeted sibling queue on the same rule still receives it,
    # proving the bogus second target did not break the rule as a whole. The queue policy was
    # just created by the same stack and can take a while to propagate, so resend the event
    # periodically while polling rather than relying on a single attempt.
    message = _send_until_received(
        events, sqs, good_queue_url,
        {
            "Source": redshift_source,
            "DetailType": "Redshift Cluster Event Notification",
            "Detail": json.dumps({"eventId": "SIM2REAL-WRONG-ARN"}),
        },
        timeout_s=120.0, resend_interval_s=15.0,
        description="event delivered to correctly-targeted queue despite sibling bogus target",
    )
    # SQS delivers the EventBridge event envelope as a single JSON string; "detail" is already
    # the parsed object (the Detail we passed to put_events), not a nested JSON string.
    delivered_event_id = json.loads(message["Body"])["detail"]["eventId"]
    assert delivered_event_id == "SIM2REAL-WRONG-ARN", (
        f"expected delivered detail.eventId == 'SIM2REAL-WRONG-ARN', got {delivered_event_id!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _client_error(fn):
    """Call fn() and return its error as (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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
        timeout_s=300,
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
