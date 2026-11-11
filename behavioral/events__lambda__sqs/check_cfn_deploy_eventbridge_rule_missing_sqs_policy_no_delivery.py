"""cfn-deploy-eventbridge-rule-missing-sqs-policy-no-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-missing-sqs-policy-no-delivery"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sqs"]

def _template(source: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueNameParam": {"Type": "String"},
            "RuleNameParam": {"Type": "String"},
        },
        "Resources": {
            # Deliberately NO AWS::SQS::QueuePolicy resource: the queue's default access
            # policy denies any principal other than the queue owner, so events.amazonaws.com
            # has no sqs:SendMessage grant.
            "TargetQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "RuleNameParam"},
                    "EventPattern": {"source": [source], "detail-type": ["NoPolicyTest"]},
                    "State": "ENABLED",
                    "Targets": [
                        {"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["TargetQueue", "Arn"]}}
                    ],
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "TargetQueue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["TargetQueue", "Arn"]}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
        },
    })


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation rule whose SQS target has no queue policy accepts PutEvents but never
    delivers the event; adding the queue policy afterwards delivers the next matching event."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    source = _xname(ctx, "nopolicy-src")
    result = _deploy_cfn(
        ctx,
        _template(source),
        parameters={
            "QueueNameParam": _xname(ctx, "nopolicy-q"),
            "RuleNameParam": _xname(ctx, "nopolicy-rule"),
        },
    )
    queue_url = result["outputs"]["QueueUrl"]
    queue_arn = result["outputs"]["QueueArn"]
    rule_arn = result["outputs"]["RuleArn"]

    marker1 = ctx.unique_name("nopolicy-payload-")
    put_result = events.put_events(Entries=[{
        "Source": source,
        "DetailType": "NoPolicyTest",
        "Detail": json.dumps({"id": marker1}),
    }])
    # PutEvents itself reports success -- EventBridge accepted the event for routing.
    assert put_result.get("FailedEntryCount", 0) == 0, (
        f"expected PutEvents to accept the entry (FailedEntryCount 0), got {put_result}"
    )

    delivered = _poll_for_marker(ctx, queue_url, marker1, timeout_s=45)
    assert delivered is None, f"event was unexpectedly delivered without a queue policy: {delivered}"

    # --- positive control: add the missing policy statement, and delivery starts working ---
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    marker2 = ctx.unique_name("nopolicy-payload2-")

    def _send_and_check():
        events.put_events(Entries=[{
            "Source": source,
            "DetailType": "NoPolicyTest",
            "Detail": json.dumps({"id": marker2}),
        }])
        return _poll_for_marker(ctx, queue_url, marker2, timeout_s=10)

    # Queue-policy propagation is eventually consistent; retry the send+check round trip.
    fixed_delivery = _poll_until(
        _send_and_check, lambda d: d is not None, timeout_s=60, interval_s=5.0,
        description="delivery after adding the queue policy",
    )
    assert fixed_delivery["id"] == marker2, (
        f"expected marker {marker2!r} once the queue policy allows delivery, got {fixed_delivery!r}"
    )


def _poll_for_marker(ctx, queue_url: str, marker: str, *, timeout_s: float):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            detail = body.get("detail", {})
            if detail.get("id") == marker:
                return detail
        time.sleep(1)
    return None


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if hasattr(template, "read_text") else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
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
