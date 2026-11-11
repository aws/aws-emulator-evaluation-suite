"""cfn-deploy-eventbridge-rule-sqs-target-with-policy."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-rule-sqs-target-with-policy"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "sqs"]


def _template(source: str, detail_type: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueNameParam": {"Type": "String"},
            "RuleNameParam": {"Type": "String"},
        },
        "Resources": {
            "TargetQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueNameParam"}},
            },
            "Rule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "RuleNameParam"},
                    "EventPattern": {"source": [source], "detail-type": [detail_type]},
                    "State": "ENABLED",
                    "Targets": [{"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["TargetQueue", "Arn"]}}],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "TargetQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                            "Condition": {
                                "ArnEquals": {"aws:SourceArn": {"Fn::GetAtt": ["Rule", "Arn"]}}
                            },
                        }],
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "TargetQueue"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["Rule", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation rule whose SQS target has a SourceArn-scoped queue policy delivers the
    matching event's raw envelope (detail, source, detail-type) and never delivers a
    non-matching one."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    source = _xname(ctx, "order-src")
    result = _deploy_cfn(
        ctx,
        _template(source, "OrderPlaced"),
        parameters={
            "QueueNameParam": _xname(ctx, "eb-sqs-q"),
            "RuleNameParam": _xname(ctx, "eb-sqs-rule"),
        },
    )
    queue_url = result["outputs"]["QueueUrl"]

    order_id = ctx.unique_name("order-")
    put_at = time.monotonic()
    events.put_events(Entries=[{
        "Source": source,
        "DetailType": "OrderPlaced",
        "Detail": json.dumps({"orderId": order_id}),
    }])

    matched = _poll_for_matching_event(ctx, queue_url, source, "OrderPlaced", timeout_s=60)
    assert matched is not None, "matching event was never delivered to the queue"
    delivery_latency_s = time.monotonic() - put_at
    assert matched["detail"]["orderId"] == order_id, (
        f"expected orderId {order_id!r}, got {matched['detail'].get('orderId')!r}"
    )
    assert matched["source"] == source, f"expected source {source!r}, got {matched['source']!r}"
    assert matched["detail-type"] == "OrderPlaced", (
        f"expected detail-type 'OrderPlaced', got {matched['detail-type']!r}"
    )

    # Absence window calibrated against this run's own observed delivery latency: a fixed window can
    # pass a correct-but-slower target as "blocked".
    absence_window_s = max(20.0, 3.0 * delivery_latency_s)
    events.put_events(Entries=[{
        "Source": source,
        "DetailType": "OrderCancelled",
        "Detail": json.dumps({"orderId": order_id}),
    }])
    mismatch = _poll_for_matching_event(
        ctx, queue_url, source, "OrderCancelled", timeout_s=absence_window_s
    )
    assert mismatch is None, f"mismatched event was unexpectedly delivered: {mismatch}"

    # Second, independent observable for the absence: the queue itself reports empty
    # (the poll above already drained and deleted every message it received).
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"expected queue to be empty after the withheld delivery, "
        f"got ApproximateNumberOfMessages={attrs['ApproximateNumberOfMessages']!r}"
    )


def _poll_for_matching_event(ctx, queue_url, source, detail_type, *, timeout_s):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            body = json.loads(msg["Body"])
            if body.get("source") == source and body.get("detail-type") == detail_type:
                return body
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
