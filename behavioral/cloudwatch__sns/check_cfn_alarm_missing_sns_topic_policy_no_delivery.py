"""cfn-alarm-missing-sns-topic-policy-no-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-alarm-missing-sns-topic-policy-no-delivery"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:negative-delivery", "cap:c7", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed alarm whose topic policy omits Publish never delivers its ALARM notification,
    while an identical control stack with the default topic policy, driven to ALARM after it, does."""
    good_topic = _xname(ctx, "topic-ok")
    good_queue = _xname(ctx, "queue-ok")
    good_alarm = _xname(ctx, "alarm-ok")
    good_template = _build_template(good_topic, good_queue, good_alarm, restrict_topic_policy=False)
    good_stack = _deploy_cfn(ctx, good_template)

    bad_topic = _xname(ctx, "topic-bad")
    bad_queue = _xname(ctx, "queue-bad")
    bad_alarm = _xname(ctx, "alarm-bad")
    bad_template = _build_template(bad_topic, bad_queue, bad_alarm, restrict_topic_policy=True)
    bad_stack = _deploy_cfn(ctx, bad_template)

    cloudwatch = ctx.client("cloudwatch")
    # The control is driven AFTER the denied alarm, so its delivery is the barrier for the absence.
    cloudwatch.set_alarm_state(AlarmName=bad_alarm, StateValue="ALARM", StateReason="negative: no publish permission")
    cloudwatch.set_alarm_state(AlarmName=good_alarm, StateValue="ALARM", StateReason="positive control")

    control_start = time.monotonic()
    good_envelope = _poll_for_notification(ctx, good_stack["outputs"]["QueueUrl"], timeout_s=90.0)
    control_s = time.monotonic() - control_start
    assert good_envelope is not None, "positive control: expected the notification to be delivered"
    good_payload = json.loads(good_envelope["Message"])
    assert good_payload["AlarmName"] == good_alarm, (
        f"expected notification for {good_alarm!r}, got AlarmName={good_payload.get('AlarmName')!r}"
    )
    assert good_payload["NewStateValue"] == "ALARM", (
        f"expected NewStateValue='ALARM', got {good_payload.get('NewStateValue')!r}"
    )

    # Independent pipeline: hold an absence window of at least 60 s (longer if the control was slower).
    bad_envelope = _poll_for_notification(
        ctx, bad_stack["outputs"]["QueueUrl"], timeout_s=max(60.0, control_s), wait_s=1
    )
    assert bad_envelope is None, (
        "expected NO delivery when the SNS topic's access policy omits Publish permission"
    )


# ===== helpers =====
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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
    template_body = template
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


def _build_template(topic_name: str, queue_name: str, alarm_name: str, *, restrict_topic_policy: bool) -> str:
    resources: dict[str, Any] = {
        "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name, "Tags": _xsvc_tags_kv()}},
        "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name, "Tags": _xsvc_tags_kv()}},
        "Subscription": {
            "Type": "AWS::SNS::Subscription",
            "Properties": {
                "TopicArn": {"Ref": "Topic"},
                "Protocol": "sqs",
                "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
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
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                            "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                        }
                    ],
                },
            },
        },
        "Alarm": {
            "Type": "AWS::CloudWatch::Alarm",
            "Properties": {
                "AlarmName": alarm_name,
                "Namespace": "sim2real/behavioral",
                "MetricName": "check",
                "Statistic": "Average",
                "Period": 60,
                "EvaluationPeriods": 1,
                "Threshold": 1,
                "ComparisonOperator": "GreaterThanThreshold",
                "TreatMissingData": "notBreaching",
                "AlarmActions": [{"Ref": "Topic"}],
                "Tags": _xsvc_tags_kv(),
            },
        },
    }
    if restrict_topic_policy:
        resources["TopicPolicy"] = {
            "Type": "AWS::SNS::TopicPolicy",
            "Properties": {
                "Topics": [{"Ref": "Topic"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SubscribeOnlyNoPublish",
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": ["SNS:Subscribe", "SNS:Receive", "SNS:GetTopicAttributes"],
                            "Resource": {"Ref": "Topic"},
                        }
                    ],
                },
            },
        }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "TopicArn": {"Value": {"Ref": "Topic"}},
        },
    }
    return json.dumps(template)


def _poll_for_notification(ctx, queue_url: str, *, timeout_s: float = 90.0, interval_s: float = 1.0, wait_s: int = 5):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envelope = _next_notification(sqs, queue_url, wait_s=wait_s)
        if envelope is not None:
            return envelope
        time.sleep(interval_s)
    return None


def _next_notification(sqs, queue_url: str, *, wait_s: int):
    """One long-poll receive: delete what arrived and return the first JSON envelope, else None."""
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    for msg in resp.get("Messages", []):
        try:
            envelope = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            envelope = None
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if envelope is not None:
            return envelope
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
