"""cfn-deploy-cloudwatch-alarm-sns-topic."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-cloudwatch-alarm-sns-topic"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack deploying a metric alarm with AlarmActions -> SNS topic (subscribed by an
    SQS queue, also provisioned in the stack) delivers the real state-change notification to the
    queue once the alarm is driven to ALARM after the stack reaches CREATE_COMPLETE."""
    topic_name = _xname(ctx, "topic")
    queue_name = _xname(ctx, "queue")
    alarm_name = _xname(ctx, "alarm")
    template = _build_template(topic_name, queue_name, alarm_name, restrict_topic_policy=False)

    stack = _deploy_cfn(ctx, template)
    queue_url = stack["outputs"]["QueueUrl"]
    topic_arn = stack["outputs"]["TopicArn"]

    cloudwatch = ctx.client("cloudwatch")
    cloudwatch.set_alarm_state(
        AlarmName=alarm_name, StateValue="ALARM", StateReason="sim2real behavioral trigger"
    )

    envelope = _poll_for_notification(ctx, queue_url, timeout_s=90.0)
    assert envelope is not None, "expected an SNS notification after the alarm went to ALARM"
    assert envelope["Type"] == "Notification", f"expected an SNS Notification envelope, got Type={envelope.get('Type')!r}"
    assert envelope["TopicArn"] == topic_arn, f"expected notification from {topic_arn!r}, got TopicArn={envelope.get('TopicArn')!r}"
    payload = json.loads(envelope["Message"])
    assert payload["AlarmName"] == alarm_name, f"expected notification for {alarm_name!r}, got AlarmName={payload.get('AlarmName')!r}"
    assert payload["NewStateValue"] == "ALARM", f"expected NewStateValue='ALARM', got {payload.get('NewStateValue')!r}"
    assert payload["OldStateValue"] in ("INSUFFICIENT_DATA", "OK"), (
        f"expected OldStateValue in ('INSUFFICIENT_DATA', 'OK'), got {payload.get('OldStateValue')!r}"
    )


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
    """A CFN template: SQS queue subscribed to an SNS topic, and a metric alarm whose
    AlarmActions targets that topic. When restrict_topic_policy is True the topic's access
    policy is overridden to grant only Subscribe/Receive (no Publish), simulating a topic
    that lacks the permission CloudWatch needs to deliver notifications."""
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


def _poll_for_notification(ctx, queue_url: str, *, timeout_s: float = 90.0, interval_s: float = 3.0):
    """Poll an SQS queue for one SNS notification envelope; return None if none arrives."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        for msg in messages:
            try:
                envelope = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                envelope = None
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if envelope is not None:
                return envelope
        if not messages:
            time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
