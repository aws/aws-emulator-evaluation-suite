"""cfn-cloudwatch-alarm-wrong-region-arn-no-delivery."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-cloudwatch-alarm-wrong-region-arn-no-delivery"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "sns"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack's alarm with a same-region topic Ref delivers its ALARM notification, while one whose
    AlarmActions names the topic's ARN in another region either fails at the Alarm resource or
    deploys and delivers nothing."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # A real, different AWS region is required here by construction: the check's whole subject is
    # a syntactically-valid SNS topic ARN that can never resolve because it names a region other
    # than ctx.region, so the literal is the region-mismatch under test, not a pinned target region.
    alt_region = "us-west-2" if ctx.region != "us-west-2" else "eu-west-1"

    good_topic = _xname(ctx, "topic-good")
    good_queue = _xname(ctx, "queue-good")
    good_alarm = _xname(ctx, "alarm-good")
    good_template = _build_template(good_topic, good_queue, good_alarm, action_arn={"Ref": "Topic"})
    good_stack = _deploy_cfn(ctx, good_template)

    cloudwatch = ctx.client("cloudwatch")
    cloudwatch.set_alarm_state(AlarmName=good_alarm, StateValue="ALARM", StateReason="same-region control")
    good_envelope = _poll_for_notification(ctx, good_stack["outputs"]["QueueUrl"], timeout_s=90.0)
    assert good_envelope is not None, "expected the same-region alarm's notification to be delivered"
    good_payload = json.loads(good_envelope["Message"])
    assert good_payload["AlarmName"] == good_alarm, (
        f"expected the delivered notification's AlarmName to be {good_alarm!r}, "
        f"got {good_payload.get('AlarmName')!r}"
    )

    bad_topic = _xname(ctx, "topic-bad")
    bad_queue = _xname(ctx, "queue-bad")
    bad_alarm = _xname(ctx, "alarm-bad")
    # A syntactically valid ARN for a topic of the same name/account but in a region where it
    # was never created -- deliberately NOT the local Topic's real ARN.
    wrong_region_arn = f"arn:aws:sns:{alt_region}:{account_id}:{bad_topic}"
    bad_template = _build_template(bad_topic, bad_queue, bad_alarm, action_arn=wrong_region_arn)

    bad_stack = _deploy_cfn(ctx, bad_template, allow_failure=True)
    if bad_stack["status"] != "CREATE_COMPLETE":
        # A deploy failure is only a confirmation of "no delivery" if the failure is actually about
        # the mismatched-region action ARN -- any other CREATE_FAILED (a name collision, a throttle,
        # an unrelated resource) is a real failure.
        assert bad_stack["failed_logical_id"] == "Alarm", (
            f"expected only the Alarm resource to fail create because of the mismatched-region "
            f"action ARN, but stack {bad_stack['stack_name']} ended in {bad_stack['status']!r} "
            f"with logical id {bad_stack['failed_logical_id']!r} failing "
            f"(reason: {bad_stack['failed_reason']!r})"
        )
        return

    # It deployed -- the alarm's action still can't reach a topic that only the local region's
    # queue is subscribed to. Confirm nothing shows up there, over a window matching the same-
    # region control's own observed delivery budget (90s) so a correct-but-slower target is not
    # mistaken for a blocked one.
    cloudwatch.set_alarm_state(AlarmName=bad_alarm, StateValue="ALARM", StateReason="mismatched-region ARN")
    bad_envelope = _poll_for_notification(ctx, bad_stack["outputs"]["QueueUrl"], timeout_s=90.0)
    assert bad_envelope is None, (
        f"expected the mismatched-region-ARN alarm's notification to never be delivered, got {bad_envelope!r}"
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
    allow_failure=False,
) -> dict[str, Any]:
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
    status = stack["StackStatus"]
    if status != "CREATE_COMPLETE":
        if not allow_failure:
            raise AssertionError(f"Stack {name} ended in {status}")
        failed_logical_id = None
        failed_reason = None
        events = list(reversed(cfn.describe_stack_events(StackName=name)["StackEvents"]))
        for event in events:
            if event["ResourceStatus"] == "CREATE_FAILED" and event.get("ResourceType") != "AWS::CloudFormation::Stack":
                failed_logical_id = event["LogicalResourceId"]
                failed_reason = event.get("ResourceStatusReason")
                break
        return {
            "stack_name": name,
            "stack_id": stack_id,
            "status": status,
            "outputs": {},
            "failed_logical_id": failed_logical_id,
            "failed_reason": failed_reason,
        }
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "status": status, "outputs": outputs}


def _build_template(topic_name: str, queue_name: str, alarm_name: str, *, action_arn) -> str:
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
                "AlarmActions": [action_arn],
                "Tags": _xsvc_tags_kv(),
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
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        messages = resp.get("Messages", [])
        for msg in messages:
            envelope = None
            try:
                raw = json.loads(msg["Body"])
                envelope = {"Message": raw["Message"]}
            except (json.JSONDecodeError, ValueError, KeyError, TypeError):
                pass
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if envelope is not None:
                return envelope
        if not messages:
            time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
