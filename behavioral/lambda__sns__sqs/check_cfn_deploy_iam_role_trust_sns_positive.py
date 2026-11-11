"""cfn-deploy-iam-role-trust-sns-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trust-sns-positive"
GROUP = "deploy-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """SNS assumes a CFN-deployed role trusting sns.amazonaws.com: with SQS delivery-status logging at
    100% sampling, a publish delivered to a subscribed queue yields SNS's own delivery-status log.

    Reference: https://docs.aws.amazon.com/sns/latest/dg/topics-attrib-prereq.html"""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    topic_name = _xname(ctx, "fbtopic")
    template = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  TopicName:
    Type: String
Resources:
  FeedbackRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sns.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sns-delivery-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "arn:aws:logs:*:*:*"
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref TopicName
      DeliveryStatusLogging:
        - Protocol: sqs
          SuccessFeedbackRoleArn: !GetAtt FeedbackRole.Arn
          SuccessFeedbackSampleRate: "100"
Outputs:
  TopicArn:
    Value: !Ref Topic
  RoleArn:
    Value: !GetAtt FeedbackRole.Arn
"""
    result = _deploy_cfn(ctx, template, parameters={"TopicName": topic_name})
    topic_arn = result["outputs"]["TopicArn"]

    sqs = ctx.client("sqs")
    queue_name = _xname(ctx, "fbqueue")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    sns = ctx.client("sns")
    sub_arn = sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)["SubscriptionArn"]
    ctx.on_cleanup(lambda: sns.unsubscribe(SubscriptionArn=sub_arn))

    marker = ctx.unique_name("feedback-marker-")
    publish_resp = sns.publish(TopicArn=topic_arn, Message=marker)
    message_id = publish_resp["MessageId"]

    # Delivery is confirmed via the actual SQS delivery (proves the pipe works), and the
    # delivered body is matched back to this exact publish by SNS's own MessageId — not
    # merely "some message arrived" — so a stale or foreign message can't satisfy this.
    delivered = _poll_until(
        lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=60.0,
        interval_s=3.0,
        description="message delivered to subscriber queue",
    )
    delivered_body = json.loads(delivered[0]["Body"])
    assert delivered_body.get("MessageId") == message_id, (
        f"expected delivered SQS body to carry MessageId {message_id!r}, got {delivered_body.get('MessageId')!r}"
    )
    assert delivered_body.get("Message") == marker, (
        f"expected delivered SQS body Message {marker!r}, got {delivered_body.get('Message')!r}"
    )

    # ...and the trust policy's real effect is confirmed by SNS's own delivery-status log entry,
    # which only exists if SNS successfully assumed FeedbackRole to write it.
    logs = ctx.client("logs")
    # Documented naming convention for SNS delivery-status log groups.
    log_group_name = f"sns/{ctx.region}/{account_id}/{topic_name}"

    def _find_success_event():
        try:
            groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
        except ClientError:
            groups = []
        if not groups:
            return None
        streams = logs.describe_log_streams(logGroupName=log_group_name, orderBy="LastEventTime", descending=True)["logStreams"]
        for stream in streams:
            events = logs.get_log_events(logGroupName=log_group_name, logStreamName=stream["logStreamName"], limit=50)["events"]
            for event in events:
                try:
                    body = json.loads(event["message"])
                except (json.JSONDecodeError, ValueError):
                    continue
                # The delivery-status log's "notification" object carries only a timestamp and
                # the SNS-assigned messageId (never the message body) — match on that, per the
                # documented log shape (sns-msg-status.html).
                if body.get("status") == "SUCCESS" and body.get("notification", {}).get("messageId") == message_id:
                    return body
        return None

    # SNS delivery-status CloudWatch log entries are not written synchronously with the
    # publish; AWS documents no SLA and in practice the first log group/stream can take
    # several minutes to appear, so this uses a long, generous poll window.
    found = _poll_until(
        _find_success_event,
        lambda b: b is not None,
        timeout_s=480.0,
        interval_s=15.0,
        description=f"SUCCESS delivery-status log event in {log_group_name}",
    )
    assert found["status"] == "SUCCESS"
    assert found["delivery"]["destination"] == queue_arn


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
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
