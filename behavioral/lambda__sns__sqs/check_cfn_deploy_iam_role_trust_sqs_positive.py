"""cfn-deploy-iam-role-trust-sqs-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trust-sqs-positive"
GROUP = "deploy-trust"
SERVICES = ["lambda", "sns", "sqs"]


# timing:real-time — visibility: 3 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stack-deployed role's trust policy keeps sqs.amazonaws.com, and the stack's redrive policy
    moves a message that exceeds maxReceiveCount to the allowed dead-letter queue, leaving the
    source empty."""
    ctx.client("sts").get_caller_identity()["Account"]
    dlq_name = _xname(ctx, "dlq")
    src_name = _xname(ctx, "src")
    template = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  DlqName:
    Type: String
  SrcName:
    Type: String
Resources:
  OpsRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: sqs.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: redrive-ops
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - sqs:StartMessageMoveTask
                  - sqs:ListMessageMoveTasks
                  - sqs:ListQueues
                Resource: "*"
  Dlq:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref DlqName
      RedriveAllowPolicy:
        redrivePermission: allowAll
  SrcQueue:
    Type: AWS::SQS::Queue
    DependsOn: Dlq
    Properties:
      QueueName: !Ref SrcName
      VisibilityTimeout: 3
      RedrivePolicy:
        deadLetterTargetArn: !GetAtt Dlq.Arn
        maxReceiveCount: 1
Outputs:
  RoleArn:
    Value: !GetAtt OpsRole.Arn
  RoleName:
    Value: !Ref OpsRole
  DlqUrl:
    Value: !Ref Dlq
  SrcUrl:
    Value: !Ref SrcQueue
"""
    result = _deploy_cfn(ctx, template, parameters={"DlqName": dlq_name, "SrcName": src_name})
    outputs = result["outputs"]

    # 1. Control-plane correctness: the trust document IAM stored really names sqs.amazonaws.com.
    iam = ctx.client("iam")
    role = iam.get_role(RoleName=outputs["RoleName"])["Role"]
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    principals = [s["Principal"].get("Service") for s in statements]
    assert "sqs.amazonaws.com" in principals, (
        f"expected sqs.amazonaws.com among trust principals, got {principals!r}"
    )

    # 2. Data-plane depth: drive a real DLQ redrive transition end to end.
    sqs = ctx.client("sqs")
    src_url = outputs["SrcUrl"]
    dlq_url = outputs["DlqUrl"]
    body = ctx.unique_name("redrive-payload-")
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # First delivery: consume without deleting (simulated processing failure) -> ReceiveCount=1.
    first = _poll_until(
        lambda: sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30.0,
        interval_s=2.0,
        description="first delivery of redrive test message",
    )
    assert first[0]["Body"] == body, f"expected first delivery body {body!r}, got {first[0]['Body']!r}"

    # Second delivery attempt exceeds maxReceiveCount=1, so SQS diverts it to the DLQ instead of
    # returning it from the source queue. The move only happens once VisibilityTimeout=3s (set
    # above) has actually elapsed and the source queue is polled again (SQS does not proactively
    # move it in the background) -- the retry cadence below (interval_s=3.0) both waits out that
    # window and re-polls the source (to trigger the move) while checking the DLQ for it.
    def _poll_src_and_check_dlq():
        sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
        return sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])

    dlq_messages = _poll_until(
        _poll_src_and_check_dlq,
        lambda msgs: len(msgs) > 0,
        timeout_s=60.0,
        interval_s=3.0,
        description="message moved to DLQ after exceeding maxReceiveCount",
    )

    assert dlq_messages[0]["Body"] == body, (
        f"expected redriven body {body!r} on the DLQ, got {dlq_messages[0]['Body']!r}"
    )
    sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=dlq_messages[0]["ReceiptHandle"])

    # The source queue must no longer hold the message.
    remaining = sqs.receive_message(QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get("Messages", [])
    assert remaining == [], f"expected source queue empty after redrive, still has {remaining!r}"


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
