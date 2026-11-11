"""cfn-deploy-sns-sqs-lambda-full-pipeline-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sns-sqs-lambda-full-pipeline-positive"
GROUP = "deploy-pipeline"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring SNS -> SQS -> Lambda (ESM) carries a publish through every hop: the function
    unwraps the SNS envelope and forwards the inner message to a second queue, where it is read."""
    topic_name = _xname(ctx, "pipetopic")
    in_queue_name = _xname(ctx, "pipein")
    out_queue_name = _xname(ctx, "pipeout")
    fn_name = _xname(ctx, "pipefn")
    template = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  TopicName: {Type: String}
  InQueueName: {Type: String}
  OutQueueName: {Type: String}
  FunctionName: {Type: String}
Resources:
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref TopicName
  InQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref InQueueName
      VisibilityTimeout: 30
  OutQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref OutQueueName
  InQueuePolicy:
    Type: AWS::SQS::QueuePolicy
    Properties:
      Queues: [!Ref InQueue]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: sns.amazonaws.com}
            Action: sqs:SendMessage
            Resource: !GetAtt InQueue.Arn
            Condition:
              ArnEquals: {"aws:SourceArn": !Ref Topic}
  Subscription:
    Type: AWS::SNS::Subscription
    DependsOn: InQueuePolicy
    Properties:
      TopicArn: !Ref Topic
      Protocol: sqs
      Endpoint: !GetAtt InQueue.Arn
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
      Policies:
        - PolicyName: pipeline-access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: [sqs:ReceiveMessage, sqs:DeleteMessage, sqs:GetQueueAttributes]
                Resource: !GetAtt InQueue.Arn
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !GetAtt OutQueue.Arn
  Fn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt ExecRole.Arn
      Timeout: 20
      Environment:
        Variables:
          OUTPUT_QUEUE_URL: !Ref OutQueue
      Code:
        ZipFile: |
          import json, os, boto3
          sqs = boto3.client("sqs")
          def handler(event, context):
              out_url = os.environ["OUTPUT_QUEUE_URL"]
              for record in event.get("Records", []):
                  envelope = json.loads(record["body"])
                  inner = envelope.get("Message", envelope) if isinstance(envelope, dict) else envelope
                  sqs.send_message(QueueUrl=out_url, MessageBody=f"{inner}-processed")
              return {"handled": len(event.get("Records", []))}
  Esm:
    Type: AWS::Lambda::EventSourceMapping
    Properties:
      EventSourceArn: !GetAtt InQueue.Arn
      FunctionName: !Ref Fn
      BatchSize: 1
Outputs:
  TopicArn: {Value: !Ref Topic}
  OutQueueUrl: {Value: !Ref OutQueue}
"""
    result = _deploy_cfn(
        ctx,
        template,
        parameters={
            "TopicName": topic_name,
            "InQueueName": in_queue_name,
            "OutQueueName": out_queue_name,
            "FunctionName": fn_name,
        },
    )
    outputs = result["outputs"]
    topic_arn = outputs["TopicArn"]
    out_queue_url = outputs["OutQueueUrl"]

    sqs = ctx.client("sqs")
    sns = ctx.client("sns")
    marker = ctx.unique_name("pipeline-msg-")
    sns.publish(TopicArn=topic_arn, Message=marker)

    delivered = _poll_until(
        lambda: sqs.receive_message(QueueUrl=out_queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=120.0,
        interval_s=5.0,
        description="message forwarded through SNS->SQS->Lambda->SQS pipeline",
    )
    actual_body = delivered[0]["Body"]
    expected_body = f"{marker}-processed"
    assert actual_body == expected_body, (
        f"expected the Lambda-forwarded message body {expected_body!r} on the output queue, "
        f"got {actual_body!r}"
    )
    sqs.delete_message(QueueUrl=out_queue_url, ReceiptHandle=delivered[0]["ReceiptHandle"])


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
