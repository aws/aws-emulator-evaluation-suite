"""cfn-deploy-lambda-execution-role-missing-sqs-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-lambda-execution-role-missing-sqs-permission-negative"
GROUP = "deploy-permission"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Lambda whose role lacks sqs:SendMessage gets AccessDenied from SQS and delivers
    nothing; a sibling function whose role grants it on the same queue delivers (positive control)."""
    queue_name = _xname(ctx, "permq")
    denied_fn = _xname(ctx, "fndenied")
    allowed_fn = _xname(ctx, "fnallowed")
    template = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  QueueName: {Type: String}
  DeniedFnName: {Type: String}
  AllowedFnName: {Type: String}
Resources:
  Queue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: !Ref QueueName
  DeniedRole:
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
  AllowedRole:
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
        - PolicyName: sqs-send
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: sqs:SendMessage
                Resource: !GetAtt Queue.Arn
  DeniedFn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref DeniedFnName
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt DeniedRole.Arn
      Timeout: 10
      Environment:
        Variables: {QUEUE_URL: !Ref Queue}
      Code:
        ZipFile: |
          import os, boto3
          from botocore.exceptions import ClientError
          def handler(event, context):
              sqs = boto3.client("sqs")
              try:
                  resp = sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody="ping")
                  return {"ok": True, "message_id": resp["MessageId"]}
              except ClientError as e:
                  return {"ok": False, "code": e.response["Error"]["Code"], "message": e.response["Error"]["Message"]}
  AllowedFn:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref AllowedFnName
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt AllowedRole.Arn
      Timeout: 10
      Environment:
        Variables: {QUEUE_URL: !Ref Queue}
      Code:
        ZipFile: |
          import os, boto3
          from botocore.exceptions import ClientError
          def handler(event, context):
              sqs = boto3.client("sqs")
              try:
                  resp = sqs.send_message(QueueUrl=os.environ["QUEUE_URL"], MessageBody="ping")
                  return {"ok": True, "message_id": resp["MessageId"]}
              except ClientError as e:
                  return {"ok": False, "code": e.response["Error"]["Code"], "message": e.response["Error"]["Message"]}
Outputs:
  QueueUrl: {Value: !Ref Queue}
  DeniedFnName: {Value: !Ref DeniedFn}
  AllowedFnName: {Value: !Ref AllowedFn}
"""
    result = _deploy_cfn(
        ctx,
        template,
        parameters={"QueueName": queue_name, "DeniedFnName": denied_fn, "AllowedFnName": allowed_fn},
    )
    outputs = result["outputs"]
    queue_url = outputs["QueueUrl"]
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    # --- Negative: missing sqs:SendMessage -> real AccessDenied, no delivery ---
    denied_payload = _poll_until(
        lambda: json.loads(lam.invoke(FunctionName=outputs["DeniedFnName"], Payload=b"{}")["Payload"].read()),
        lambda p: isinstance(p, dict) and "ok" in p,
        timeout_s=30.0,
        interval_s=3.0,
        description="denied function invocation completes",
    )
    assert denied_payload["ok"] is False
    assert denied_payload["code"] == "AccessDenied"
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    role_arn = lam.get_function_configuration(FunctionName=outputs["DeniedFnName"])["Role"]
    principal = (
        f"arn:aws:sts::{queue_arn.split(':')[4]}:assumed-role/{role_arn.rsplit('/', 1)[1]}/{outputs['DeniedFnName']}"
    )
    expected_message = (
        f"User: {principal} is not authorized to perform: sqs:sendmessage on resource: {queue_arn} "
        "because no identity-based policy allows the sqs:sendmessage action"
    )
    assert denied_payload["message"] == expected_message, (
        f"expected {expected_message!r}, got {denied_payload['message']!r}"
    )

    # Effect absent: nothing was ever enqueued because of the denied attempt.
    leaked = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=3).get("Messages", [])
    assert leaked == []

    # --- Positive control: identical code/queue, role additionally grants sqs:SendMessage ---
    allowed_payload = _poll_until(
        lambda: json.loads(lam.invoke(FunctionName=outputs["AllowedFnName"], Payload=b"{}")["Payload"].read()),
        lambda p: isinstance(p, dict) and "ok" in p,
        timeout_s=30.0,
        interval_s=3.0,
        description="allowed function invocation completes",
    )
    assert allowed_payload["ok"] is True
    assert "message_id" in allowed_payload

    delivered = _poll_until(
        lambda: sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30.0,
        interval_s=3.0,
        description="message delivered by the correctly-permissioned function",
    )
    assert delivered[0]["Body"] == "ping"
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=delivered[0]["ReceiptHandle"])


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
