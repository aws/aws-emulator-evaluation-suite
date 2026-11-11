"""deploy-cfn-lambda-rds-missing-permission-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-rds-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Of two Lambdas in one stack, the one whose role has no RDS permissions gets AccessDenied and no
    data from DescribeDBInstances, while the one with rds:DescribeDBInstances gets a count."""
    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=300.0)
    outputs = stack["outputs"]
    lambda_client = ctx.client("lambda")

    def _invoke(function_name: str) -> dict[str, Any]:
        resp = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        assert resp.get("FunctionError") is None, f"unexpected FunctionError: {resp}"
        return json.loads(resp["Payload"].read())

    denied = _invoke(outputs["FnNoRdsName"])
    assert denied["ok"] is False, f"expected the RDS call to be denied, got {denied!r}"
    assert denied["code"] == "AccessDenied", (
        f"expected error code AccessDenied for a role missing rds:DescribeDBInstances, "
        f"got {denied['code']!r}"
    )
    assert "count" not in denied, (
        f"no DB instance data should leak to a denied caller, got {denied!r}"
    )

    allowed = _invoke(outputs["FnWithRdsName"])
    assert allowed["ok"] is True, f"expected the positive control to succeed, got {allowed!r}"
    assert "count" in allowed, f"expected DB instance count in a successful response, got {allowed!r}"


_TEMPLATE = r"""
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real lambda role missing rds permissions (negative) vs a positive control
Resources:
  RoleNoRds:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: logs-only
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
  RoleWithRds:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: rds-describe-and-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: rds:DescribeDBInstances
                Resource: "*"
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
  FnNoRds:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt RoleNoRds.Arn
      Timeout: 15
      Code:
        ZipFile: |
          import boto3

          def handler(event, context):
              client = boto3.client("rds")
              try:
                  resp = client.describe_db_instances()
                  return {"ok": True, "count": len(resp["DBInstances"])}
              except Exception as e:
                  code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
                  return {"ok": False, "code": code}
  FnWithRds:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt RoleWithRds.Arn
      Timeout: 15
      Code:
        ZipFile: |
          import boto3

          def handler(event, context):
              client = boto3.client("rds")
              try:
                  resp = client.describe_db_instances()
                  return {"ok": True, "count": len(resp["DBInstances"])}
              except Exception as e:
                  code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
                  return {"ok": False, "code": code}
Outputs:
  FnNoRdsName:
    Value: !Ref FnNoRds
  FnWithRdsName:
    Value: !Ref FnWithRds
"""


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
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
