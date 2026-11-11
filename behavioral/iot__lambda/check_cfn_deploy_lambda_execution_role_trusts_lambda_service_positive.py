"""cfn-deploy-lambda-execution-role-trusts-lambda-service-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-execution-role-trusts-lambda-service-positive"
GROUP = "iam-trust"
SERVICES = ["iot", "lambda"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  FunctionName:
    Type: String
  RoleName:
    Type: String
Resources:
  LambdaLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub "/aws/lambda/${FunctionName}"
      RetentionInDays: 1
  LambdaExecRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: logs-write
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !GetAtt LambdaLogGroup.Arn
        - PolicyName: iot-read
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - iot:DescribeEndpoint
                Resource: "*"
  LambdaFunction:
    Type: AWS::Lambda::Function
    DependsOn: LambdaLogGroup
    Properties:
      FunctionName: !Ref FunctionName
      Role: !GetAtt LambdaExecRole.Arn
      Handler: index.handler
      Runtime: python3.12
      Timeout: 15
      Code:
        ZipFile: |
          import json
          import boto3
          def handler(event, context):
              iot = boto3.client("iot")
              resp = iot.describe_endpoint(endpointType="iot:Data-ATS")
              return {"ok": True, "endpointAddress": resp["endpointAddress"]}
Outputs:
  RoleNameOut:
    Value: !Ref RoleName
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """The deployed execution role's AssumeRolePolicyDocument trusts lambda.amazonaws.com (so
    the Lambda service can actually assume it to run the function) and the function's attached
    policy lets it successfully call an IoT API at runtime."""
    function_name = _xname(ctx, "fn")
    role_name = _xname(ctx, "role")

    _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"FunctionName": function_name, "RoleName": role_name},
    )

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly 1 trust statement, got {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected Allow, got {stmt['Effect']!r}"
    assert stmt["Principal"]["Service"] == "lambda.amazonaws.com", (
        f"expected trust principal lambda.amazonaws.com, got {stmt['Principal']!r}"
    )
    assert stmt["Action"] == "sts:AssumeRole", f"expected sts:AssumeRole, got {stmt['Action']!r}"

    lam = ctx.client("lambda")
    invoke_resp = lam.invoke(
        FunctionName=function_name, InvocationType="RequestResponse", Payload=b"{}"
    )
    assert invoke_resp["StatusCode"] == 200, f"expected StatusCode 200, got {invoke_resp!r}"
    assert "FunctionError" not in invoke_resp, (
        f"execution role could not assume/run: {invoke_resp.get('FunctionError')!r}"
    )
    payload = json.loads(invoke_resp["Payload"].read())
    assert payload["ok"] is True, f"handler did not report ok: {payload!r}"

    # Independent read at the destination: the account's own IoT endpoint, fetched directly,
    # must match what the execution role's IAM permission let the running function see.
    expected_endpoint = ctx.client("iot").describe_endpoint(endpointType="iot:Data-ATS")[
        "endpointAddress"
    ]
    assert payload["endpointAddress"] == expected_endpoint, (
        f"execution role's IoT call diverged: lambda saw {payload.get('endpointAddress')!r}, "
        f"direct call saw {expected_endpoint!r}"
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
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

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
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
