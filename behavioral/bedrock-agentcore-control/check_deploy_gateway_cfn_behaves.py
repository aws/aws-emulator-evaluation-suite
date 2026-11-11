"""deploy-gateway-cfn-behaves."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-gateway-cfn-behaves"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]

_LAMBDA_CODE = """
def handler(event, context):
    return {"greeting": "hello from sim2real gateway target"}
"""

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  LambdaExecRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  TargetFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: '__FUNCTION_NAME__'
      Runtime: python3.12
      Handler: index.handler
      Role: !GetAtt LambdaExecRole.Arn
      Timeout: 10
      Code:
        ZipFile: |
__LAMBDA_CODE_INDENTED__
  GatewayRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock-agentcore.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sim2real-gateway-invoke-lambda
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: lambda:InvokeFunction
                Resource: !GetAtt TargetFunction.Arn
  Gateway:
    Type: AWS::BedrockAgentCore::Gateway
    Properties:
      Name: '__GATEWAY_NAME__'
      RoleArn: !GetAtt GatewayRole.Arn
      AuthorizerType: AWS_IAM
  GatewayTarget:
    Type: AWS::BedrockAgentCore::GatewayTarget
    Properties:
      GatewayIdentifier: !Ref Gateway
      Name: '__TARGET_NAME__'
      TargetConfiguration:
        Mcp:
          Lambda:
            LambdaArn: !GetAtt TargetFunction.Arn
            ToolSchema:
              InlinePayload:
                - Name: sim2realGreet
                  Description: Returns a static greeting for gateway routing validation.
                  InputSchema:
                    Type: object
                    Properties: {}
      CredentialProviderConfigurations:
        - CredentialProviderType: GATEWAY_IAM_ROLE
Outputs:
  GatewayId:
    Value: !Ref Gateway
  TargetId:
    Value: !GetAtt GatewayTarget.TargetId
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CloudFormation-deployed Gateway+Lambda target reaches READY, not merely CREATE_COMPLETE."""
    control = ctx.client("bedrock-agentcore-control")
    cfn = ctx.client("cloudformation")

    function_name = _alnum_name(ctx, "sim2realCfnFn")
    gateway_name = _alnum_name(ctx, "sim2realcfngw")
    target_name = _alnum_name(ctx, "sim2realcfntgt")

    indented_code = "\n".join(f"          {line}" for line in _LAMBDA_CODE.strip("\n").splitlines())
    template_body = (
        _TEMPLATE.replace("__FUNCTION_NAME__", function_name)
        .replace("__LAMBDA_CODE_INDENTED__", indented_code)
        .replace("__GATEWAY_NAME__", gateway_name)
        .replace("__TARGET_NAME__", target_name)
    )

    stack_name = _deploy_cfn(ctx, cfn, template_body)
    outputs = _stack_outputs(cfn, stack_name)
    gateway_id = outputs["GatewayId"]
    target_id = outputs["TargetId"]

    gw_ready = _poll_until(
        lambda: control.get_gateway(gatewayIdentifier=gateway_id),
        lambda r: r["status"] == "READY",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert gw_ready["name"] == gateway_name, (
        f"expected CFN-deployed gateway name {gateway_name!r}, got {gw_ready['name']!r}"
    )

    target_ready = _poll_until(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id),
        lambda r: r["status"] == "READY",
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert target_ready["status"] == "READY", (
        f"expected target {target_id} status READY, got {target_ready['status']!r}: "
        f"{target_ready.get('statusReasons')}"
    )
    assert target_ready["name"] == target_name, (
        f"expected CFN-deployed target name {target_name!r}, got {target_ready['name']!r}"
    )

    listing = control.list_gateway_targets(gatewayIdentifier=gateway_id)["items"]
    assert any(item["targetId"] == target_id for item in listing), (
        f"expected target {target_id} in list_gateway_targets, got {[i['targetId'] for i in listing]}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    gw_code, gw_message = _error(lambda: control.get_gateway(gatewayIdentifier=gateway_id))
    assert gw_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted gateway {gateway_id}, got {gw_code!r}"
    )
    expected_gw = (
        "Failed to retrieve gateway because it doesn't exist. "
        "Retry the request with a different resource identifier."
    )
    assert gw_message == expected_gw, f"expected message {expected_gw!r}, got {gw_message!r}"

    target_code, target_message = _error(
        lambda: control.get_gateway_target(gatewayIdentifier=gateway_id, targetId=target_id)
    )
    assert target_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted target {target_id}, got {target_code!r}"
    )
    # The parent gateway is gone too, so the target read is refused with the gateway's message.
    assert target_message == expected_gw, f"expected message {expected_gw!r}, got {target_message!r}"


# ===== helpers =====
def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "-")


def _deploy_cfn(ctx, cfn, template_body: str) -> str:
    stack_name = ctx.unique_name("sim2real-gateway-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _destroy_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )
    return stack_name


def _destroy_stack(cfn, stack_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        cfn.delete_stack(StackName=stack_name)
        # Bounded by the cleanup budget the runner gives all teardowns together.
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except ClientError as exc:
        if not (
            (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
        ):
            raise


def _stack_outputs(cfn, stack_name: str) -> dict:
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
