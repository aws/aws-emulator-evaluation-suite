"""deploy-code-interpreter-custom-resource-executes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-code-interpreter-custom-resource-executes"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  CiName:
    Type: String
Resources:
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: bedrock-agentcore.amazonaws.com
            Action: sts:AssumeRole
  CustomCodeInterpreter:
    Type: AWS::BedrockAgentCore::CodeInterpreterCustom
    Properties:
      Name: !Ref CiName
      ExecutionRoleArn: !GetAtt ExecutionRole.Arn
      NetworkConfiguration:
        NetworkMode: PUBLIC
Outputs:
  CodeInterpreterArn:
    Value: !Ref CustomCodeInterpreter
  CodeInterpreterId:
    Value: !GetAtt CustomCodeInterpreter.CodeInterpreterId
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "cap:c6", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::BedrockAgentCore::CodeInterpreterCustom resource is a working
    code interpreter once the stack reports CREATE_COMPLETE: it starts a session and executes code
    that prints a per-run marker.
    """
    cfn = ctx.client("cloudformation")
    ci_client = ctx.client("bedrock-agentcore")

    stack_name = ctx.unique_name("sim2real-ci-stack-")
    ci_name = ctx.unique_name("Sim2RealCI")[:48].replace("-", "")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "CiName", "ParameterValue": ci_name}],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    outputs = _wait_for_stack_complete(cfn, stack_name, timeout_s=300.0)
    code_interpreter_arn = outputs["CodeInterpreterArn"]

    session_id = ci_client.start_code_interpreter_session(
        codeInterpreterIdentifier=code_interpreter_arn,
    )["sessionId"]
    ctx.on_cleanup(lambda: ci_client.stop_code_interpreter_session(
        codeInterpreterIdentifier=code_interpreter_arn, sessionId=session_id))

    marker = ctx.unique_name("sim2real-ci-cfn-")
    resp = ci_client.invoke_code_interpreter(
        codeInterpreterIdentifier=code_interpreter_arn,
        sessionId=session_id,
        name="executeCode",
        arguments={"language": "python", "code": f"print('{marker}')"},
    )
    text_parts = []
    is_error = False
    for event in resp["stream"]:
        result = event.get("result")
        if not result:
            continue
        if result.get("isError"):
            is_error = True
        for block in result.get("content") or []:
            if block.get("text"):
                text_parts.append(block["text"])
        structured = result.get("structuredContent") or {}
        if structured.get("stdout"):
            text_parts.append(structured["stdout"])
    output = "\n".join(text_parts)

    assert not is_error, output
    assert marker in output, (
        f"the CloudFormation-deployed code interpreter did not actually execute the submitted "
        f"code (expected {marker!r} in output, got {output!r})"
    )


def _wait_for_stack_complete(cfn, stack_name, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = stack["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        if status in ("CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS"):
            raise AssertionError(f"stack {stack_name} failed to create: status={status!r}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached CREATE_COMPLETE (last status={status!r})")


def _delete_stack(cfn, stack_name, timeout_s=300.0, interval_s=10.0):
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return
        status = stack["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(
                f"teardown: stack {stack_name} DELETE_FAILED: {stack.get('StackStatusReason')!r}"
            )
        time.sleep(interval_s)
    raise AssertionError(f"teardown: stack {stack_name} still {status!r} after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
