"""cli-cfn-deploy-stack-describe-resources-iam-lambda-positive."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-cfn-deploy-stack-describe-resources-iam-lambda-positive"
GROUP = "cli-roundtrip"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleName:
    Type: String
  FunctionName:
    Type: String
Resources:
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  EchoFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Ref FunctionName
      Runtime: python3.12
      Handler: index.handler
      Timeout: 10
      Role: !GetAtt ExecutionRole.Arn
      Code:
        ZipFile: |
          def handler(event, context):
              return {"echo": event.get("msg", "none")}
Outputs:
  RoleArn:
    Value: !GetAtt ExecutionRole.Arn
  FunctionArn:
    Value: !GetAtt EchoFunction.Arn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws cloudformation deploy followed by describe-stack-resources returns the correct IAM
    role and Lambda physical resource ids, and the deployed function is actually invokable."""
    require_tools("aws")

    stack_name = ctx.unique_name("sim2real-cfndeploy-")
    role_name = ctx.unique_name("sim2real-cfndeploy-role-")
    function_name = ctx.unique_name("sim2real-cfndeploy-fn-")

    template_fd, template_path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(template_fd, "w") as f:
        f.write(_TEMPLATE)

    # Registered BEFORE the deploy: a deploy that fails or times out part-way still leaves a
    # stack (and its role/function) behind. DeleteStack on a name that never existed is a no-op.
    ctx.on_cleanup(lambda: _run_shell(
        ctx, ["aws", "cloudformation", "delete-stack", "--stack-name", stack_name],
    ))
    try:
        _run_shell(
            ctx,
            [
                "aws", "cloudformation", "deploy",
                "--stack-name", stack_name,
                "--template-file", template_path,
                "--capabilities", "CAPABILITY_NAMED_IAM",
                "--parameter-overrides",
                f"RoleName={role_name}", f"FunctionName={function_name}",
                "--tags", "sim2real:managed=true", "sim2real:prefix=sim2real-cfndeploy",
            ],
            timeout_s=180,
        )
    finally:
        os.unlink(template_path)

    status = _run_aws(ctx, "cloudformation", "describe-stacks", "--stack-name", stack_name)
    stack_status = status["Stacks"][0]["StackStatus"]
    assert stack_status == "CREATE_COMPLETE", f"unexpected stack status: {stack_status}"

    resources = _run_aws(
        ctx, "cloudformation", "describe-stack-resources", "--stack-name", stack_name,
    )["StackResources"]
    role_resource = next(r for r in resources if r["LogicalResourceId"] == "ExecutionRole")
    fn_resource = next(r for r in resources if r["LogicalResourceId"] == "EchoFunction")

    assert role_resource["PhysicalResourceId"] == role_name, (
        f"expected role physical id {role_name!r}, got {role_resource['PhysicalResourceId']!r}"
    )
    assert fn_resource["PhysicalResourceId"] == function_name, (
        f"expected function physical id {function_name!r}, got {fn_resource['PhysicalResourceId']!r}"
    )
    assert role_resource["ResourceStatus"] == "CREATE_COMPLETE", (
        f"ExecutionRole resource status: {role_resource['ResourceStatus']!r}"
    )
    assert fn_resource["ResourceStatus"] == "CREATE_COMPLETE", (
        f"EchoFunction resource status: {fn_resource['ResourceStatus']!r}"
    )

    role = _run_aws(ctx, "iam", "get-role", "--role-name", role_resource["PhysicalResourceId"])
    fn_config = _run_aws(
        ctx, "lambda", "get-function-configuration",
        "--function-name", fn_resource["PhysicalResourceId"],
    )
    assert fn_config["Role"] == role["Role"]["Arn"], (
        "CFN-created function's Role does not match the CFN-created role's real ARN"
    )

    _poll_until(
        lambda: _run_aws(ctx, "lambda", "get-function-configuration",
                          "--function-name", function_name).get("State"),
        lambda state: state == "Active",
        timeout_s=60, interval_s=2,
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as pf:
        json.dump({"msg": "ping"}, pf)
        payload_path = pf.name
    out_path = payload_path + ".out"
    try:
        _run_aws(
            ctx, "lambda", "invoke",
            "--function-name", function_name,
            "--cli-binary-format", "raw-in-base64-out",
            "--payload", f"file://{payload_path}",
            out_path,
        )
        with open(out_path) as f:
            invoke_result = json.load(f)
        assert invoke_result == {"echo": "ping"}, f"unexpected invoke result: {invoke_result}"
    finally:
        os.unlink(payload_path)
        if os.path.exists(out_path):
            os.unlink(out_path)


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
