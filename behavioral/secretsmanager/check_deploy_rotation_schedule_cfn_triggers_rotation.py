"""deploy-rotation-schedule-cfn-triggers-rotation."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "deploy-rotation-schedule-cfn-triggers-rotation"
GROUP = "deploy"
SERVICES = ["secretsmanager"]

_LAMBDA_SRC = '''import boto3


def lambda_handler(event, context):
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]
    client = boto3.client("secretsmanager")
    metadata = client.describe_secret(SecretId=arn)
    if not metadata.get("RotationEnabled", False):
        raise ValueError("secret not enabled for rotation: " + arn)
    versions = metadata["VersionIdsToStages"]
    if token not in versions:
        raise ValueError("version has no stage: " + token)
    if "AWSCURRENT" in versions[token]:
        return
    if "AWSPENDING" not in versions[token]:
        raise ValueError("version not AWSPENDING: " + token)

    if step == "createSecret":
        try:
            client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        except client.exceptions.ResourceNotFoundException:
            new_value = client.get_random_password(ExcludeCharacters='"@/')["RandomPassword"]
            client.put_secret_value(
                SecretId=arn,
                ClientRequestToken=token,
                SecretString=new_value,
                VersionStages=["AWSPENDING"],
            )
    elif step == "setSecret":
        pass
    elif step == "testSecret":
        client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
    elif step == "finishSecret":
        current_version = None
        for version, stages in metadata["VersionIdsToStages"].items():
            if "AWSCURRENT" in stages:
                if version == token:
                    return
                current_version = version
                break
        client.update_secret_version_stage(
            SecretId=arn,
            VersionStage="AWSCURRENT",
            MoveToVersionId=token,
            RemoveFromVersionId=current_version,
        )
    else:
        raise ValueError("invalid step: " + step)
'''


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


_TEMPLATE = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  RotationRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {{Service: lambda.amazonaws.com}}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sm-rotate-policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: 'secretsmanager:*'
                Resource: '*'
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'
  RotationFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt RotationRole.Arn
      Timeout: 30
      Code:
        ZipFile: |
{_indent(_LAMBDA_SRC, 10)}
  InvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref RotationFunction
      Action: lambda:InvokeFunction
      Principal: secretsmanager.amazonaws.com
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString:
        PasswordLength: 24
  RotationSchedule:
    Type: AWS::SecretsManager::RotationSchedule
    DependsOn: InvokePermission
    Properties:
      SecretId: !Ref MySecret
      RotationLambdaARN: !GetAtt RotationFunction.Arn
      RotationRules:
        AutomaticallyAfterDays: 30
Outputs:
  SecretArn:
    Value: !Ref MySecret
  FunctionArn:
    Value: !GetAtt RotationFunction.Arn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed secret with an attached RotationSchedule and Lambda actually rotates
    on invocation, producing a new AWSCURRENT version distinct from the original one."""
    stack_name = ctx.unique_name("sim2real-sm-rotcfn-")
    outputs = _deploy_stack(ctx, _TEMPLATE, stack_name)
    secret_arn = outputs["SecretArn"]

    sm = ctx.client("secretsmanager")
    before = sm.describe_secret(SecretId=secret_arn)
    original_current = [v for v, stages in before["VersionIdsToStages"].items() if "AWSCURRENT" in stages][0]
    original_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]

    _rotate_with_retry(ctx, secret_arn)

    after = _poll_until(
        lambda: sm.describe_secret(SecretId=secret_arn),
        lambda d: any(
            "AWSCURRENT" in stages and version != original_current
            for version, stages in d["VersionIdsToStages"].items()
        ),
        timeout_s=180.0,
        interval_s=5.0,
    )
    new_current = [v for v, stages in after["VersionIdsToStages"].items() if "AWSCURRENT" in stages][0]
    assert new_current != original_current, (
        f"expected AWSCURRENT to move off version {original_current!r} once the CFN-deployed "
        f"rotation Lambda finished, but it is still {new_current!r}"
    )
    assert after.get("LastRotatedDate") is not None, (
        "expected DescribeSecret to report a LastRotatedDate once rotation completed, got None"
    )

    # Independent read, through GetSecretValue rather than DescribeSecret, proving the rotation
    # Lambda actually wrote new secret material -- not just that Secrets Manager relabeled a stage.
    new_value = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")["SecretString"]
    assert new_value != original_value, (
        "expected the CFN-deployed rotation Lambda to write a new secret value on AWSCURRENT, "
        "but the value is unchanged after rotation"
    )

    _delete_stack_and_verify(ctx, stack_name)


_SIM2REAL_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _deploy_stack(ctx, template_body: str, stack_name: str, timeout_minutes: int = 12) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
        Tags=_SIM2REAL_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: cfn.delete_stack(StackName=stack_name)))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(
        StackName=stack_name,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(6, timeout_minutes * 6) * 10 // 2},
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return outputs


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


def _stack_status(cfn, stack_name: str) -> str:
    from botocore.exceptions import ClientError

    try:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    except ClientError:
        return "GONE"


def _delete_stack_and_verify(ctx, stack_name: str) -> None:
    """Deletes the stack this check created and proves it is actually gone -- not just that the
    delete call was accepted -- via an independent DescribeStacks read."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda status: status in ("DELETE_COMPLETE", "GONE"),
        timeout_s=180.0,
        interval_s=5.0,
    )


def _rotate_with_retry(ctx, secret_arn: str, attempts: int = 6, delay_s: float = 5.0) -> None:
    from botocore.exceptions import ClientError

    sm = ctx.client("secretsmanager")
    last_exc = None
    for _ in range(attempts):
        try:
            sm.rotate_secret(SecretId=secret_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidRequestException" and "previous rotation isn't complete" in message:
                return
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
