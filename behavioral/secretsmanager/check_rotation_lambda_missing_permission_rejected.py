"""rotation-lambda-missing-permission-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags


CHECK = "rotation-lambda-missing-permission-rejected"
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


_LAMBDA_BLOCK = _indent(_LAMBDA_SRC, 10)

_TEMPLATE = f"""
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  GoodRole:
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
  GoodFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt GoodRole.Arn
      Timeout: 30
      Code:
        ZipFile: |
{_LAMBDA_BLOCK}
  GoodPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref GoodFunction
      Action: lambda:InvokeFunction
      Principal: secretsmanager.amazonaws.com
  GoodSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString:
        PasswordLength: 24
  GoodSchedule:
    Type: AWS::SecretsManager::RotationSchedule
    DependsOn: GoodPermission
    Properties:
      SecretId: !Ref GoodSecret
      RotationLambdaARN: !GetAtt GoodFunction.Arn
      RotationRules:
        AutomaticallyAfterDays: 30
  BadRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {{Service: lambda.amazonaws.com}}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: logs-only-policy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: '*'
  BadFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt BadRole.Arn
      Timeout: 30
      Code:
        ZipFile: |
{_LAMBDA_BLOCK}
  BadPermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !Ref BadFunction
      Action: lambda:InvokeFunction
      Principal: secretsmanager.amazonaws.com
  BadSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      GenerateSecretString:
        PasswordLength: 24
  BadSchedule:
    Type: AWS::SecretsManager::RotationSchedule
    DependsOn: BadPermission
    Properties:
      SecretId: !Ref BadSecret
      RotationLambdaARN: !GetAtt BadFunction.Arn
      RotationRules:
        AutomaticallyAfterDays: 30
Outputs:
  GoodSecretArn:
    Value: !Ref GoodSecret
  BadSecretArn:
    Value: !Ref BadSecret
  GoodFunctionName:
    Value: !Ref GoodFunction
  BadFunctionName:
    Value: !Ref BadFunction
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A rotation Lambda whose role lacks secretsmanager permissions logs AccessDeniedException and
    leaves AWSCURRENT unchanged after RotateSecret, while a sibling secret wired to a permitted
    Lambda rotates; both are deployed by one CloudFormation stack."""
    stack_name = ctx.unique_name("sim2real-sm-rotperm-")
    # Lambda creates each function's log group on first invocation and the stack never owns it;
    # registered before the stack's own teardown, so LIFO cleanup removes the groups after it.
    function_names: list[str] = []
    ctx.on_cleanup(lambda: _delete_function_log_groups(ctx, function_names))
    outputs = _deploy_stack(ctx, _TEMPLATE, stack_name)
    function_names.extend([outputs["GoodFunctionName"], outputs["BadFunctionName"]])
    good_arn = outputs["GoodSecretArn"]
    bad_arn = outputs["BadSecretArn"]
    bad_fn_name = outputs["BadFunctionName"]

    sm = ctx.client("secretsmanager")
    logs = ctx.client("logs")

    good_before = sm.describe_secret(SecretId=good_arn)
    good_v1 = [v for v, s in good_before["VersionIdsToStages"].items() if "AWSCURRENT" in s][0]
    bad_before = sm.describe_secret(SecretId=bad_arn)
    bad_v1 = [v for v, s in bad_before["VersionIdsToStages"].items() if "AWSCURRENT" in s][0]

    _rotate_with_retry(ctx, good_arn)
    good_after = _poll_until(
        lambda: sm.describe_secret(SecretId=good_arn),
        lambda d: any("AWSCURRENT" in s and v != good_v1 for v, s in d["VersionIdsToStages"].items()),
        timeout_s=180.0,
        interval_s=5.0,
    )
    good_new = [v for v, s in good_after["VersionIdsToStages"].items() if "AWSCURRENT" in s][0]
    assert good_new != good_v1, (
        f"positive control did not rotate: AWSCURRENT is still {good_new!r} (was {good_v1!r})"
    )

    _rotate_with_retry(ctx, bad_arn)
    log_group = f"/aws/lambda/{bad_fn_name}"
    found = _poll_until(
        lambda: _search_logs(logs, log_group, "AccessDeniedException"),
        lambda hit: hit is True,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert found is True, (
        f"no AccessDeniedException was logged in {log_group} within the poll window — the "
        f"permission-starved rotation invocation's failure was never observed"
    )

    bad_after = sm.describe_secret(SecretId=bad_arn)
    stages_by_version = bad_after["VersionIdsToStages"]
    assert "AWSCURRENT" in stages_by_version[bad_v1], (
        f"AWSCURRENT moved off the original version {bad_v1!r} despite the rotation Lambda's "
        f"execution role lacking secretsmanager permissions: {stages_by_version!r}"
    )
    assert all(v == bad_v1 or "AWSCURRENT" not in s for v, s in stages_by_version.items()), (
        f"a version other than the original {bad_v1!r} carries AWSCURRENT: {stages_by_version!r}"
    )
    # The failed attempt may leave one empty AWSPENDING version; that is not a rotation.
    non_current_versions = [v for v in stages_by_version if v != bad_v1]
    assert len(non_current_versions) <= 1, (
        f"expected at most one leftover (AWSPENDING) version besides {bad_v1!r}, "
        f"found {non_current_versions!r}"
    )


def _deploy_stack(ctx, template_body: str, stack_name: str, timeout_minutes: int = 12) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(
        StackName=stack_name,
        WaiterConfig={"Delay": 2, "MaxAttempts": max(6, timeout_minutes * 6) * 10 // 2},
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return outputs


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
            # An earlier attempt that errored transiently may still have started the rotation;
            # "previous rotation isn't complete" means one is in flight, which is the goal.
            if code == "InvalidRequestException" and "previous rotation isn't complete" in message:
                return
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _delete_function_log_groups(ctx, function_names: list[str]) -> None:
    from botocore.exceptions import ClientError

    logs = ctx.client("logs")
    for name in function_names:
        try:
            logs.delete_log_group(logGroupName=f"/aws/lambda/{name}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


def _search_logs(logs_client, log_group: str, needle: str) -> bool:
    from botocore.exceptions import ClientError

    try:
        resp = logs_client.filter_log_events(logGroupName=log_group, filterPattern=f'"{needle}"')
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return False
        raise
    return len(resp.get("events", [])) > 0


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
