"""deploy-cfn-rds-rotation-lambda-wiring."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-rotation-lambda-wiring"
GROUP = "deployment-order"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """RotateSecret on a stack-wired RDS secret runs its custom rotation Lambda end to end: a new
    version with a new password becomes current, LastRotatedDate is set and the original version
    loses AWSCURRENT."""
    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=1200.0)
    secret_arn = stack["outputs"]["SecretArn"]

    sm = ctx.client("secretsmanager")

    original = sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")
    original_version = original["VersionId"]
    original_password = _password(original["SecretString"])

    _rotate_with_retry(ctx, secret_arn)

    def _current():
        return sm.get_secret_value(SecretId=secret_arn, VersionStage="AWSCURRENT")

    rotated = _poll_until(
        _current,
        lambda r: r["VersionId"] != original_version,
        timeout_s=900.0,
        interval_s=10.0,
        description="secret rotation promotes a new AWSCURRENT version",
    )
    assert rotated["VersionId"] != original_version
    assert _password(rotated["SecretString"]) != original_password

    description = sm.describe_secret(SecretId=secret_arn)
    assert description.get("LastRotatedDate") is not None
    assert original_version not in description["VersionIdsToStages"] or (
        "AWSCURRENT" not in description["VersionIdsToStages"][original_version]
    )


def _password(secret_string: str) -> str:
    import json

    return json.loads(secret_string)["password"]


_TEMPLATE = r"""
AWSTemplateFormatVersion: "2010-09-09"
Description: sim2real rds secret rotation wired to a custom lambda rotation function
Resources:
  DbSecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Description: sim2real rds master credentials
      GenerateSecretString:
        SecretStringTemplate: '{"username":"dbadmin"}'
        GenerateStringKey: password
        ExcludeCharacters: '"@/'
        PasswordLength: 20
  DbInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: !Sub "{{resolve:secretsmanager:${DbSecret}:SecretString:username}}"
      MasterUserPassword: !Sub "{{resolve:secretsmanager:${DbSecret}:SecretString:password}}"
      PubliclyAccessible: false
      BackupRetentionPeriod: 0
      DeletionProtection: false
  SecretAttachment:
    Type: AWS::SecretsManager::SecretTargetAttachment
    Properties:
      SecretId: !Ref DbSecret
      TargetId: !Ref DbInstance
      TargetType: AWS::RDS::DBInstance
  RotationRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal: {Service: lambda.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - secretsmanager:GetSecretValue
                  - secretsmanager:PutSecretValue
                  - secretsmanager:UpdateSecretVersionStage
                  - secretsmanager:DescribeSecret
                Resource: !Ref DbSecret
              - Effect: Allow
                # GetRandomPassword has no resource-level permission support; IAM silently
                # denies it when scoped to a specific ARN, so it needs its own "*" statement.
                Action: secretsmanager:GetRandomPassword
                Resource: "*"
              - Effect: Allow
                Action:
                  - rds:ModifyDBInstance
                  - rds:DescribeDBInstances
                Resource: !Sub "arn:${AWS::Partition}:rds:${AWS::Region}:${AWS::AccountId}:db:${DbInstance}"
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
  RotationFn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.lambda_handler
      Role: !GetAtt RotationRole.Arn
      Timeout: 240
      Environment:
        Variables:
          DB_INSTANCE_IDENTIFIER: !Ref DbInstance
      Code:
        ZipFile: |
          import json, os, time, boto3

          def lambda_handler(event, context):
              service_client = boto3.client("secretsmanager")
              rds_client = boto3.client("rds")
              arn = event["SecretId"]
              token = event["ClientRequestToken"]
              step = event["Step"]

              metadata = service_client.describe_secret(SecretId=arn)
              if not metadata["RotationEnabled"]:
                  raise ValueError("rotation not enabled for %s" % arn)
              versions = metadata["VersionIdsToStages"]
              if token not in versions:
                  raise ValueError("no stage for token %s" % token)
              if "AWSCURRENT" in versions[token]:
                  return
              elif "AWSPENDING" not in versions[token]:
                  raise ValueError("token %s not pending" % token)

              if step == "createSecret":
                  current = service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
                  current_dict = json.loads(current["SecretString"])
                  try:
                      service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
                  except service_client.exceptions.ResourceNotFoundException:
                      new_password = service_client.get_random_password(ExcludeCharacters='"@/')["RandomPassword"]
                      current_dict["password"] = new_password
                      service_client.put_secret_value(
                          SecretId=arn, ClientRequestToken=token,
                          SecretString=json.dumps(current_dict), VersionStages=["AWSPENDING"])
              elif step == "setSecret":
                  pending = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
                  pending_dict = json.loads(pending["SecretString"])
                  db_id = os.environ["DB_INSTANCE_IDENTIFIER"]
                  rds_client.modify_db_instance(
                      DBInstanceIdentifier=db_id,
                      MasterUserPassword=pending_dict["password"],
                      ApplyImmediately=True,
                  )
              elif step == "testSecret":
                  db_id = os.environ["DB_INSTANCE_IDENTIFIER"]
                  for _ in range(20):
                      status = rds_client.describe_db_instances(
                          DBInstanceIdentifier=db_id
                      )["DBInstances"][0]["DBInstanceStatus"]
                      if status == "available":
                          break
                      time.sleep(10)
                  else:
                      raise ValueError("db instance %s did not return to available" % db_id)
              elif step == "finishSecret":
                  metadata = service_client.describe_secret(SecretId=arn)
                  current_version = None
                  for version, stages in metadata["VersionIdsToStages"].items():
                      if "AWSCURRENT" in stages:
                          if version == token:
                              return
                          current_version = version
                          break
                  service_client.update_secret_version_stage(
                      SecretId=arn, VersionStage="AWSCURRENT",
                      MoveToVersionId=token, RemoveFromVersionId=current_version)
              else:
                  raise ValueError("invalid step %s" % step)
  RotationPermission:
    Type: AWS::Lambda::Permission
    Properties:
      Action: lambda:InvokeFunction
      FunctionName: !Ref RotationFn
      Principal: secretsmanager.amazonaws.com
      SourceAccount: !Ref AWS::AccountId
  RotationSchedule:
    Type: AWS::SecretsManager::RotationSchedule
    DependsOn: RotationPermission
    Properties:
      SecretId: !Ref DbSecret
      RotationLambdaARN: !GetAtt RotationFn.Arn
      RotationRules:
        AutomaticallyAfterDays: 1
Outputs:
  SecretArn:
    Value: !Ref DbSecret
  DbInstanceId:
    Value: !Ref DbInstance
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


def _rotate_with_retry(
    ctx, secret_arn: str, attempts: int = 6, delay_s: float = 5.0
) -> None:
    """RotationSchedule's creation (RotateImmediatelyOnUpdate defaults to true) already kicks off
    a rotation as part of the CFN deploy; calling RotateSecret again right after can race that
    still-running rotation. Treat AWS's own "will be reattempted" answer as equivalent to having
    triggered one, since the in-flight rotation still promotes a new AWSCURRENT version, which the
    caller polls for."""
    sm = ctx.client("secretsmanager")
    last_exc = None
    for _ in range(attempts):
        try:
            sm.rotate_secret(SecretId=secret_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if (
                code == "InvalidRequestException"
                and "previous rotation isn't complete" in message
            ):
                return
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


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
