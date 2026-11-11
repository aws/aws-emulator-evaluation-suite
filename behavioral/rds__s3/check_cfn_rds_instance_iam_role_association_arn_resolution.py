"""cfn-rds-instance-iam-role-association-arn-resolution."""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-instance-iam-role-association-arn-resolution"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: RDS PostgreSQL instance with an AssociatedRoles entry pointing at an IAM S3-import role.
Parameters:
  BucketName:
    Type: String
  DbInstanceIdentifier:
    Type: String
  DbMasterPassword:
    Type: String
    NoEcho: true
Resources:
  ImportBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  ImportRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: RdsS3ImportAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt ImportBucket.Arn
                  - !Sub "${ImportBucket.Arn}/*"
  DbInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: !Ref DbInstanceIdentifier
      Engine: postgres
      DBInstanceClass: db.t3.micro
      AllocatedStorage: "20"
      MasterUsername: postgres
      MasterUserPassword: !Ref DbMasterPassword
      BackupRetentionPeriod: 1
      PubliclyAccessible: false
      AssociatedRoles:
        - FeatureName: s3Import
          RoleArn: !GetAtt ImportRole.Arn
Outputs:
  BucketName:
    Value: !Ref ImportBucket
  RoleArn:
    Value: !GetAtt ImportRole.Arn
  DbInstanceId:
    Value: !Ref DbInstance
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed DBInstance's AssociatedRoles entry resolves to the exact ARN of the
    IAM role the same stack created for S3 access (not a stale/placeholder/truncated value)."""
    rds = ctx.client("rds")

    bucket_name = _xname(ctx, "assoc-bkt")
    db_id = _xname(ctx, "assoc-db")
    password = "Sim2Real" + secrets.token_hex(8)

    deployed = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "BucketName": bucket_name,
            "DbInstanceIdentifier": db_id,
            "DbMasterPassword": password,
        },
        timeout_s=1800,
    )
    expected_role_arn = deployed["outputs"]["RoleArn"]

    instance = _wait_association_active(rds, db_id)
    roles = instance.get("AssociatedRoles", [])
    assert len(roles) == 1, f"expected exactly one associated role, got {roles!r}"
    assert roles[0]["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import', got {roles[0]['FeatureName']!r}"
    )
    assert roles[0]["RoleArn"] == expected_role_arn, (
        f"AssociatedRoles ARN {roles[0]['RoleArn']!r} does not match the role CFN created "
        f"{expected_role_arn!r}"
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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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


def _wait_association_active(rds, db_id: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]

    def _settled(inst: dict[str, Any]) -> bool:
        if inst["DBInstanceStatus"] != "available":
            return False
        roles = inst.get("AssociatedRoles", [])
        return bool(roles) and all(r.get("Status") != "PENDING" for r in roles)

    instance = _poll_until(
        _probe,
        _settled,
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"DB instance {db_id} available with a settled (non-PENDING) associated role",
    )
    roles = instance.get("AssociatedRoles", [])
    assert roles and all(r.get("Status") == "ACTIVE" for r in roles), (
        f"expected associated role(s) to settle ACTIVE, got {roles!r}"
    )
    return instance


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
