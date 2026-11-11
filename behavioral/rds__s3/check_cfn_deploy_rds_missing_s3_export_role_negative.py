"""cfn-deploy-rds-missing-s3-export-role-negative."""
from __future__ import annotations

import secrets
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-missing-s3-export-role-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: RDS instance + S3 bucket + KMS key + a permission-less IAM role (bad) and a
  correctly-permissioned IAM role (good), both trusting export.rds.amazonaws.com.
Parameters:
  BucketName:
    Type: String
  DbInstanceIdentifier:
    Type: String
  DbAdminPassword:
    Type: String
    NoEcho: true
Resources:
  ExportBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  ExportKmsKey:
    Type: AWS::KMS::Key
    Properties:
      Description: Key for RDS snapshot export to S3
      KeyPolicy:
        Version: "2012-10-17"
        Statement:
          - Sid: EnableRootAccess
            Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: "kms:*"
            Resource: "*"
  BadRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: export.rds.amazonaws.com
            Action: sts:AssumeRole
      # Deliberately no Policies/ManagedPolicyArns at all: trust is correct, S3/KMS access is not.
  GoodRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: export.rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: RdsS3ExportAccess
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - s3:PutObject*
                  - s3:GetObject*
                  - s3:ListBucket
                  - s3:DeleteObject*
                  - s3:GetBucketLocation
                Resource:
                  - !GetAtt ExportBucket.Arn
                  - !Sub "${ExportBucket.Arn}/*"
              - Effect: Allow
                Action:
                  - kms:Encrypt
                  - kms:Decrypt
                  - kms:GenerateDataKey*
                  - kms:DescribeKey
                Resource: !GetAtt ExportKmsKey.Arn
  DbInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: !Ref DbInstanceIdentifier
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: "20"
      MasterUsername: admin
      MasterUserPassword: !Ref DbAdminPassword
      BackupRetentionPeriod: 1
      PubliclyAccessible: false
Outputs:
  BucketName:
    Value: !Ref ExportBucket
  KmsKeyArn:
    Value: !GetAtt ExportKmsKey.Arn
  BadRoleArn:
    Value: !GetAtt BadRole.Arn
  GoodRoleArn:
    Value: !GetAtt GoodRole.Arn
  DbInstanceId:
    Value: !Ref DbInstance
"""


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a role that has the right trust but no S3/KMS permissions is rejected with
    IamRoleMissingPermissions, creates no task and writes nothing, while a permitted role exports the
    same snapshot to COMPLETE with objects."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket_name = _xname(ctx, "noperm-bkt")
    db_id = _xname(ctx, "noperm-db")
    password = "Sim2Real" + secrets.token_hex(8)

    deployed = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "BucketName": bucket_name,
            "DbInstanceIdentifier": db_id,
            "DbAdminPassword": password,
        },
        timeout_s=1800,
    )
    bad_role_arn = deployed["outputs"]["BadRoleArn"]
    good_role_arn = deployed["outputs"]["GoodRoleArn"]
    kms_arn = deployed["outputs"]["KmsKeyArn"]

    _wait_db_instance_available(rds, db_id)

    snapshot_id = _xname(ctx, "noperm-snap")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=db_id, Tags=_xsvc_tags_kv()
    )
    ctx.on_cleanup(lambda: _delete_snapshot_quiet(rds, snapshot_id))
    snapshot = _wait_snapshot_available(rds, snapshot_id)
    snapshot_arn = snapshot["DBSnapshotArn"]
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_name))

    # 1. Break exactly one thing: export with the role that has no S3/KMS permissions.
    #    Real AWS validates the role's S3/KMS access SYNCHRONOUSLY at StartExportTask
    #    submission time -- the call itself raises IamRoleMissingPermissions and no export
    #    task is ever created for this identifier.
    bad_task_id = _xname(ctx, "bad-export")
    code, message = _client_error(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_task_id,
            SourceArn=snapshot_arn,
            S3BucketName=bucket_name,
            IamRoleArn=bad_role_arn,
            KmsKeyId=kms_arn,
            S3Prefix="bad-export",
        )
    )
    assert code == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions for a role with no attached S3/KMS policy, got {code!r}"
    )
    assert message == (
        f"The IAM role {bad_role_arn} isn't authorized to call s3:GetBucketLocation on the "
        f"S3 bucket {bucket_name}."
    ), f"unexpected IamRoleMissingPermissions message: {message!r}"
    all_ids = {t["ExportTaskIdentifier"] for t in rds.describe_export_tasks().get("ExportTasks", [])}
    assert bad_task_id not in all_ids, (
        f"start_export_task was rejected synchronously yet created task {bad_task_id}"
    )
    bad_objs = s3.list_objects_v2(Bucket=bucket_name, Prefix="bad-export")
    assert bad_objs.get("KeyCount", 0) == 0, "objects were delivered to S3 despite a permission-less export role"

    # 2. Positive control in the same file, same snapshot: the correctly-permissioned role succeeds.
    good_task_id = _xname(ctx, "good-export")
    rds.start_export_task(
        ExportTaskIdentifier=good_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket_name,
        IamRoleArn=good_role_arn,
        KmsKeyId=kms_arn,
        S3Prefix="good-export",
    )
    good_task = _wait_export_task_terminal(rds, good_task_id)
    assert good_task["Status"] == "COMPLETE", f"expected COMPLETE with a properly-permissioned role, got {good_task['Status']}"
    good_objs = s3.list_objects_v2(Bucket=bucket_name, Prefix="good-export")
    assert good_objs.get("KeyCount", 0) > 0, "properly-permissioned export did not deliver any objects"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, but the call succeeded")


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
        timeout_s=900,
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


def _wait_db_instance_available(rds, db_id: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]

    return _poll_until(
        _probe,
        lambda inst: inst["DBInstanceStatus"] == "available",
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"DB instance {db_id} available",
    )


def _wait_snapshot_available(rds, snapshot_id: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]

    return _poll_until(
        _probe,
        lambda snap: snap["Status"] == "available",
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"snapshot {snapshot_id} available",
    )


def _wait_export_task_terminal(rds, task_id: str, timeout_s: float = 1800.0) -> dict[str, Any]:
    def _probe():
        return rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]

    return _poll_until(
        _probe,
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"export task {task_id} terminal",
    )


def _delete_snapshot_quiet(rds, snapshot_id: str) -> None:
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _empty_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
