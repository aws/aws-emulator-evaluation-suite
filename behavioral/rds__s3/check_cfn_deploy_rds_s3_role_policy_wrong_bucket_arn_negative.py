"""cfn-deploy-rds-s3-role-policy-wrong-bucket-arn-negative."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-s3-role-policy-wrong-bucket-arn-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask to a bucket outside the export role's S3 policy is rejected with
    IamRoleMissingPermissions and writes nothing there, while the same role and snapshot export to
    the allowed bucket completes with objects."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    cluster_id = _xname(ctx, "cluster")
    role_name = _xname(ctx, "role")
    allowed_bucket = _xname(ctx, "bucket-ok")
    wrong_bucket = _xname(ctx, "bucket-wrong")
    password = _admin_password(ctx)

    result = _deploy_cfn(
        ctx,
        _WRONG_BUCKET_TEMPLATE,
        parameters={
            "ClusterId": cluster_id,
            "RoleName": role_name,
            "AllowedBucketName": allowed_bucket,
            "WrongBucketName": wrong_bucket,
            "MasterUserPassword": password,
        },
        timeout_s=900.0,
    )
    role_arn = result["outputs"]["RoleArn"]
    key_arn = result["outputs"]["KmsKeyArn"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, allowed_bucket))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, wrong_bucket))

    snapshot_id = _xname(ctx, "snap")
    rds.create_db_cluster_snapshot(
        DBClusterSnapshotIdentifier=snapshot_id,
        DBClusterIdentifier=cluster_id,
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snapshot_id)
    )
    snapshot_arn = _poll_snapshot_available(ctx, snapshot_id, timeout_s=1200.0)

    # --- negative: export to the bucket the role's policy does NOT cover ---
    wrong_export_id = _xname(ctx, "export-wrong")
    code, message = _error(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=wrong_export_id,
            SourceArn=snapshot_arn,
            S3BucketName=wrong_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=key_arn,
            S3Prefix="export-data",
        )
    )
    assert code == "IamRoleMissingPermissions", f"expected IamRoleMissingPermissions, got {code!r}"
    expected_message = (
        f"The IAM role {role_arn} isn't authorized to call s3:GetBucketLocation on the S3 bucket "
        f"{wrong_bucket}."
    )
    assert message == expected_message, (
        f"expected StartExportTask refusal message {expected_message!r}, got {message!r}"
    )

    listing = s3.list_objects_v2(Bucket=wrong_bucket)
    assert listing.get("KeyCount", 0) == 0, "no export ran, but the wrong bucket has objects"

    # --- positive control (same file, same role/snapshot): export to the allowed bucket ---
    good_export_id = _xname(ctx, "export-ok")
    rds.start_export_task(
        ExportTaskIdentifier=good_export_id,
        SourceArn=snapshot_arn,
        S3BucketName=allowed_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
        S3Prefix="export-data",
    )
    final = _poll_export_task(ctx, good_export_id, timeout_s=2400.0)
    assert final["Status"] == "COMPLETE", (
        f"expected control export task COMPLETE, got {final['Status']!r} "
        f"(FailureCause={final.get('FailureCause')!r})"
    )
    good_listing = s3.list_objects_v2(Bucket=allowed_bucket, Prefix="export-data")
    assert good_listing.get("KeyCount", 0) > 0, "control export completed but wrote no objects"


_WRONG_BUCKET_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  RoleName:
    Type: String
  AllowedBucketName:
    Type: String
  WrongBucketName:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  AllowedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref AllowedBucketName
  WrongBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref WrongBucketName
  ExportKmsKey:
    Type: AWS::KMS::Key
    Properties:
      Description: sim2real rds export key (wrong bucket negative)
      KeyPolicy:
        Version: '2012-10-17'
        Statement:
          - Sid: EnableRootAccount
            Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::${AWS::AccountId}:root'
            Action: 'kms:*'
            Resource: '*'
          - Sid: AllowExportService
            Effect: Allow
            Principal:
              Service: export.rds.amazonaws.com
            Action:
              - kms:CreateGrant
              - kms:DescribeKey
            Resource: '*'
  ExportRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - rds.amazonaws.com
                - export.rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3ExportAccessAllowedBucketOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:PutObject*
                  - s3:GetObject*
                  - s3:ListBucket
                  - s3:DeleteObject*
                  - s3:GetBucketLocation
                Resource:
                  - !Sub 'arn:aws:s3:::${AllowedBucketName}'
                  - !Sub 'arn:aws:s3:::${AllowedBucketName}/*'
  ClusterVpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.196.0.0/24
  ClusterSubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref ClusterVpc
      CidrBlock: 10.196.0.0/28
      AvailabilityZone: !Select [0, !GetAZs '']
  ClusterSubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref ClusterVpc
      CidrBlock: 10.196.0.16/28
      AvailabilityZone: !Select [1, !GetAZs '']
  ClusterSubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: sim2real wrong-bucket negative subnet group
      SubnetIds:
        - !Ref ClusterSubnetA
        - !Ref ClusterSubnetB
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-mysql
      DBSubnetGroupName: !Ref ClusterSubnetGroup
      MasterUsername: admin
      MasterUserPassword: !Ref MasterUserPassword
Outputs:
  RoleArn:
    Value: !GetAtt ExportRole.Arn
  KmsKeyArn:
    Value: !GetAtt ExportKmsKey.Arn
"""


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
        timeout_s=1200,
        interval_s=10.0,
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
        failed = [
            f"{e['LogicalResourceId']} ({e.get('ResourceStatus')}): {e.get('ResourceStatusReason')}"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if str(e.get("ResourceStatus", "")).endswith("FAILED")
        ]
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; failed resources: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _admin_password(ctx) -> str:
    suffix = ctx.unique_name("pw").split("-")[-1]
    return f"S2r{suffix}Aa1"


def _poll_snapshot_available(ctx, snapshot_id: str, *, timeout_s: float = 1200.0) -> str:
    rds = ctx.client("rds")

    def _probe():
        return rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snapshot_id)[
            "DBClusterSnapshots"
        ][0]

    snap = _poll_until(
        _probe,
        lambda s: s["Status"] in {"available", "failed"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"cluster snapshot {snapshot_id} available",
    )
    assert snap["Status"] == "available", f"snapshot ended in status {snap['Status']!r}"
    return snap["DBClusterSnapshotArn"]


def _poll_export_task(ctx, export_id: str, *, timeout_s: float = 2400.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def _probe():
        return rds.describe_export_tasks(ExportTaskIdentifier=export_id)["ExportTasks"][0]

    return _poll_until(
        _probe,
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=timeout_s,
        interval_s=20.0,
        description=f"export task {export_id} reach terminal status",
    )


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
