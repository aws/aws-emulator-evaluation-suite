"""cfn-deploy-rds-cluster-s3-export-role-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-cluster-s3-export-role-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack-deployed role trusted by export.rds.amazonaws.com lets StartExportTask on an Aurora cluster
    snapshot complete and write objects, while AddRoleToDBCluster with s3Export is rejected with
    InvalidParameterValue and leaves AssociatedRoles empty."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    cluster_id = _xname(ctx, "cluster")
    role_name = _xname(ctx, "role")
    bucket_name = _xname(ctx, "bucket")
    password = _admin_password(ctx)

    result = _deploy_cfn(
        ctx,
        _EXPORT_TEMPLATE,
        parameters={
            "ClusterId": cluster_id,
            "RoleName": role_name,
            "BucketName": bucket_name,
            "MasterUserPassword": password,
        },
        timeout_s=900.0,
    )
    role_arn = result["outputs"]["RoleArn"]
    key_arn = result["outputs"]["KmsKeyArn"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

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

    export_id = _xname(ctx, "export")
    prefix = "export-data"
    rds.start_export_task(
        ExportTaskIdentifier=export_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket_name,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
        S3Prefix=prefix,
    )

    final = _poll_export_task(ctx, export_id, timeout_s=2400.0)
    assert final["Status"] == "COMPLETE", (
        f"expected export task COMPLETE, got {final['Status']!r} "
        f"(FailureCause={final.get('FailureCause')!r})"
    )

    listing = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    key_count = listing.get("KeyCount", 0)
    assert key_count > 0, (
        f"export task completed but wrote no objects to S3 under prefix {prefix!r} "
        f"(KeyCount={key_count})"
    )

    # The check's name promises an AssociatedRoles FeatureName=s3Export role, on a DB cluster.
    # That FeatureName belongs to Postgres's aws_s3 extension, not to MySQL/Aurora snapshot
    # export -- so assert the refusal is the real contract, derived from the account's own
    # reported engine capabilities rather than assumed.
    versions = rds.describe_db_engine_versions(Engine="aurora-mysql", IncludeAll=True)[
        "DBEngineVersions"
    ]
    capable_versions = [
        v["EngineVersion"] for v in versions if "s3Export" in v.get("SupportedFeatureNames", [])
    ]
    assert not capable_versions, (
        f"expected no Aurora MySQL engine version to report s3Export support, but "
        f"{capable_versions!r} do -- the AssociatedRoles refusal below may no longer hold"
    )

    error = _client_error(
        lambda: rds.add_role_to_db_cluster(
            DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName="s3Export"
        )
    )
    assert error.get("Code") == "InvalidParameterValue", (
        f"expected AddRoleToDBCluster(FeatureName='s3Export') on an Aurora MySQL cluster to be "
        f"rejected as InvalidParameterValue, got {error!r}"
    )
    assert error.get("Message") == (
        "IAM role ARN value is invalid or does not include the required permissions for: "
        "AWS_ROLE_INTEGRATION"
    ), f"unexpected InvalidParameterValue message for AddRoleToDBCluster(s3Export): {error!r}"

    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    assert cluster["AssociatedRoles"] == [], (
        f"AddRoleToDBCluster(FeatureName='s3Export') was refused, but the cluster shows a role "
        f"association anyway: {cluster['AssociatedRoles']!r}"
    )


_EXPORT_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  RoleName:
    Type: String
  BucketName:
    Type: String
  MasterUserPassword:
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
      Description: sim2real rds export key
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
              Service: export.rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3ExportAccess
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
                  - !Sub 'arn:aws:s3:::${BucketName}'
                  - !Sub 'arn:aws:s3:::${BucketName}/*'
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-mysql
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
        timeout_s=900,
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
            f"{e['LogicalResourceId']} ({e['ResourceStatus']}): {e.get('ResourceStatusReason', '')}"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; failed resources: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _client_error(fn) -> dict[str, Any]:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
