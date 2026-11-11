"""cfn-deploy-rds-cluster-inline-s3-import-role-negative."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-cluster-inline-s3-import-role-negative"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack with an inline s3Import AssociatedRoles entry on an aurora-mysql DBCluster fails with a
    reason naming s3Import as not valid for Aurora MySQL and leaves no cluster, while the same stack
    without the entry creates an available cluster."""
    cluster_id = _xname(ctx, "cluster")
    role_name = _xname(ctx, "role")
    bucket_name = _xname(ctx, "bucket")
    password = _admin_password(ctx)

    control = _deploy_cfn(
        ctx,
        _NO_ROLE_TEMPLATE,
        parameters={
            "ClusterId": cluster_id,
            "RoleName": role_name,
            "BucketName": bucket_name,
            "MasterUserPassword": password,
        },
        timeout_s=900.0,
    )
    role_arn = control["outputs"]["RoleArn"]

    control_cluster = ctx.client("rds").describe_db_clusters(DBClusterIdentifier=cluster_id)[
        "DBClusters"
    ][0]
    assert control_cluster["Status"] == "available", (
        f"positive control: expected cluster {cluster_id} available, got "
        f"{control_cluster['Status']!r}"
    )

    rejected_cluster_id = _xname(ctx, "cluster-inline")
    try:
        _deploy_cfn(
            ctx,
            _INLINE_ROLE_TEMPLATE,
            parameters={
                "ClusterId": rejected_cluster_id,
                "RoleArn": role_arn,
                "MasterUserPassword": password,
            },
            timeout_s=300.0,
        )
    except AssertionError as e:
        detail = str(e)
        assert "s3Import" in detail and "not valid for the Aurora MySQL" in detail, (
            "expected the inline-AssociatedRoles create to fail with the "
            f"'s3Import ... not valid for the Aurora MySQL' error, got: {detail}"
        )
    else:
        raise AssertionError(
            "expected CloudFormation to reject an inline AssociatedRoles entry on "
            "AWS::RDS::DBCluster for aurora-mysql, but the stack reached CREATE_COMPLETE"
        )

    try:
        ctx.client("rds").describe_db_clusters(DBClusterIdentifier=rejected_cluster_id)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "DBClusterNotFoundFault", (
            f"expected DBClusterNotFoundFault for the never-created {rejected_cluster_id!r}, "
            f"got {code!r}"
        )
        message = e.response["Error"].get("Message")
        assert message == f"DBCluster {rejected_cluster_id} not found.", message
    else:
        raise AssertionError(
            f"expected {rejected_cluster_id!r} to not exist, but describe_db_clusters returned it"
        )


_NO_ROLE_TEMPLATE = """
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
  ImportBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Ref BucketName
  S3ImportRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: S3ImportAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:ListBucket
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
    Value: !GetAtt S3ImportRole.Arn
"""


_INLINE_ROLE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  RoleArn:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-mysql
      MasterUsername: admin
      MasterUserPassword: !Ref MasterUserPassword
      AssociatedRoles:
        - FeatureName: s3Import
          RoleArn: !Ref RoleArn
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

    # A stack that owns an Aurora cluster takes minutes to delete; the deadline sits inside
    # budget.cleanup_timeout for behavioral/rds__s3 (1800 s).
    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=1500,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended DELETE_FAILED")


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
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if e["ResourceStatus"] in {"CREATE_FAILED", "ROLLBACK_IN_PROGRESS"} and e.get("ResourceStatusReason")
        ]
        raise AssertionError(
            f"expected stack {name} CREATE_COMPLETE, got {stack['StackStatus']}: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _admin_password(ctx) -> str:
    suffix = ctx.unique_name("pw").split("-")[-1]
    return f"S2r{suffix}Aa1"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
