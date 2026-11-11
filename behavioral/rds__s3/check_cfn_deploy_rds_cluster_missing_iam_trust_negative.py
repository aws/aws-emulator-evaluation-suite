"""cfn-deploy-rds-cluster-missing-iam-trust-negative."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-rds-cluster-missing-iam-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """Of two CFN-created roles with the same S3 policy, AddRoleToDBCluster(s3Import) on an Aurora PostgreSQL
    cluster accepts the one trusting rds.amazonaws.com, which settles ACTIVE, and refuses the one trusting
    ec2.amazonaws.com with InvalidParameterValue on every retry for at least 3x the good role's propagation lag."""
    cluster_id = _xname(ctx, "cluster")
    good_role_name = _xname(ctx, "good-role")
    bad_role_name = _xname(ctx, "bad-role")
    password = _master_password(ctx)

    result = _deploy_cfn(
        ctx,
        _MIXED_TRUST_TEMPLATE,
        parameters={
            "ClusterId": cluster_id,
            "GoodRoleName": good_role_name,
            "BadRoleName": bad_role_name,
            "MasterUserPassword": password,
        },
        timeout_s=900.0,
    )
    good_role_arn = result["outputs"]["GoodRoleArn"]
    bad_role_arn = result["outputs"]["BadRoleArn"]

    rds = ctx.client("rds")

    good_latency_s = _add_role_until_accepted(rds, cluster_id, good_role_arn, "s3Import")
    ctx.on_cleanup(lambda: _remove_role(rds, cluster_id, good_role_arn, "s3Import"))
    good_status = _poll_role_status(ctx, cluster_id, good_role_arn, timeout_s=600.0)
    # Positive control (same cluster): the correctly-trusted role does activate.
    assert good_status == "ACTIVE", f"expected correctly-trusted role ACTIVE, got {good_status!r}"

    # Negative: hold for >=3x the measured propagation-lag latency before trusting the
    # rejection as real and not a slower repeat of the same lag the positive control hit.
    _assert_add_role_never_accepted(rds, cluster_id, bad_role_arn, "s3Import", timeout_s=max(120.0, 3 * good_latency_s))
    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    associated_arns = {r["RoleArn"] for r in cluster.get("AssociatedRoles", [])}
    assert bad_role_arn not in associated_arns, "mistrusted role should never appear in AssociatedRoles"


_MIXED_TRUST_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  GoodRoleName:
    Type: String
  BadRoleName:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  GoodTrustRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref GoodRoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-import-export-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub "${DataBucket.Arn}/*"
  BadTrustRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref BadRoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-import-export-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub "${DataBucket.Arn}/*"
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-postgresql
      MasterUsername: dbadmin
      MasterUserPassword: !Ref MasterUserPassword
Outputs:
  GoodRoleArn:
    Value: !GetAtt GoodTrustRole.Arn
  BadRoleArn:
    Value: !GetAtt BadTrustRole.Arn
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
        reasons = [
            f"{e['LogicalResourceId']}({e.get('ResourceStatus')}): {e.get('ResourceStatusReason')}"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if e.get("ResourceStatus", "").endswith("FAILED")
        ]
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _master_password(ctx) -> str:
    suffix = ctx.unique_name("pw").split("-")[-1]
    return f"S2r{suffix}Aa1"


def _add_role_until_accepted(rds, cluster_id: str, role_arn: str, feature_name: str, *, timeout_s: float = 120.0) -> float:
    """Retries AddRoleToDBCluster through the IAM/RDS cross-service propagation lag on a
    brand-new role (InvalidParameterValue / AWS_ROLE_INTEGRATION) and returns how many
    seconds acceptance actually took, so the negative can be held for a multiple of it."""
    start = time.monotonic()
    deadline = start + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)
            return time.monotonic() - start
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last = exc
            time.sleep(5.0)
    raise AssertionError(f"add_role_to_db_cluster kept rejecting {role_arn} within {timeout_s}s: {last}")


def _assert_add_role_never_accepted(rds, cluster_id: str, role_arn: str, feature_name: str, *, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            rds.add_role_to_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)
            raise AssertionError(
                f"add_role_to_db_cluster with a mistrusted role unexpectedly succeeded after {attempts} attempt(s)"
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            assert code == "InvalidParameterValue", f"expected InvalidParameterValue for a mistrusted role, got {code}: {exc}"
            message = exc.response["Error"].get("Message", "")
            assert message == (
                "IAM role ARN value is invalid or does not include the required permissions for: "
                "AWS_ROLE_INTEGRATION"
            ), f"unexpected InvalidParameterValue message for a mistrusted role: {message!r}"
            time.sleep(5.0)


def _remove_role(rds, cluster_id: str, role_arn: str, feature_name: str) -> None:
    try:
        rds.remove_role_from_db_cluster(DBClusterIdentifier=cluster_id, RoleArn=role_arn, FeatureName=feature_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("DBClusterNotFoundFault", "DBClusterRoleNotFound"):
            raise


def _poll_role_status(ctx, cluster_id: str, role_arn: str, *, timeout_s: float = 600.0) -> str:
    rds = ctx.client("rds")

    def _probe():
        cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        for role in cluster["AssociatedRoles"]:
            if role["RoleArn"] == role_arn:
                return role["Status"]
        return "MISSING"

    return _poll_until(
        _probe,
        lambda s: s in {"ACTIVE", "INVALID"},
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"associated role {role_arn} reach terminal status",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
