"""cfn-stack-update-rds-cluster-add-s3-role-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-rds-cluster-add-s3-role-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack update adding an s3Export AssociatedRoles entry to an aurora-mysql cluster fails with an
    "s3Export ... not valid" reason, adds no s3Export role, and the existing role stays ACTIVE."""
    cfn = ctx.client("cloudformation")
    rds = ctx.client("rds")

    valid_feature = _pick_valid_feature(rds)

    cluster_id = _xname(ctx, "cluster")
    role_a_name = _xname(ctx, "role-a")
    role_b_name = _xname(ctx, "role-b")
    password = _admin_password(ctx)

    result = _deploy_cfn(
        ctx,
        _INITIAL_TEMPLATE,
        parameters={
            "ClusterId": cluster_id,
            "RoleAName": role_a_name,
            "RoleAFeatureName": valid_feature,
            "MasterUserPassword": password,
        },
        timeout_s=900.0,
    )
    stack_name = result["stack_name"]
    role_a_arn = result["outputs"]["RoleAArn"]

    status_a_before = _poll_role_status(ctx, cluster_id, role_a_arn, timeout_s=600.0)
    assert status_a_before == "ACTIVE", (
        f"expected initial ({valid_feature}) role ACTIVE, got {status_a_before!r}"
    )

    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_UPDATED_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ClusterId", "ParameterValue": cluster_id},
            {"ParameterKey": "RoleAName", "ParameterValue": role_a_name},
            {"ParameterKey": "RoleAFeatureName", "ParameterValue": valid_feature},
            {"ParameterKey": "RoleBName", "ParameterValue": role_b_name},
            {"ParameterKey": "MasterUserPassword", "ParameterValue": password},
        ],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=600.0,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    assert final_status != "UPDATE_COMPLETE", (
        "expected the withdrawn s3Export AddRoleToDBCluster feature to reject the update, "
        "but it completed -- real AWS may have re-added support for it"
    )
    reason = _failure_reasons(cfn, stack_name)
    assert "s3Export" in reason and "not valid" in reason, (
        f"expected the rollback to name the withdrawn s3Export feature specifically, got: {reason!r}"
    )

    cluster = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
    roles_by_feature = {r["FeatureName"]: r for r in cluster.get("AssociatedRoles", [])}
    assert "s3Export" not in roles_by_feature, (
        f"rejected update unexpectedly left an s3Export association behind: {roles_by_feature}"
    )
    assert roles_by_feature.get(valid_feature, {}).get("RoleArn") == role_a_arn, (
        f"pre-existing {valid_feature} role association missing/changed after the rejected update: "
        f"{roles_by_feature}"
    )

    status_a_after = _poll_role_status(ctx, cluster_id, role_a_arn, timeout_s=60.0)
    assert status_a_after == "ACTIVE", (
        f"pre-existing role regressed to {status_a_after!r} after the rejected update"
    )


_INITIAL_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  RoleAName:
    Type: String
  RoleAFeatureName:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  RoleA:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleAName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-mysql
      MasterUsername: admin
      MasterUserPassword: !Ref MasterUserPassword
      AssociatedRoles:
        - FeatureName: !Ref RoleAFeatureName
          RoleArn: !GetAtt RoleA.Arn
Outputs:
  RoleAArn:
    Value: !GetAtt RoleA.Arn
"""

_UPDATED_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterId:
    Type: String
  RoleAName:
    Type: String
  RoleAFeatureName:
    Type: String
  RoleBName:
    Type: String
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  RoleA:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleAName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
  RoleB:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleBName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: rds.amazonaws.com
            Action: sts:AssumeRole
  AuroraCluster:
    Type: AWS::RDS::DBCluster
    Properties:
      DBClusterIdentifier: !Ref ClusterId
      Engine: aurora-mysql
      MasterUsername: admin
      MasterUserPassword: !Ref MasterUserPassword
      AssociatedRoles:
        - FeatureName: !Ref RoleAFeatureName
          RoleArn: !GetAtt RoleA.Arn
        - FeatureName: s3Export
          RoleArn: !GetAtt RoleB.Arn
Outputs:
  RoleAArn:
    Value: !GetAtt RoleA.Arn
  RoleBArn:
    Value: !GetAtt RoleB.Arn
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
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}: {_failure_reasons(cfn, name)}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _failure_reasons(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]
    return "; ".join(reasons) if reasons else "no FAILED resource events found"


def _pick_valid_feature(rds, engine: str = "aurora-mysql") -> str:
    """A FeatureName the account's CURRENT default engine version actually supports for
    AddRoleToDBCluster -- looked up rather than assumed, since the set is engine/version
    specific and has shrunk over time (see DescribeDBEngineVersions' SupportedFeatureNames)."""
    versions = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)["DBEngineVersions"]
    supported = versions[0].get("SupportedFeatureNames", []) if versions else []
    if not supported:
        raise AssertionError(f"engine {engine} advertises no SupportedFeatureNames to test a positive control with")
    if "s3Export" in supported:
        raise AssertionError(
            "s3Export is now a valid AddRoleToDBCluster feature for the default aurora-mysql "
            "engine version -- real AWS may have re-added support for it, and this check's "
            "withdrawal premise needs re-authoring"
        )
    return supported[0]


def _admin_password(ctx) -> str:
    suffix = ctx.unique_name("pw").split("-")[-1]
    return f"S2r{suffix}Aa1"


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
