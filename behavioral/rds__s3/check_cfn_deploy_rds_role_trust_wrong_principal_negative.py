"""cfn-deploy-rds-role-trust-wrong-principal-negative."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-rds-role-trust-wrong-principal-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

# The bucket and a role trusting rds.amazonaws.com, associated for s3Import.
_GOOD_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "RoleName": {"Type": "String"},
    "BucketName": {"Type": "String"},
    "DbInstanceId": {"Type": "String"},
    "MasterUserPassword": {"Type": "String", "NoEcho": true}
  },
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "BucketName"}}
    },
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": {"Ref": "RoleName"},
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {"Service": "rds.amazonaws.com"},
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Policies": [
          {
            "PolicyName": "s3-access",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                  "Resource": [
                    {"Fn::Sub": "arn:aws:s3:::${BucketName}"},
                    {"Fn::Sub": "arn:aws:s3:::${BucketName}/*"}
                  ]
                }
              ]
            }
          }
        ]
      }
    },
    "DbInstance": {
      "Type": "AWS::RDS::DBInstance",
      "DeletionPolicy": "Delete",
      "Properties": {
        "DBInstanceIdentifier": {"Ref": "DbInstanceId"},
        "Engine": "postgres",
        "DBInstanceClass": "db.t3.micro",
        "AllocatedStorage": "20",
        "MasterUsername": "postgres",
        "MasterUserPassword": {"Ref": "MasterUserPassword"},
        "BackupRetentionPeriod": 0,
        "PubliclyAccessible": false,
        "AssociatedRoles": [
          {
            "FeatureName": "s3Import",
            "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}
          }
        ]
      }
    }
  },
  "Outputs": {
    "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    "DbInstanceId": {"Value": {"Ref": "DbInstanceId"}}
  }
}
"""

# The same bucket, and a role trusting s3.amazonaws.com instead, associated for s3Export.
_BAD_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "RoleName": {"Type": "String"},
    "BucketName": {"Type": "String"},
    "DbInstanceId": {"Type": "String"},
    "MasterUserPassword": {"Type": "String", "NoEcho": true}
  },
  "Resources": {
    "Role": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": {"Ref": "RoleName"},
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {"Service": "s3.amazonaws.com"},
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Policies": [
          {
            "PolicyName": "s3-access",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                  "Resource": [
                    {"Fn::Sub": "arn:aws:s3:::${BucketName}"},
                    {"Fn::Sub": "arn:aws:s3:::${BucketName}/*"}
                  ]
                }
              ]
            }
          }
        ]
      }
    },
    "DbInstance": {
      "Type": "AWS::RDS::DBInstance",
      "DeletionPolicy": "Delete",
      "Properties": {
        "DBInstanceIdentifier": {"Ref": "DbInstanceId"},
        "Engine": "postgres",
        "DBInstanceClass": "db.t3.micro",
        "AllocatedStorage": "20",
        "MasterUsername": "postgres",
        "MasterUserPassword": {"Ref": "MasterUserPassword"},
        "BackupRetentionPeriod": 0,
        "PubliclyAccessible": false,
        "AssociatedRoles": [
          {
            "FeatureName": "s3Export",
            "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]}
          }
        ]
      }
    }
  },
  "Outputs": {
    "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    "DbInstanceId": {"Value": {"Ref": "DbInstanceId"}}
  }
}
"""


@tags(
    "axis:rejection",
    "cap:c4",
    "cap:c7",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A stack associating a role trusted by s3.amazonaws.com with an instance rolls back with "IAM role
    ARN value is invalid" and leaves no instance, while a role trusted by rds.amazonaws.com associates
    for s3Import and reaches ACTIVE."""
    bucket = _xname(ctx, "trust-bkt")[:63]
    good = _deploy_cfn(
        ctx,
        _GOOD_TEMPLATE,
        parameters={
            "RoleName": _xname(ctx, "good-role")[:64],
            "BucketName": bucket,
            "DbInstanceId": _xname(ctx, "db")[:60],
            "MasterUserPassword": _gen_db_password(),
        },
        timeout_s=1800.0,
    )
    good_role_arn = good["outputs"]["RoleArn"]
    rds = ctx.client("rds")

    def _roles_by_arn():
        desc = rds.describe_db_instances(DBInstanceIdentifier=good["outputs"]["DbInstanceId"])["DBInstances"][0]
        return {r["RoleArn"]: r for r in desc.get("AssociatedRoles", [])}

    roles = _poll_until(
        _roles_by_arn,
        lambda r: good_role_arn in r and r[good_role_arn]["Status"] != "PENDING",
        timeout_s=900.0,
        interval_s=10.0,
        description="the rds-trusted role's association to leave PENDING",
    )
    assert roles[good_role_arn]["Status"] == "ACTIVE", (
        f"role trusted by rds.amazonaws.com should be ACTIVE, got {roles[good_role_arn]['Status']}"
    )
    assert roles[good_role_arn]["FeatureName"] == "s3Import", (
        f"expected the association FeatureName to be s3Import, got {roles[good_role_arn]['FeatureName']!r}"
    )

    bad_db_id = _xname(ctx, "baddb")[:60]
    bad = _deploy_cfn(
        ctx,
        _BAD_TEMPLATE,
        parameters={
            "RoleName": _xname(ctx, "bad-role")[:64],
            "BucketName": bucket,
            "DbInstanceId": bad_db_id,
            "MasterUserPassword": _gen_db_password(),
        },
        timeout_s=1800.0,
        expect_complete=False,
    )
    assert bad["status"] == "ROLLBACK_COMPLETE", (
        f"a stack associating an s3-trusted role should roll back, got {bad['status']} ({bad['failed']})"
    )
    db_failures = [reason for logical, reason in bad["failed"] if logical == "DbInstance"]
    assert any("IAM role ARN value is invalid" in r for r in db_failures), (
        f"expected DbInstance to fail on the role ARN, got {bad['failed']}"
    )
    left = rds.describe_db_instances(
        Filters=[{"Name": "db-instance-id", "Values": [bad_db_id]}]
    )["DBInstances"]
    assert left == [], f"expected no DB instance left behind, got {left!r}"


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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _gen_db_password() -> str:
    return "Sim2Real1" + uuid.uuid4().hex[:16]


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
        interval_s=15.0,
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
    expect_complete=True,
) -> dict:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict = {
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
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason", ""))
        for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
        if e["ResourceStatus"] in ("CREATE_FAILED", "ROLLBACK_FAILED")
    ]
    if not expect_complete:
        return {"stack_name": name, "status": stack["StackStatus"], "failed": failed}
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']} "
            f"(reason: {stack.get('StackStatusReason', '<none>')}); failed resources: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
