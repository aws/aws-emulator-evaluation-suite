"""cfn-deploy-rds-instance-with-s3-import-role-positive."""
from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-rds-instance-with-s3-import-role-positive"
GROUP = "deployment-order"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "BucketName": {"Type": "String"},
    "RoleName": {"Type": "String"},
    "DbInstanceId": {"Type": "String"},
    "MasterUserPassword": {"Type": "String", "NoEcho": true}
  },
  "Resources": {
    "ImportBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "BucketName"}}
    },
    "S3ImportRole": {
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
            "PolicyName": "s3-import-access",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": ["s3:GetObject", "s3:ListBucket"],
                  "Resource": [
                    {"Fn::GetAtt": ["ImportBucket", "Arn"]},
                    {"Fn::Sub": "${ImportBucket.Arn}/*"}
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
            "RoleArn": {"Fn::GetAtt": ["S3ImportRole", "Arn"]}
          }
        ]
      }
    }
  },
  "Outputs": {
    "RoleArn": {"Value": {"Fn::GetAtt": ["S3ImportRole", "Arn"]}},
    "DbInstanceId": {"Value": {"Ref": "DbInstanceId"}}
  }
}
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB instance deployed in the same CFN stack as its S3-import IAM role
    lists that role in AssociatedRoles as ACTIVE with FeatureName s3Import,
    and deleting the stack removes the instance."""
    params = {
        "BucketName": _xname(ctx, "import-bkt")[:63],
        "RoleName": _xname(ctx, "s3-import-role")[:64],
        "DbInstanceId": _xname(ctx, "db")[:60],
        "MasterUserPassword": _gen_db_password(),
    }
    deployed = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=1800.0)
    role_arn = deployed["outputs"]["RoleArn"]
    db_id = deployed["outputs"]["DbInstanceId"]

    rds = ctx.client("rds")

    def _associated_role():
        desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        for role in desc.get("AssociatedRoles", []):
            if role["RoleArn"] == role_arn:
                return role
        return None

    role_state = _poll_until(
        _associated_role,
        lambda r: r is not None and r["Status"] != "PENDING",
        timeout_s=900.0,
        interval_s=10.0,
        description=f"AssociatedRoles entry for {role_arn} to leave PENDING",
    )
    assert role_state is not None, (
        f"AssociatedRoles for {db_id} never gained an entry for {role_arn}"
    )
    assert role_state["FeatureName"] == "s3Import", (
        f"expected FeatureName 's3Import', got {role_state['FeatureName']!r}"
    )
    assert role_state["Status"] == "ACTIVE", (
        f"expected role trusted by rds.amazonaws.com to become ACTIVE, got {role_state['Status']}"
    )

    deployed_stack_name = deployed["stack_name"]
    _delete_stack_and_wait(ctx, deployed_stack_name, timeout_s=900.0, interval_s=15.0)
    try:
        rds.describe_db_instances(DBInstanceIdentifier=db_id)
        raise AssertionError(f"expected {db_id} to be gone after stack delete, but describe_db_instances still finds it")
    except ClientError as e:
        assert e.response["Error"]["Code"] == "DBInstanceNotFound", (
            f"expected DBInstanceNotFound for deleted {db_id}, got {e.response['Error']['Code']}"
        )
        message = e.response["Error"].get("Message", "")
        assert message == f"DBInstance {db_id} not found.", (
            f"unexpected DBInstanceNotFound message for deleted {db_id}: {message!r}"
        )


# ===== helpers =====
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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _gen_db_password() -> str:
    return "Sim2Real1" + uuid.uuid4().hex[:16]


def _delete_stack_and_wait(ctx, stack_name: str, *, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            err = e.response["Error"]
            if err["Code"] == "ValidationError" and "does not exist" in err.get("Message", ""):
                return "GONE"
            raise

    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} delete ended in DELETE_FAILED")


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name, timeout_s=900.0, interval_s=2.0))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
