"""cfn-rds-cluster-parameter-group-s3-role-arn-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-cluster-parameter-group-s3-role-arn-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "RoleName": {"Type": "String"},
    "BucketName": {"Type": "String"},
    "ParamGroupDescription": {"Type": "String", "Default": "sim2real aws_default_s3_role arn resolution"}
  },
  "Resources": {
    "S3Bucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "BucketName"}}
    },
    "S3Role": {
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
            "PolicyName": "s3-load-save-access",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                  "Resource": [
                    {"Fn::GetAtt": ["S3Bucket", "Arn"]},
                    {"Fn::Sub": "${S3Bucket.Arn}/*"}
                  ]
                }
              ]
            }
          }
        ]
      }
    },
    "ClusterParamGroup": {
      "Type": "AWS::RDS::DBClusterParameterGroup",
      "Properties": {
        "Family": "aurora-mysql8.0",
        "Description": {"Ref": "ParamGroupDescription"},
        "Parameters": {
          "aws_default_s3_role": {"Fn::GetAtt": ["S3Role", "Arn"]}
        }
      }
    }
  },
  "Outputs": {
    "RoleArn": {"Value": {"Fn::GetAtt": ["S3Role", "Arn"]}},
    "ParamGroupName": {"Value": {"Ref": "ClusterParamGroup"}}
  }
}
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB cluster parameter group's aws_default_s3_role parameter, set in CFN to
    !GetAtt on an IAM role created in the same template, resolves to that role's real
    ARN once the stack settles -- not a literal token, not the logical id, the ARN."""
    params = {
        "RoleName": _xname(ctx, "s3-default-role")[:64],
        "BucketName": _xname(ctx, "s3-default-bkt")[:63],
    }
    deployed = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=300.0)
    expected_role_arn = deployed["outputs"]["RoleArn"]
    param_group_name = deployed["outputs"]["ParamGroupName"]

    rds = ctx.client("rds")

    def _param_value():
        resp = rds.describe_db_cluster_parameters(
            DBClusterParameterGroupName=param_group_name, Source="user"
        )
        for p in resp.get("Parameters", []):
            if p["ParameterName"] == "aws_default_s3_role":
                return p.get("ParameterValue")
        return None

    value = _poll_until(
        _param_value,
        lambda v: v is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description="aws_default_s3_role parameter to appear with Source=user",
    )
    assert value == expected_role_arn, (
        f"aws_default_s3_role resolved to {value!r}, expected the role ARN {expected_role_arn!r}"
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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
