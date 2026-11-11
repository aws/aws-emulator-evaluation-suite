"""cfn-rds-iam-role-trust-policy-export-rds-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-rds-iam-role-trust-policy-export-rds-positive"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "RoleName": {"Type": "String"},
    "BucketName": {"Type": "String"}
  },
  "Resources": {
    "ExportBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "BucketName"}}
    },
    "ExportRole": {
      "Type": "AWS::IAM::Role",
      "Properties": {
        "RoleName": {"Ref": "RoleName"},
        "AssumeRolePolicyDocument": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Principal": {"Service": "export.rds.amazonaws.com"},
              "Action": "sts:AssumeRole"
            }
          ]
        },
        "Policies": [
          {
            "PolicyName": "export-s3-access",
            "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation"
                  ],
                  "Resource": [
                    {"Fn::GetAtt": ["ExportBucket", "Arn"]},
                    {"Fn::Sub": "${ExportBucket.Arn}/*"}
                  ]
                }
              ]
            }
          }
        ]
      }
    }
  },
  "Outputs": {
    "RoleArn": {"Value": {"Fn::GetAtt": ["ExportRole", "Arn"]}},
    "RoleName": {"Value": {"Ref": "ExportRole"}},
    "BucketArn": {"Value": {"Fn::GetAtt": ["ExportBucket", "Arn"]}}
  }
}
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The stack's export role has exactly one trust statement allowing sts:AssumeRole to
    export.rds.amazonaws.com, and its S3 policy names the stack's bucket and its objects."""
    params = {
        "RoleName": _xname(ctx, "export-role")[:64],
        "BucketName": _xname(ctx, "export-bkt")[:63],
    }
    deployed = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=300.0)
    role_name = deployed["outputs"]["RoleName"]
    bucket_arn = deployed["outputs"]["BucketArn"]

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    assert len(statements) == 1, f"expected exactly 1 trust statement, got {len(statements)}: {statements!r}"
    stmt = statements[0]
    assert stmt["Effect"] == "Allow", f"expected trust statement Effect Allow, got {stmt['Effect']!r}"
    assert stmt["Principal"]["Service"] == "export.rds.amazonaws.com", (
        f"trust policy principal is {stmt['Principal']!r}, expected export.rds.amazonaws.com only"
    )
    assert stmt["Action"] == "sts:AssumeRole", f"expected trust statement Action sts:AssumeRole, got {stmt['Action']!r}"

    policy = iam.get_role_policy(RoleName=role_name, PolicyName="export-s3-access")
    policy_stmt = policy["PolicyDocument"]["Statement"][0]
    resources = policy_stmt["Resource"]
    if isinstance(resources, str):
        resources = [resources]
    assert bucket_arn in resources, (
        f"export policy Resource {resources!r} does not scope to the deployed bucket {bucket_arn!r}"
    )
    assert f"{bucket_arn}/*" in resources, (
        f"export policy Resource {resources!r} missing the deployed bucket's object wildcard {bucket_arn}/*"
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
