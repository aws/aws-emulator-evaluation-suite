"""cfn-deploy-rds-s3-export-bucket-missing-negative."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "cfn-deploy-rds-s3-export-bucket-missing-negative"
GROUP = "permission-boundary"
SERVICES = ["rds", "s3"]

_TEMPLATE = """
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Parameters": {
    "RoleName": {"Type": "String"},
    "GoodBucketName": {"Type": "String"},
    "DbInstanceId": {"Type": "String"},
    "MasterUserPassword": {"Type": "String", "NoEcho": true}
  },
  "Resources": {
    "GoodBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {"BucketName": {"Ref": "GoodBucketName"}}
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
                    {"Fn::GetAtt": ["GoodBucket", "Arn"]},
                    {"Fn::Sub": "${GoodBucket.Arn}/*"}
                  ]
                }
              ]
            }
          }
        ]
      }
    },
    "ExportKmsKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "Description": "sim2real RDS S3 export test key",
        "KeyPolicy": {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Sid": "EnableRootAdmin",
              "Effect": "Allow",
              "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
              "Action": "kms:*",
              "Resource": "*"
            },
            {
              "Sid": "AllowExportRoleUse",
              "Effect": "Allow",
              "Principal": {"AWS": {"Fn::GetAtt": ["ExportRole", "Arn"]}},
              "Action": ["kms:CreateGrant", "kms:DescribeKey"],
              "Resource": "*"
            }
          ]
        }
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
        "PubliclyAccessible": false
      }
    }
  },
  "Outputs": {
    "ExportRoleArn": {"Value": {"Fn::GetAtt": ["ExportRole", "Arn"]}},
    "ExportKmsKeyArn": {"Value": {"Fn::GetAtt": ["ExportKmsKey", "Arn"]}},
    "GoodBucketName": {"Value": {"Ref": "GoodBucketName"}},
    "DbInstanceId": {"Value": {"Ref": "DbInstanceId"}}
  }
}
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """StartExportTask to a bucket that does not exist is rejected with InvalidS3BucketFault and its
    exact message and creates no task, while the same export to the stack's bucket is accepted and
    does not fail."""
    params = {
        "RoleName": _xname(ctx, "export-role")[:64],
        "GoodBucketName": _xname(ctx, "export-good-bkt")[:63],
        "DbInstanceId": _xname(ctx, "db")[:60],
        "MasterUserPassword": _gen_db_password(),
    }
    deployed = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=1800.0)
    role_arn = deployed["outputs"]["ExportRoleArn"]
    kms_key_arn = deployed["outputs"]["ExportKmsKeyArn"]
    good_bucket = deployed["outputs"]["GoodBucketName"]
    db_id = deployed["outputs"]["DbInstanceId"]

    rds = ctx.client("rds")

    snapshot_id = _xname(ctx, "snap")[:60]
    rds.create_db_snapshot(DBSnapshotIdentifier=snapshot_id, DBInstanceIdentifier=db_id)

    def _cleanup_snapshot():
        try:
            rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
                raise

    ctx.on_cleanup(_cleanup_snapshot)

    def _snapshot_status():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)[
            "DBSnapshots"
        ][0]

    snap = _poll_until(
        _snapshot_status,
        lambda s: s["Status"] in {"available", "failed", "error"},
        timeout_s=900.0,
        interval_s=10.0,
        description=f"manual snapshot {snapshot_id} to leave creating",
    )
    assert snap["Status"] == "available", f"manual snapshot ended in {snap['Status']}"
    snapshot_arn = snap["DBSnapshotArn"]

    nonexistent_bucket = _xname(ctx, "nonexistent-bkt")[:63]
    bad_task_id = _xname(ctx, "exp-bad")[:60]
    good_task_id = _xname(ctx, "exp-good")[:60]

    def _task_status(task_id):
        resp = rds.describe_export_tasks(ExportTaskIdentifier=task_id)
        tasks = resp.get("ExportTasks", [])
        return tasks[0] if tasks else None

    # IAM/KMS grants attached moments earlier can transiently surface as
    # KMSKeyNotAccessibleFault before they propagate, which would otherwise mask
    # the real, persistent rejection code this check is asserting on.
    code, message = _client_error_with_retry(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_task_id,
            SourceArn=snapshot_arn,
            S3BucketName=nonexistent_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_arn,
        ),
        retryable_codes=("KMSKeyNotAccessibleFault",),
    )
    assert code == "InvalidS3BucketFault", (
        f"export to a nonexistent bucket should be rejected synchronously with "
        f"InvalidS3BucketFault, got {code!r}"
    )
    assert message == (
        f"The S3 bucket {nonexistent_bucket} isn't valid. Either it isn't located in the "
        "current AWS Region or it doesn't exist."
    ), f"unexpected InvalidS3BucketFault message: {message!r}"

    # Effect absent: the rejected call must not have created an export task.
    assert _task_status(bad_task_id) is None, (
        f"export task {bad_task_id} should not exist after a synchronous rejection"
    )

    # Positive control: the identical export (same snapshot/role/key), pointed at
    # the real bucket provisioned in the same stack, must be accepted.
    rds.start_export_task(
        ExportTaskIdentifier=good_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=good_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_arn,
    )

    def _cleanup_good_task():
        try:
            rds.cancel_export_task(ExportTaskIdentifier=good_task_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ExportTaskNotFound":
                raise

    ctx.on_cleanup(_cleanup_good_task)

    good_task = _poll_until(
        lambda: _task_status(good_task_id),
        lambda t: t is not None and t["Status"] != "STARTING",
        timeout_s=1800.0,
        interval_s=15.0,
        description=f"export task {good_task_id} (real bucket) to leave STARTING",
    )
    assert good_task["Status"] != "FAILED", (
        f"export to the real bucket should not fail, got {good_task['Status']} "
        f"cause={good_task.get('FailureCause')!r}"
    )


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


def _client_error_with_retry(fn, retryable_codes, timeout_s=90.0, interval_s=5.0):
    """Call fn() until it raises a non-retryable ClientError; return its (code, message).
    A success raises: real AWS refuses this call."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retryable_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, err.response["Error"].get("Message", "")
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
        timeout_s=900,
        interval_s=5.0,
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
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
