"""deploy-rds-export-task-role-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-export-task-role-stack-positive"
GROUP = "iac-snapshot-export"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed stack (S3 bucket + export.rds.amazonaws.com-trusted IAM role + CMK) enables a
    post-deploy StartExportTask against a manual RDS snapshot whose Parquet output objects
    actually land in the target S3 bucket."""
    bucket_name = _xname(ctx, "export-bkt")
    role_name = _xname(ctx, "export-role")
    db_id = _xname(ctx, "export-db")
    master_password = _db_password(ctx)

    s3_export_actions = [
        "s3:PutObject*",
        "s3:GetObject*",
        "s3:ListBucket",
        "s3:DeleteObject*",
        "s3:GetBucketLocation",
    ]

    template = json.dumps(
        {
            "Resources": {
                "ExportBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket_name},
                },
                "ExportKey": {
                    "Type": "AWS::KMS::Key",
                    "Properties": {
                        "Description": "sim2real RDS snapshot export CMK",
                        "PendingWindowInDays": 7,
                        "KeyPolicy": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "EnableRootFullAccess",
                                    "Effect": "Allow",
                                    "Principal": {
                                        "AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}
                                    },
                                    "Action": "kms:*",
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                },
                "ExportRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "export.rds.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "export-access",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": s3_export_actions,
                                            "Resource": [
                                                f"arn:aws:s3:::{bucket_name}",
                                                f"arn:aws:s3:::{bucket_name}/*",
                                            ],
                                        },
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "kms:Encrypt",
                                                "kms:Decrypt",
                                                "kms:ReEncrypt*",
                                                "kms:GenerateDataKey*",
                                                "kms:DescribeKey",
                                                "kms:CreateGrant",
                                            ],
                                            "Resource": {"Fn::GetAtt": ["ExportKey", "Arn"]},
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                "DBInstance": {
                    "Type": "AWS::RDS::DBInstance",
                    "DeletionPolicy": "Delete",
                    "Properties": {
                        "DBInstanceIdentifier": db_id,
                        "Engine": "postgres",
                        "DBInstanceClass": "db.t3.micro",
                        "AllocatedStorage": "20",
                        "MasterUsername": "dbadmin",
                        "MasterUserPassword": master_password,
                        "PubliclyAccessible": False,
                        "BackupRetentionPeriod": 0,
                        "DBSubnetGroupName": _network_db_subnet_group(ctx, ctx.client("rds")),
                    },
                },
            }
        }
    )

    deployed = _deploy_cfn(ctx, template, timeout_s=1800.0)

    rds = ctx.client("rds")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    # KMS key ARN: resolve via CFN stack resource (physical id is the key id).
    cfn = ctx.client("cloudformation")
    key_physical_id = cfn.describe_stack_resource(
        StackName=deployed["stack_name"], LogicalResourceId="ExportKey"
    )["StackResourceDetail"]["PhysicalResourceId"]
    key_arn = ctx.client("kms").describe_key(KeyId=key_physical_id)["KeyMetadata"]["Arn"]

    snap_id = _xname(ctx, "export-snap")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))

    def _snapshot_status():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0]["Status"]

    snap_status = _poll_until(
        _snapshot_status,
        lambda s: s in {"available", "failed"},
        timeout_s=900.0,
        interval_s=15.0,
        description=f"manual snapshot {snap_id} available",
    )
    assert snap_status == "available", f"snapshot setup failed: {snap_status!r}"
    snap_arn = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0][
        "DBSnapshotArn"
    ]

    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    task_id = _xname(ctx, "export-task")
    rds.start_export_task(
        ExportTaskIdentifier=task_id,
        SourceArn=snap_arn,
        S3BucketName=bucket_name,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )

    def _task_status():
        return rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]["Status"]

    final_status = _poll_until(
        _task_status,
        lambda s: s in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=1800.0,
        interval_s=20.0,
        description=f"export task {task_id} reaches a terminal state",
    )
    assert final_status == "COMPLETE", f"expected export task COMPLETE, got {final_status!r}"

    listing = s3.list_objects_v2(Bucket=bucket_name, Prefix=task_id)
    assert listing.get("KeyCount", 0) > 0, (
        f"export task {task_id} completed but delivered no S3 objects under its own "
        f"prefix in bucket {bucket_name!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _db_password(ctx: Any) -> str:
    suffix = ctx.unique_name("pw").rsplit("-", 1)[-1]
    return f"Sim2Real1{suffix}Aa"


def _empty_bucket(ctx, bucket_name: str) -> None:
    """Delete all objects (best-effort) so the bucket can be removed by the CFN stack delete."""
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
