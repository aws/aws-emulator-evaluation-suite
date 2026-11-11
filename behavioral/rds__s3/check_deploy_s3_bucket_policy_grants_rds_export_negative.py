"""deploy-s3-bucket-policy-grants-rds-export-negative."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-bucket-policy-grants-rds-export-negative"
GROUP = "iac-snapshot-export"
SERVICES = ["rds", "s3"]


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """With IAM write access to both buckets, a bucket-policy Deny on one makes StartExportTask to
    it fail synchronously with IamRoleMissingPermissions and create no task or object, while the
    same role/snapshot exporting to the other bucket completes."""
    allow_bucket = _xname(ctx, "export-allow-bkt")
    deny_bucket = _xname(ctx, "export-deny-bkt")
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
                "AllowBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": allow_bucket},
                },
                "DenyBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": deny_bucket},
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
                                        "AWS": {
                                            "Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"
                                        }
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
                                    "Principal": {
                                        "Service": "export.rds.amazonaws.com"
                                    },
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "export-access-both-buckets",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": s3_export_actions,
                                            "Resource": [
                                                f"arn:aws:s3:::{allow_bucket}",
                                                f"arn:aws:s3:::{allow_bucket}/*",
                                                f"arn:aws:s3:::{deny_bucket}",
                                                f"arn:aws:s3:::{deny_bucket}/*",
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
                                            "Resource": {
                                                "Fn::GetAtt": ["ExportKey", "Arn"]
                                            },
                                        },
                                    ],
                                },
                            }
                        ],
                    },
                },
                # The one thing broken: an explicit bucket-policy Deny of the export role's
                # principal for the DenyBucket only. IAM grants write access; the resource policy
                # overrides it via an explicit Deny (explicit Deny always wins).
                "DenyBucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "DependsOn": ["DenyBucket", "ExportRole"],
                    "Properties": {
                        "Bucket": {"Ref": "DenyBucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "DenyExportRolePut",
                                    "Effect": "Deny",
                                    "Principal": {
                                        "AWS": {"Fn::GetAtt": ["ExportRole", "Arn"]}
                                    },
                                    "Action": "s3:PutObject*",
                                    "Resource": f"arn:aws:s3:::{deny_bucket}/*",
                                }
                            ],
                        },
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
    cfn = ctx.client("cloudformation")

    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    key_physical_id = cfn.describe_stack_resource(
        StackName=deployed["stack_name"], LogicalResourceId="ExportKey"
    )["StackResourceDetail"]["PhysicalResourceId"]
    key_arn = ctx.client("kms").describe_key(KeyId=key_physical_id)["KeyMetadata"][
        "Arn"
    ]

    snap_id = _xname(ctx, "export-snap")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=db_id, Tags=_xsvc_tags_kv()
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))

    def _snapshot_status():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][
            0
        ]["Status"]

    snap_status = _poll_until(
        _snapshot_status,
        lambda s: s in {"available", "failed"},
        timeout_s=900.0,
        interval_s=15.0,
        description=f"manual snapshot {snap_id} available",
    )
    assert snap_status == "available", f"snapshot setup failed: {snap_status!r}"
    snap_arn = rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][
        0
    ]["DBSnapshotArn"]

    ctx.on_cleanup(lambda: _empty_bucket(ctx, allow_bucket))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, deny_bucket))

    # RDS checks the role's S3 write access on the destination synchronously: the Deny surfaces
    # as an immediate IamRoleMissingPermissionsFault, never a task that later FAILs, so the same
    # snapshot is safe to reuse for the positive control.
    deny_task = _xname(ctx, "export-task-deny")
    try:
        rds.start_export_task(
            ExportTaskIdentifier=deny_task,
            SourceArn=snap_arn,
            S3BucketName=deny_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=key_arn,
        )
        raise AssertionError(
            "start_export_task to the bucket-policy-denied bucket unexpectedly succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "IamRoleMissingPermissions", (
            f"expected IamRoleMissingPermissions from the bucket-policy deny, got {code}: {exc}"
        )
        expected = f"The IAM role {role_arn} isn't authorized to call s3:PutObject on the S3 bucket {deny_bucket}."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    deny_listing = s3.list_objects_v2(Bucket=deny_bucket)
    assert deny_listing.get("KeyCount", 0) == 0, (
        "denied export unexpectedly delivered objects"
    )

    # Positive control: the SAME role/snapshot exporting to the allow-bucket (no Deny statement)
    # completes and delivers objects.
    allow_task = _xname(ctx, "export-task-allow")
    rds.start_export_task(
        ExportTaskIdentifier=allow_task,
        SourceArn=snap_arn,
        S3BucketName=allow_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=key_arn,
    )
    allow_detail = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=allow_task)[
            "ExportTasks"
        ][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=1800.0,
        interval_s=20.0,
        description=f"export task {allow_task} (positive control) reaches a terminal state",
    )
    assert allow_detail["Status"] == "COMPLETE", (
        f"positive control expected COMPLETE, got {allow_detail['Status']!r}: "
        f"{allow_detail.get('FailureCause')}"
    )
    allow_listing = s3.list_objects_v2(Bucket=allow_bucket)
    assert allow_listing.get("KeyCount", 0) > 0, "positive control delivered no objects"


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

    # A stack that owns an Aurora cluster takes minutes to delete.
    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=1500,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended DELETE_FAILED")


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
