"""deploy-cfn-rds-s3-bucket-policy-restricts-export-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-s3-bucket-policy-restricts-export-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real-Export-2024!"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask to a bucket whose policy denies the export role is rejected with
    IamRoleMissingPermissions and writes nothing, while the same role exporting the same snapshot to
    a bucket without the deny completes with objects."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    db_id = _xname(ctx, "db")
    template = _template(db_id, ctx=ctx)
    result = _deploy_cfn(ctx, json.dumps(template), timeout_s=1200.0)
    outputs = result["outputs"]
    open_bucket = outputs["OpenBucketName"]
    denied_bucket = outputs["DeniedBucketName"]
    role_arn = outputs["RoleArn"]
    kms_key_id = outputs["KmsKeyId"]

    ctx.on_cleanup(lambda: _empty_bucket(s3, open_bucket))
    ctx.on_cleanup(lambda: _empty_bucket(s3, denied_bucket))

    snapshot_id = _xname(ctx, "snap")
    rds.create_db_snapshot(DBInstanceIdentifier=db_id, DBSnapshotIdentifier=snapshot_id)
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snapshot_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0],
        lambda s: s["Status"] in {"available", "failed"},
        timeout_s=1500.0,
        interval_s=20.0,
        description=f"snapshot {snapshot_id} available",
    )
    assert snap["Status"] == "available"
    source_arn = snap["DBSnapshotArn"]

    denied_export_id = _xname(ctx, "export-denied")
    try:
        rds.start_export_task(
            ExportTaskIdentifier=denied_export_id,
            SourceArn=source_arn,
            S3BucketName=denied_bucket,
            IamRoleArn=role_arn,
            KmsKeyId=kms_key_id,
        )
        raise AssertionError("start_export_task to a bucket that denies the role principal unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "IamRoleMissingPermissions", (
            f"expected IamRoleMissingPermissions from the bucket-policy deny, got {code}: {exc}"
        )
        # The bucket policy denies s3:*, so the S3 action RDS names varies; the rest is stable.
        message = exc.response["Error"].get("Message", "")
        assert message.startswith(f"The IAM role {role_arn} isn't authorized to call s3:"), message
        assert message.endswith(f" on the S3 bucket {denied_bucket}."), message
    denied_listing = s3.list_objects_v2(Bucket=denied_bucket, Prefix=denied_export_id)
    assert denied_listing.get("KeyCount", 0) == 0, "denied-bucket export wrote objects despite the bucket policy deny"

    open_export_id = _xname(ctx, "export-open")
    rds.start_export_task(
        ExportTaskIdentifier=open_export_id,
        SourceArn=source_arn,
        S3BucketName=open_bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
    )

    open_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=open_export_id)["ExportTasks"][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=2400.0,
        interval_s=30.0,
        description=f"export task {open_export_id} terminal",
    )

    # positive control: same role, same snapshot, bucket without the deny statement.
    assert open_task["Status"] == "COMPLETE", f"control export ended {open_task['Status']}: {open_task.get('FailureCause')}"
    open_listing = s3.list_objects_v2(Bucket=open_bucket, Prefix=open_export_id)
    assert open_listing.get("KeyCount", 0) > 0, "control export reported COMPLETE but wrote no objects"


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_snapshot(rds, snapshot_id: str) -> None:
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _template(db_id: str, *, ctx) -> dict:
    role_logical = "ExportRole"
    open_bucket, denied_bucket = "OpenBucket", "DeniedBucket"
    denied_policy_logical = "DeniedBucketPolicy"
    key_logical, db_logical = "ExportKey", "DBInstance"

    role_perms = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject*",
                    "s3:GetObject*",
                    "s3:ListBucket",
                    "s3:DeleteObject*",
                    "s3:GetBucketLocation",
                ],
                "Resource": [
                    {"Fn::Sub": "arn:aws:s3:::${" + open_bucket + "}"},
                    {"Fn::Sub": "arn:aws:s3:::${" + open_bucket + "}/*"},
                    {"Fn::Sub": "arn:aws:s3:::${" + denied_bucket + "}"},
                    {"Fn::Sub": "arn:aws:s3:::${" + denied_bucket + "}/*"},
                ],
            }
        ],
    }

    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            open_bucket: {"Type": "AWS::S3::Bucket"},
            denied_bucket: {"Type": "AWS::S3::Bucket"},
            key_logical: {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real RDS export key (bucket-policy-deny negative)",
                    "KeyPolicy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "EnableRootPermissions",
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
                                "Action": "kms:*",
                                "Resource": "*",
                            },
                            {
                                "Sid": "AllowExportRoleUse",
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::GetAtt": [role_logical, "Arn"]}},
                                "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },
            role_logical: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [{"PolicyName": "ExportPolicy", "PolicyDocument": role_perms}],
                },
            },
            denied_policy_logical: {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": denied_bucket},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "ExplicitDenyExportRole",
                                "Effect": "Deny",
                                "Principal": {"AWS": {"Fn::GetAtt": [role_logical, "Arn"]}},
                                "Action": "s3:*",
                                "Resource": [
                                    {"Fn::Sub": "arn:aws:s3:::${" + denied_bucket + "}"},
                                    {"Fn::Sub": "arn:aws:s3:::${" + denied_bucket + "}/*"},
                                ],
                            }
                        ],
                    },
                },
            },
            db_logical: {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBInstanceIdentifier": db_id,
                    "Engine": "mysql",
                    "DBInstanceClass": "db.t3.micro",
                    "AllocatedStorage": "20",
                    "MasterUsername": "admin",
                    "MasterUserPassword": _DB_PASSWORD,
                    "BackupRetentionPeriod": 1,
                    "PubliclyAccessible": False,
                    "MultiAZ": False,
                    "DBSubnetGroupName": subnet_group,
                },
            },
        },
        "Outputs": {
            "OpenBucketName": {"Value": {"Ref": open_bucket}},
            "DeniedBucketName": {"Value": {"Ref": denied_bucket}},
            "RoleArn": {"Value": {"Fn::GetAtt": [role_logical, "Arn"]}},
            "KmsKeyId": {"Value": {"Ref": key_logical}},
        },
    }


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
    return {"sim2real:managed": "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


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
        timeout_s=600,
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
        interval_s=10.0,
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
