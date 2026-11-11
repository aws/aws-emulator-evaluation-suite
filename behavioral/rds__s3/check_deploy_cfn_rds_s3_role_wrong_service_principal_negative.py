"""deploy-cfn-rds-s3-role-wrong-service-principal-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-s3-role-wrong-service-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real-Export-2024!"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a role trusted by ec2.amazonaws.com is rejected with IamRoleNotFound and
    writes nothing, while a role trusted by export.rds.amazonaws.com exports the same snapshot to
    COMPLETE with objects."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    db_id = _xname(ctx, "db")
    template = _template(db_id, ctx=ctx)
    result = _deploy_cfn(ctx, json.dumps(template), timeout_s=1200.0)
    outputs = result["outputs"]
    correct_bucket = outputs["CorrectBucketName"]
    wrong_bucket = outputs["WrongBucketName"]
    correct_role_arn = outputs["CorrectRoleArn"]
    wrong_role_arn = outputs["WrongRoleArn"]
    kms_key_id = outputs["KmsKeyId"]

    ctx.on_cleanup(lambda: _empty_bucket(s3, correct_bucket))
    ctx.on_cleanup(lambda: _empty_bucket(s3, wrong_bucket))

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

    wrong_export_id = _xname(ctx, "export-wrong")
    try:
        rds.start_export_task(
            ExportTaskIdentifier=wrong_export_id,
            SourceArn=source_arn,
            S3BucketName=wrong_bucket,
            IamRoleArn=wrong_role_arn,
            KmsKeyId=kms_key_id,
        )
        raise AssertionError("start_export_task with a wrong-service-principal role unexpectedly succeeded")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "IamRoleNotFound", f"expected IamRoleNotFound, got {code}: {exc}"
        expected = (
            f"The principal export.rds.amazonaws.com isn't allowed to assume the IAM role {wrong_role_arn} "
            f"or the IAM role {wrong_role_arn} doesn't exist."
        )
        assert exc.response["Error"].get("Message") == expected, exc.response["Error"]
    wrong_listing = s3.list_objects_v2(Bucket=wrong_bucket, Prefix=wrong_export_id)
    assert wrong_listing.get("KeyCount", 0) == 0, "wrong-principal export wrote objects despite failing to assume the role"

    correct_export_id = _xname(ctx, "export-correct")
    rds.start_export_task(
        ExportTaskIdentifier=correct_export_id,
        SourceArn=source_arn,
        S3BucketName=correct_bucket,
        IamRoleArn=correct_role_arn,
        KmsKeyId=kms_key_id,
    )

    correct_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=correct_export_id)["ExportTasks"][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=2400.0,
        interval_s=30.0,
        description=f"export task {correct_export_id} terminal",
    )

    # positive control: same snapshot, role trusting export.rds.amazonaws.com, completes.
    assert correct_task["Status"] == "COMPLETE", (
        f"control export ended {correct_task['Status']}: {correct_task.get('FailureCause')}"
    )
    correct_listing = s3.list_objects_v2(Bucket=correct_bucket, Prefix=correct_export_id)
    assert correct_listing.get("KeyCount", 0) > 0, "control export reported COMPLETE but wrote no objects"


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
    correct_role, wrong_role = "CorrectExportRole", "WrongExportRole"
    correct_bucket, wrong_bucket = "CorrectBucket", "WrongBucket"
    key_logical, db_logical = "ExportKey", "DBInstance"

    def s3_policy(bucket_logical: str) -> dict:
        return {
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
                        {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}"},
                        {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}/*"},
                    ],
                }
            ],
        }

    subnet_group = _network_db_subnet_group(ctx, ctx.client('rds'))
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            correct_bucket: {"Type": "AWS::S3::Bucket"},
            wrong_bucket: {"Type": "AWS::S3::Bucket"},
            key_logical: {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real RDS export key (wrong-principal negative)",
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
                                "Sid": "AllowCorrectRoleUse",
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::GetAtt": [correct_role, "Arn"]}},
                                "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },
            correct_role: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "export.rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [{"PolicyName": "ExportPolicy", "PolicyDocument": s3_policy(correct_bucket)}],
                },
            },
            wrong_role: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    # Trusts ec2.amazonaws.com instead of export.rds.amazonaws.com — CFN deploys
                    # this without complaint since trust policies aren't validated against how
                    # the role is later used.
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [{"PolicyName": "ExportPolicy", "PolicyDocument": s3_policy(wrong_bucket)}],
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
            "CorrectBucketName": {"Value": {"Ref": correct_bucket}},
            "WrongBucketName": {"Value": {"Ref": wrong_bucket}},
            "CorrectRoleArn": {"Value": {"Fn::GetAtt": [correct_role, "Arn"]}},
            "WrongRoleArn": {"Value": {"Fn::GetAtt": [wrong_role, "Arn"]}},
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
