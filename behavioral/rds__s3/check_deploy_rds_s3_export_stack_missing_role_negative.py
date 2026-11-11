"""deploy-rds-s3-export-stack-missing-role-negative."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-rds-s3-export-stack-missing-role-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a stack role that has the right trust but no S3 policy is rejected with
    IamRoleMissingPermissions and writes nothing, while a sibling role with the S3 policy exports to
    COMPLETE with objects."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    db_id = _xname(ctx, "dbi")
    template = _build_export_stack_template(
        "mysql",
        [
            ("GoodRole", "export.rds.amazonaws.com", True),
            ("BadRole", "export.rds.amazonaws.com", False),
        ],
        db_id, ctx=ctx
    )
    password = secrets.token_urlsafe(12)
    stack = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"MasterUsername": "dbadmin", "MasterUserPassword": password},
        timeout_s=900,
    )
    outputs = stack["outputs"]
    bucket = outputs["BucketName"]
    good_role_arn = outputs["GoodRoleArn"]
    bad_role_arn = outputs["BadRoleArn"]
    kms_arn = outputs["KmsKeyArn"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    snap_id = _xname(ctx, "snap")
    rds.create_db_snapshot(DBInstanceIdentifier=db_id, DBSnapshotIdentifier=snap_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snapshot = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200,
        interval_s=15.0,
        description=f"snapshot {snap_id} available",
    )
    snap_arn = snapshot["DBSnapshotArn"]

    # Break exactly one thing: BadRole has the right trust policy but no S3 permissions at all.
    bad_task_id = _xname(ctx, "expbad")
    code, message = _error_code(
        lambda: rds.start_export_task(
            ExportTaskIdentifier=bad_task_id,
            SourceArn=snap_arn,
            S3BucketName=bucket,
            IamRoleArn=bad_role_arn,
            KmsKeyId=kms_arn,
            S3Prefix="bad",
        )
    )
    assert code == "IamRoleMissingPermissions", (
        f"expected IamRoleMissingPermissions for a role with no attached S3 policy, got {code!r}"
    )
    # RDS probes s3:GetBucketLocation first, and this role holds no S3 grant at all.
    expected = f"The IAM role {bad_role_arn} isn't authorized to call s3:GetBucketLocation on the S3 bucket {bucket}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    bad_objects = s3.list_objects_v2(Bucket=bucket, Prefix="bad/").get("Contents", [])
    assert bad_objects == [], f"export with a permissionless role should land no objects, found {bad_objects!r}"

    # Positive control in the SAME file/stack: GoodRole (same trust, correct S3 policy) succeeds.
    good_task_id = _xname(ctx, "expgood")
    rds.start_export_task(
        ExportTaskIdentifier=good_task_id,
        SourceArn=snap_arn,
        S3BucketName=bucket,
        IamRoleArn=good_role_arn,
        KmsKeyId=kms_arn,
        S3Prefix="good",
    )
    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=good_task_id)["ExportTasks"][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=1200,
        interval_s=15.0,
        description=f"export task {good_task_id} terminal",
    )
    assert task["Status"] == "COMPLETE", f"positive-control export ended in {task['Status']}: {task}"
    good_objects = s3.list_objects_v2(Bucket=bucket, Prefix="good/").get("Contents", [])
    assert len(good_objects) > 0, "positive-control export completed but landed no objects"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error_code(fn):
    """Call fn(); return its error code and message. An unexpected success raises, so a target that accepts
    what AWS refuses is reported as such rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
    template_body = template
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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _build_export_stack_template(engine: str, role_specs: list[tuple[str, str, bool]], db_id: str, *, ctx) -> dict[str, Any]:
    """role_specs: list of (logical_name, trust_principal, attach_s3_policy)."""
    resources: dict[str, Any] = {
        "Bucket": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Delete"},
        "KmsKey": {
            "Type": "AWS::KMS::Key",
            "DeletionPolicy": "Delete",
            "Properties": {
                "Description": "sim2real rds-s3 export test key",
                "KeyPolicy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "EnableRootPermissions",
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
                            "Action": "kms:*",
                            "Resource": "*",
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
                "Engine": engine,
                "DBInstanceClass": "db.t3.micro",
                "AllocatedStorage": "20",
                "MasterUsername": {"Ref": "MasterUsername"},
                "MasterUserPassword": {"Ref": "MasterUserPassword"},
                "BackupRetentionPeriod": 1,
                "PubliclyAccessible": False,
                "DBSubnetGroupName": _network_db_subnet_group(ctx, ctx.client("rds")),
            },
        },
    }
    outputs: dict[str, Any] = {
        "BucketName": {"Value": {"Ref": "Bucket"}},
        "KmsKeyArn": {"Value": {"Fn::GetAtt": ["KmsKey", "Arn"]}},
    }
    for logical, principal, attach_policy in role_specs:
        role: dict[str, Any] = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
                    ],
                }
            },
        }
        if attach_policy:
            role["Properties"]["Policies"] = [
                {
                    "PolicyName": "S3ExportAccess",
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
                                    "s3:GetBucketLocation",
                                ],
                                "Resource": [
                                    {"Fn::GetAtt": ["Bucket", "Arn"]},
                                    {"Fn::Sub": "${Bucket.Arn}/*"},
                                ],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                                "Resource": {"Fn::GetAtt": ["KmsKey", "Arn"]},
                            },
                        ],
                    },
                }
            ]
        resources[logical] = role
        outputs[f"{logical}Arn"] = {"Value": {"Fn::GetAtt": [logical, "Arn"]}}

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterUserPassword": {"Type": "String", "NoEcho": True, "MinLength": 8},
        },
        "Resources": resources,
        "Outputs": outputs,
    }


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
