"""deploy-rds-cluster-s3-export-cross-resource-reference-positive."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-rds-cluster-s3-export-cross-resource-reference-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack output from Fn::GetAtt resolves the bucket ARN that the export role's policy names, and a
    cluster snapshot export with that role completes and writes objects to the bucket."""
    started = time.monotonic()
    rds = ctx.client("rds")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    cluster_id = _xname(ctx, "aur")
    template = _build_cluster_export_stack_template(cluster_id, ctx=ctx)
    password = secrets.token_urlsafe(12)
    stack = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"MasterUsername": "dbadmin", "MasterUserPassword": password},
        timeout_s=1500,
    )
    outputs = stack["outputs"]
    bucket = outputs["BucketName"]
    bucket_arn_via_getatt = outputs["BucketArnFromGetAtt"]
    role_arn = outputs["ExportRoleArn"]
    kms_arn = outputs["KmsKeyArn"]
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    # The Fn::GetAtt-resolved ARN in the stack output must equal the ARN independently derived
    # from the live bucket name -- if CFN's intrinsic-function resolution were wrong, these
    # would diverge even though "the stack deployed cleanly".
    assert bucket_arn_via_getatt == f"arn:aws:s3:::{bucket}"

    role_name = role_arn.split("/")[-1]
    policy = iam.get_role_policy(RoleName=role_name, PolicyName="S3ExportAccess")["PolicyDocument"]
    policy_resources = policy["Statement"][0]["Resource"]
    assert bucket_arn_via_getatt in policy_resources, (
        f"role policy resources {policy_resources!r} do not contain the Fn::GetAtt-resolved "
        f"bucket ARN {bucket_arn_via_getatt!r}"
    )

    snap_id = _xname(ctx, "csnap")
    rds.create_db_cluster_snapshot(DBClusterIdentifier=cluster_id, DBClusterSnapshotIdentifier=snap_id)
    ctx.on_cleanup(lambda: rds.delete_db_cluster_snapshot(DBClusterSnapshotIdentifier=snap_id))
    snapshot = _poll_until(
        lambda: rds.describe_db_cluster_snapshots(DBClusterSnapshotIdentifier=snap_id)["DBClusterSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200,
        interval_s=15.0,
        description=f"cluster snapshot {snap_id} available",
    )
    snap_arn = snapshot["DBClusterSnapshotArn"]

    task_id = _xname(ctx, "exp")
    rds.start_export_task(
        ExportTaskIdentifier=task_id,
        SourceArn=snap_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_arn,
    )
    ctx.on_cleanup(lambda: _cancel_export_if_running(rds, task_id))
    # A snapshot export can stay in STARTING for a long time, so the wait uses what is left of
    # a 5,100 s window measured from the start of the check, with a floor of 600 s.
    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=max(600.0, 5100.0 - (time.monotonic() - started)),
        interval_s=15.0,
        description=f"export task {task_id} terminal",
    )
    assert task["Status"] == "COMPLETE", f"export task ended in {task['Status']}: {task}"

    objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
    assert len(objects) > 0, "cluster snapshot export completed but landed no objects in the bucket"


def _cancel_export_if_running(rds, task_id, timeout_s=600.0):
    """Cancel an export still running at teardown and wait until it stops writing to the bucket."""
    task = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
    if task["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
        return
    rds.cancel_export_task(ExportTaskIdentifier=task_id)
    _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]["Status"],
        lambda st: st in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"export task {task_id} stopped",
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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str, timeout_s: float = 700.0) -> None:
    """Delete the stack and wait until it is gone. A first delete that ends DELETE_FAILED (a
    resource still held by one that is deleting) is retried once; then the failed resources and
    their reasons are raised."""
    cfn = ctx.client("cloudformation")

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if "does not exist" in e.response["Error"].get("Message", ""):
                return "GONE"
            raise

    status = None
    for _ in range(2):
        cfn.delete_stack(StackName=stack_name)
        status = _poll_until(
            _status,
            lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
            timeout_s=timeout_s,
            interval_s=15.0,
            description=f"delete stack {stack_name}",
        )
        if status != "DELETE_FAILED":
            return
    reasons = [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}"
        for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        if e["ResourceStatus"] == "DELETE_FAILED"
    ][:5]
    raise AssertionError(f"stack {stack_name} ended {status}: {reasons}")


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
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})


def _build_cluster_export_stack_template(cluster_id: str, *, ctx) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterUserPassword": {"Type": "String", "NoEcho": True, "MinLength": 8},
        },
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "DeletionPolicy": "Delete"},
            "KmsKey": {
                "Type": "AWS::KMS::Key",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Description": "sim2real aurora cluster export test key",
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
            "ExportRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                                        # Cross-resource reference: this ARN comes from Fn::GetAtt
                                        # on the Bucket resource declared above, in this same stack.
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
                    ],
                },
            },
            "DbCluster": {
                "Type": "AWS::RDS::DBCluster",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBClusterIdentifier": cluster_id,
                    "Engine": "aurora-mysql",
                    "MasterUsername": {"Ref": "MasterUsername"},
                    "MasterUserPassword": {"Ref": "MasterUserPassword"},
                    "BackupRetentionPeriod": 1,
                    "DBSubnetGroupName": _network_db_subnet_group(ctx, ctx.client("rds")),
                },
            },
            "DbInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "DBClusterIdentifier": {"Ref": "DbCluster"},
                    "Engine": "aurora-mysql",
                    "DBInstanceClass": "db.t3.medium",
                    "PubliclyAccessible": False,
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "BucketArnFromGetAtt": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
            "ExportRoleArn": {"Value": {"Fn::GetAtt": ["ExportRole", "Arn"]}},
            "KmsKeyArn": {"Value": {"Fn::GetAtt": ["KmsKey", "Arn"]}},
        },
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
