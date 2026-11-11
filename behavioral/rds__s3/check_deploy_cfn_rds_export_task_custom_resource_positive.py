"""deploy-cfn-rds-export-task-custom-resource-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-rds-export-task-custom-resource-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]

_DB_PASSWORD = "Sim2Real-CustomRes-2024!"

_LAMBDA_SOURCE = """
import json
import time
import urllib.request
import boto3
import botocore.exceptions


def handler(event, context):
    props = event.get('ResourceProperties', {})
    response_data = {}
    status = 'SUCCESS'
    reason = 'OK'
    physical_id = event.get('PhysicalResourceId') or props.get('ExportTaskIdentifier', 'noop')
    try:
        if event['RequestType'] == 'Create':
            rds = boto3.client('rds')
            # The IAM role and KMS key this custom resource depends on were created moments
            # earlier in the same stack; StartExportTask can transiently see them as not yet
            # propagated. Retry the specific transient fault, bounded, rather than fail the
            # export on an AWS-side propagation race.
            deadline = time.time() + 150
            while True:
                try:
                    rds.start_export_task(
                        ExportTaskIdentifier=props['ExportTaskIdentifier'],
                        SourceArn=props['SourceArn'],
                        S3BucketName=props['BucketName'],
                        IamRoleArn=props['RoleArn'],
                        KmsKeyId=props['KmsKeyId'],
                    )
                    break
                except botocore.exceptions.ClientError as ce:
                    code = ce.response.get('Error', {}).get('Code', '')
                    if code == 'KMSKeyNotAccessibleFault' and time.time() < deadline:
                        time.sleep(5)
                        continue
                    raise
            physical_id = props['ExportTaskIdentifier']
            response_data['S3Arn'] = 'arn:aws:s3:::' + props['BucketName']
    except Exception as exc:
        status = 'FAILED'
        reason = str(exc)
    body = json.dumps({
        'Status': status,
        'Reason': reason,
        'PhysicalResourceId': physical_id,
        'StackId': event['StackId'],
        'RequestId': event['RequestId'],
        'LogicalResourceId': event['LogicalResourceId'],
        'Data': response_data,
    }).encode('utf-8')
    req = urllib.request.Request(event['ResponseURL'], data=body, method='PUT', headers={'Content-Type': ''})
    urllib.request.urlopen(req)
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda-backed custom resource fired at stack CREATE time calls StartExportTask using
    an S3 bucket ARN resolved from a CFN !Ref, and the CFN Output's resolved ARN matches the
    bucket that was actually created; the triggered export task also completes and delivers."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    db_id = _xname(ctx, "db")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="admin",
        MasterUserPassword=_DB_PASSWORD,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        MultiAZ=False,
        Tags=_xsvc_tags_kv(),
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, db_id))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"],
        lambda s: s in {"available", "failed", "incompatible-parameters"},
        timeout_s=1200.0,
        interval_s=20.0,
        description=f"DB instance {db_id} available",
    )

    snapshot_id = _xname(ctx, "snap")
    rds.create_db_snapshot(DBInstanceIdentifier=db_id, DBSnapshotIdentifier=snapshot_id, Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snapshot_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0],
        lambda s: s["Status"] in {"available", "failed"},
        timeout_s=1500.0,
        interval_s=20.0,
        description=f"snapshot {snapshot_id} available",
    )
    assert snap["Status"] == "available", f"snapshot {snapshot_id} ended status {snap['Status']!r}, expected 'available'"

    export_task_id = _xname(ctx, "export")
    template = _template()
    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "SnapshotArn": snap["DBSnapshotArn"],
            "ExportTaskId": export_task_id,
        },
        timeout_s=600.0,
    )
    outputs = result["outputs"]
    bucket_name = outputs["BucketName"]
    resolved_arn = outputs["ResolvedS3Arn"]
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_name))

    assert resolved_arn == f"arn:aws:s3:::{bucket_name}", (
        f"custom resource resolved S3 ARN {resolved_arn!r} does not match the actual bucket {bucket_name!r}"
    )

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)["ExportTasks"][0],
        lambda t: t["Status"] in {"COMPLETE", "FAILED", "CANCELED"},
        timeout_s=2400.0,
        interval_s=30.0,
        description=f"export task {export_task_id} terminal",
    )
    assert task["Status"] == "COMPLETE", f"custom-resource-triggered export ended {task['Status']}: {task.get('FailureCause')}"
    listing = s3.list_objects_v2(Bucket=bucket_name, Prefix=export_task_id)
    assert listing.get("KeyCount", 0) > 0, "export task reported COMPLETE but wrote no S3 objects"


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


def _delete_instance(rds, db_id: str) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise


def _delete_snapshot(rds, snapshot_id: str) -> None:
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise


def _template() -> dict:
    bucket_logical, key_logical, role_logical = "ExportBucket", "ExportKey", "ExportRole"
    lambda_role_logical, lambda_logical, cr_logical = "TriggerRole", "TriggerFunction", "TriggerResource"

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SnapshotArn": {"Type": "String"},
            "ExportTaskId": {"Type": "String"},
        },
        "Resources": {
            bucket_logical: {"Type": "AWS::S3::Bucket"},
            key_logical: {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": "sim2real custom-resource export key",
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
                    "Policies": [
                        {
                            "PolicyName": "ExportPolicy",
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
                                            {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}"},
                                            {"Fn::Sub": "arn:aws:s3:::${" + bucket_logical + "}/*"},
                                        ],
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
                                        "Resource": {"Fn::GetAtt": [key_logical, "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            lambda_role_logical: {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                    "Policies": [
                        {
                            "PolicyName": "TriggerExportPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": ["rds:StartExportTask", "iam:PassRole"], "Resource": "*"},
                                    {
                                        "Effect": "Allow",
                                        "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*"],
                                        "Resource": {"Fn::GetAtt": [key_logical, "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            lambda_logical: {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": [lambda_role_logical, "Arn"]},
                    "Timeout": 180,
                    "Code": {"ZipFile": _LAMBDA_SOURCE},
                },
            },
            cr_logical: {
                "Type": "Custom::RdsExportTrigger",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": [lambda_logical, "Arn"]},
                    "ExportTaskIdentifier": {"Ref": "ExportTaskId"},
                    "SourceArn": {"Ref": "SnapshotArn"},
                    "BucketName": {"Ref": bucket_logical},
                    "RoleArn": {"Fn::GetAtt": [role_logical, "Arn"]},
                    "KmsKeyId": {"Ref": key_logical},
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": bucket_logical}},
            "ResolvedS3Arn": {"Value": {"Fn::GetAtt": [cr_logical, "S3Arn"]}},
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
        timeout_s=300,
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
        reasons = []
        try:
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]:
                if e.get("ResourceStatus", "").endswith("FAILED") and e.get("ResourceStatusReason"):
                    reasons.append(f"{e['LogicalResourceId']}: {e['ResourceStatusReason']}")
        except ClientError:
            pass
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {reasons}")
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
