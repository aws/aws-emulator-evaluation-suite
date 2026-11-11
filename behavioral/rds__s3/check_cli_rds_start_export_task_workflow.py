"""cli-rds-start-export-task-workflow."""
from __future__ import annotations

import json
import secrets
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-rds-start-export-task-workflow"
GROUP = "sdk-cli-interop"
SERVICES = ["rds", "s3"]

_NET_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws rds start-export-task` (CLI) followed by SDK polling confirms objects land in S3."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_name, role_arn = _create_export_role(ctx, bucket)
    key_id = _create_kms_key(ctx, role_arn)
    instance_id = _create_source_instance(ctx, _private_db_subnet_group(ctx))
    snapshot_arn = _create_snapshot(ctx, instance_id)

    task_id = ctx.unique_name("sim2real-rds-cli-task-")
    stdout = _run_aws_with_retry(
        ctx,
        [
            "rds",
            "start-export-task",
            "--export-task-identifier",
            task_id,
            "--source-arn",
            snapshot_arn,
            "--s3-bucket-name",
            bucket,
            "--iam-role-arn",
            role_arn,
            "--kms-key-id",
            key_id,
            "--export-only",
            "mysql",
            "--output",
            "json",
        ],
    )
    cli_result = json.loads(stdout)
    assert cli_result["ExportTaskIdentifier"] == task_id, (
        f"CLI echoed task id {cli_result.get('ExportTaskIdentifier')!r}, expected {task_id!r}"
    )
    assert cli_result["Status"] in ("STARTING", "IN_PROGRESS"), (
        f"CLI-started export task reported status {cli_result.get('Status')!r}, "
        "expected STARTING or IN_PROGRESS immediately after start-export-task"
    )

    # Hand off to the SDK to poll for the workflow's completion.
    task = _wait_export_terminal(ctx, task_id)
    assert task["Status"] == "COMPLETE", (
        f"export task did not complete: status={task['Status']} cause={task.get('FailureCause')}"
    )

    s3 = ctx.client("s3")
    keys = _list_all_keys(s3, bucket)
    assert keys, "CLI-started export task reported COMPLETE but no objects landed in S3"
    assert any(k.endswith(".parquet") for k in keys), f"no parquet objects found: {keys[:10]}"


def _run_aws_with_retry(ctx, args: list[str]) -> str:
    env = ctx.subprocess_env()
    cmd = ["aws", *args, "--region", ctx.region]
    deadline = time.monotonic() + 120
    while True:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout
        if "IamRoleMissingPermissions" in proc.stderr and time.monotonic() < deadline:
            time.sleep(2)
            continue
        raise AssertionError(f"aws CLI failed (rc={proc.returncode}): {proc.stderr}")


def _wait_for(probe, predicate, timeout_s, interval_s, desc):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {desc}; last-seen={last!r}")


def _list_all_keys(s3, bucket, prefix=""):
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-cli-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_export_role(ctx, bucket_name) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-cli-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "export.rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-export-access", PolicyDocument=json.dumps(policy_doc)
    )
    return role_name, role_arn


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _create_kms_key(ctx, role_arn) -> str:
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowExportRoleUse",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": [
                    "kms:CreateGrant",
                    "kms:DescribeKey",
                    "kms:GenerateDataKey*",
                    "kms:Decrypt",
                    "kms:Encrypt",
                ],
                "Resource": "*",
            },
        ],
    }
    # The role principal above was just created; KMS's own policy validation lags IAM's
    # eventual consistency and rejects it as "invalid" for a short window after creation.
    deadline = time.monotonic() + 60
    while True:
        try:
            resp = kms.create_key(
                Description="sim2real rds->s3 cli-interop test key",
                Policy=json.dumps(policy),
                Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
            )
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if (
                code == "MalformedPolicyDocumentException"
                and "invalid principal" in str(exc).lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id


def _gen_password() -> str:
    return "Aa1!" + secrets.token_urlsafe(12)


def _delete_with_retry(fn, *, timeout_s=600.0, interval_s=15.0):
    """Teardown: run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _await_enis_clear(ec2, subnet_id, timeout_s=900.0, interval_s=15.0):
    """Teardown: wait out RDS ENIs left in a subnet of this check's own VPC after the instance is gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "subnet-id", "Values": [subnet_id]}]
        )["NetworkInterfaces"]
        if not enis:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"subnet {subnet_id} still has {len(enis)} ENI(s) after {timeout_s}s: "
                f"{[e['NetworkInterfaceId'] for e in enis]}"
            )
        time.sleep(interval_s)


def _private_db_subnet_group(ctx) -> str:
    """A two-AZ VPC this check creates for the private source instance, and the DB subnet
    group over it. Every piece is registered for cleanup as it is created."""
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    ]
    assert len(azs) >= 2, f"region {ctx.region!r} has only {len(azs)} available AZ(s); need 2"
    vpc_id = ec2.create_vpc(
        CidrBlock="10.203.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _NET_TAGS}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    subnet_ids = []
    for i, az in enumerate(azs[:2]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.203.0.{i * 64}/26",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _NET_TAGS}],
        )["Subnet"]["SubnetId"]

        def _drop_subnet(sid=subnet_id):
            _await_enis_clear(ec2, sid)
            _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=sid))

        ctx.on_cleanup(_drop_subnet)
        subnet_ids.append(subnet_id)

    name = ctx.unique_name("sim2real-rds-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real rds export source subnet group",
        SubnetIds=subnet_ids,
        Tags=_NET_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _drop_db_instance(rds, db_id: str) -> None:
    """Teardown: delete the instance with no final snapshot and wait until it is gone, so the
    subnet group and subnets under it can be deleted after it."""
    try:
        rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


def _create_source_instance(ctx, subnet_group: str) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-cli-src-")
    rds.create_db_instance(
        DBInstanceIdentifier=identifier,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        MasterUsername="admin",
        MasterUserPassword=_gen_password(),
        AllocatedStorage=20,
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _drop_db_instance(rds, identifier))
    _wait_for(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=identifier)["DBInstances"][0],
        lambda inst: inst["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=30,
        desc=f"instance {identifier} available",
    )
    return identifier


def _create_snapshot(ctx, instance_id) -> str:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-cli-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _wait_for(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=20,
        desc=f"snapshot {snap_id} available",
    )
    return snap["DBSnapshotArn"]


def _wait_export_terminal(ctx, task_id, timeout_s=1800, interval_s=20):
    rds = ctx.client("rds")
    return _wait_for(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        desc=f"export task {task_id} terminal",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
