"""cli-rds-export-invalid-bucket-name-negative."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-export-invalid-bucket-name-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

_NET_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """`aws rds start-export-task` to a bucket that does not exist fails with the exact error output and
    creates no task, while the same command to a real bucket completes and writes objects."""
    require_tools("aws")

    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    good_bucket = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, good_bucket, key_arn, grant_s3=True)
    subnet_group = _private_db_subnet_group(ctx)
    db_id = _create_source_db_instance(ctx, subnet_group)
    snap_id, snap_arn = _create_snapshot(ctx, db_id)

    nonexistent_bucket = ctx.unique_name("sim2real-rds-nosuchbucket-")
    export_bad = ctx.unique_name("sim2real-rds-export-bad-")

    bad_proc = _start_export_task_cli(
        ctx, export_bad, snap_arn, nonexistent_bucket, role_arn, key_id,
        terminal_codes=("InvalidS3BucketFault",),
    )
    assert bad_proc.returncode != 0, (
        f"start-export-task naming a non-existent bucket unexpectedly succeeded: {bad_proc.stdout!r}"
    )
    expected_stderr = (
        "aws: [ERROR]: An error occurred (InvalidS3BucketFault) when calling the StartExportTask "
        f"operation: The S3 bucket {nonexistent_bucket} isn't valid. Either it isn't located in "
        "the current AWS Region or it doesn't exist."
    )
    assert bad_proc.stderr.strip() == expected_stderr, (
        f"expected stderr {expected_stderr!r}, got rc={bad_proc.returncode} stderr={bad_proc.stderr!r}"
    )

    # The effect must be absent: no export task was ever created for this identifier.
    all_ids = {
        t["ExportTaskIdentifier"]
        for t in rds.describe_export_tasks().get("ExportTasks", [])
    }
    assert export_bad not in all_ids, (
        f"start-export-task with a non-existent bucket raised InvalidS3BucketFault yet created task {export_bad}"
    )

    # --- positive control: identical request against the real, existing bucket ---
    export_good = ctx.unique_name("sim2real-rds-export-good-")
    good_proc = _start_export_task_cli(
        ctx, export_good, snap_arn, good_bucket, role_arn, key_id,
        terminal_codes=(),
    )
    assert good_proc.returncode == 0, (
        f"positive-control start-export-task failed: rc={good_proc.returncode} stderr={good_proc.stderr!r}"
    )
    good_task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=export_good)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800.0, interval_s=30.0, desc=f"export task {export_good} terminal",
    )
    assert good_task["Status"] == "COMPLETE", (
        f"positive-control export task ended in {good_task['Status']!r}, expected COMPLETE"
    )
    good_listing = s3.list_objects_v2(Bucket=good_bucket, Prefix=f"{export_good}/")
    assert good_listing.get("KeyCount", 0) > 0, "positive-control export task COMPLETE but wrote no objects"


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _start_export_task_cli(ctx, task_id, source_arn, bucket, role_arn, kms_key_id,
                            *, terminal_codes, timeout_s=90.0, interval_s=5.0):
    """Retry the CLI start-export-task call while the IAM/KMS grants attached moments
    earlier are still propagating -- a fresh role or key can transiently surface as
    IamRoleNotFound/KMSKeyNotAccessibleFault/AccessDenied before AWS's own view catches
    up. Returns as soon as the call succeeds or fails with a code in *terminal_codes*
    (a deterministic, non-transient answer); any other failure is retried until the
    deadline, then returned as-is so the caller's own assertion reports it."""
    deadline = time.monotonic() + timeout_s
    while True:
        proc = _run_shell(
            ctx,
            ["aws", "--output", "json",
             "rds", "start-export-task",
             "--export-task-identifier", task_id,
             "--source-arn", source_arn,
             "--s3-bucket-name", bucket,
             "--iam-role-arn", role_arn,
             "--kms-key-id", kms_key_id],
            timeout_s=30.0,
            check=False,
        )
        if proc.returncode == 0 or any(code in proc.stderr for code in terminal_codes):
            return proc
        if time.monotonic() >= deadline:
            return proc
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not satisfied within {timeout_s}s (last observed: {last})")


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is the one region where S3 rejects an explicit LocationConstraint --
    # not a region pin, just the CreateBucket API's own quirk.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]},
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_kms_key(ctx) -> tuple[str, str]:
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=ctx.unique_name("sim2real-rds-export-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["KeyId"], meta["Arn"]


def _create_export_role(ctx, bucket_name: str, kms_key_arn: str, *, grant_s3: bool = True) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-export-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "export.rds.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
        "Sid": "KmsAccess",
        "Effect": "Allow",
        "Action": ["kms:CreateGrant", "kms:DescribeKey", "kms:Decrypt", "kms:GenerateDataKey*"],
        "Resource": kms_key_arn,
    }]
    if grant_s3:
        statements.append({
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": ["s3:PutObject*", "s3:GetObject*", "s3:ListBucket", "s3:DeleteObject*", "s3:GetBucketLocation"],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        })
    policy_name = ctx.unique_name("sim2real-rds-export-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Role"]["Arn"]


def _delete_with_retry(fn, *, timeout_s=600.0, interval_s=15.0):
    """Run an EC2 delete, retrying DependencyViolation until the deadline."""
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
    """Wait out RDS ENIs left in a subnet of this check's own VPC after the instance is gone."""
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


def _create_source_db_instance(ctx, subnet_group: str) -> str:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-src-")
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="mysql",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername="sim2realadmin",
        MasterUserPassword="Sim2RealPwd1!",
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        BackupRetentionPeriod=1,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    def _drop_instance():
        try:
            rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBInstanceNotFound":
                raise
        rds.get_waiter("db_instance_deleted").wait(
            DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
        )

    ctx.on_cleanup(_drop_instance)
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1800.0, interval_s=30.0, desc=f"db instance {db_id} available",
    )
    return db_id


def _create_snapshot(ctx, db_id: str) -> tuple[str, str]:
    rds = ctx.client("rds")
    snap_id = ctx.unique_name("sim2real-rds-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id,
        DBInstanceIdentifier=db_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200.0, interval_s=20.0, desc=f"snapshot {snap_id} available",
    )
    return snap_id, snap["DBSnapshotArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
