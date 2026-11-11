"""cli-rds-create-snapshot-export-to-s3-workflow."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-rds-create-snapshot-export-to-s3-workflow"
GROUP = "cli-workflow"
SERVICES = ["rds", "s3"]

_NET_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]
_PROPAGATION_CODES = ("IamRoleNotFound", "IamRoleMissingPermissions", "KMSKeyNotAccessibleFault")


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """aws rds create-db-snapshot + aws rds start-export-task delivers export objects to S3."""
    require_tools("aws")

    rds = ctx.client("rds")
    s3 = ctx.client("s3")

    bucket = _create_export_bucket(ctx)
    key_id, key_arn = _create_kms_key(ctx)
    role_arn = _create_export_role(ctx, bucket, key_arn, grant_s3=True)
    db_id = _create_source_db_instance(ctx, _private_db_subnet_group(ctx))

    snap_id = ctx.unique_name("sim2real-rds-snap-")
    _run_aws(
        ctx,
        "rds", "create-db-snapshot",
        "--db-snapshot-identifier", snap_id,
        "--db-instance-identifier", db_id,
        timeout_s=30.0,
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _poll_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200.0, interval_s=20.0, desc=f"snapshot {snap_id} available",
    )
    snap_arn = snap["DBSnapshotArn"]

    export_id = ctx.unique_name("sim2real-rds-export-")
    _run_aws_retrying(
        ctx,
        "rds", "start-export-task",
        "--export-task-identifier", export_id,
        "--source-arn", snap_arn,
        "--s3-bucket-name", bucket,
        "--iam-role-arn", role_arn,
        "--kms-key-id", key_id,
        call_timeout_s=30.0, deadline_s=120.0, interval_s=10.0,
        desc="start-export-task (waiting on IAM role/policy propagation)",
    )
    ctx.on_cleanup(lambda: _best_effort_cancel_export(rds, export_id))

    task = _poll_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=export_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("COMPLETE", "FAILED", "CANCELED"),
        timeout_s=1800.0, interval_s=30.0, desc=f"export task {export_id} terminal",
    )
    assert task["Status"] == "COMPLETE", f"export task ended in {task['Status']!r}, not COMPLETE"

    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"{export_id}/")
    assert listing.get("KeyCount", 0) > 0, (
        f"export task reported COMPLETE but no objects found under s3://{bucket}/{export_id}/"
    )


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


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _run_aws_retrying(ctx, *args: str, call_timeout_s=30.0, deadline_s=120.0, interval_s=10.0, desc="command"):
    """Retry an `aws` invocation for up to `deadline_s`, only while it fails with a
    propagation code.

    IAM and KMS are eventually consistent: the role, its policy and the key this check just
    created may not yet be visible to RDS, so the first attempt(s) can fail with one of
    `_PROPAGATION_CODES` even though the setup is correct. Any other failure is raised at once.
    """
    deadline = time.monotonic() + deadline_s
    while True:
        proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=call_timeout_s, check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        transient = any(f"({code})" in proc.stderr for code in _PROPAGATION_CODES)
        if not transient or time.monotonic() >= deadline:
            raise AssertionError(
                f"{desc} failed (rc={proc.returncode}): {proc.stderr[-500:]}"
            )
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


def _best_effort_cancel_export(rds, export_id: str) -> None:
    # A completed task refuses cancel (InvalidExportTaskStateFault); done once it is gone or terminal.
    deadline = time.monotonic() + 600.0
    while True:
        try:
            rds.cancel_export_task(ExportTaskIdentifier=export_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ExportTaskNotFound":
                return
            if code != "InvalidExportTaskStateFault":
                raise
        tasks = rds.describe_export_tasks(ExportTaskIdentifier=export_id).get("ExportTasks", [])
        if not tasks or tasks[0]["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"export task {export_id} still {tasks[0]['Status']} after 600 s")
        time.sleep(2.0)


def _create_export_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-export-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is the one region S3's CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    """Teardown: run an EC2 delete, retrying DependencyViolation until the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except botocore.exceptions.ClientError as exc:
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
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    rds.get_waiter("db_instance_deleted").wait(
        DBInstanceIdentifier=db_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


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
    ctx.on_cleanup(lambda: _drop_db_instance(rds, db_id))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1800.0, interval_s=30.0, desc=f"db instance {db_id} available",
    )
    return db_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
