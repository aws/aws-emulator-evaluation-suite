"""rds-s3-export-kms-key-mismatch-negative."""
from __future__ import annotations

import json
import time
import uuid

import botocore.exceptions

from behavioral_harness import tags

CHECK = "rds-s3-export-kms-key-mismatch-negative"
GROUP = "snapshot-export"
SERVICES = ["rds", "s3"]

_NET_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]
# Role/policy and new-bucket propagation, and the snapshot's lock held by this check's prior export.
_RETRY_CODES = (
    "IamRoleMissingPermissions",
    "IamRoleNotFound",
    "InvalidS3BucketFault",
    "ExportTaskAlreadyExists",
)
# The positive control also waits out the role's grant on its key propagating.
_POSITIVE_RETRY_CODES = _RETRY_CODES + ("KMSKeyNotAccessibleFault",)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExportTask with a KMS key the export role is not granted on fails with KMSKeyNotAccessibleFault
    and writes no S3 object; the same task with the granted key completes (positive control).
    """
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    kms = ctx.client("kms")

    bucket = _create_bucket(ctx, s3)
    granted_key_arn = _create_kms_key(ctx, kms)
    denying_key_arn = _create_kms_key(ctx, kms, policy=_deny_grant_and_describe_policy(ctx))
    snapshot_arn = _create_snapshot(ctx, rds, _private_db_subnet_group(ctx))

    # The role's policy grants kms:CreateGrant/DescribeKey on granted_key_arn only.
    role_arn = _create_export_role(ctx, iam, bucket, granted_key_arn)

    denied_task_id = ctx.unique_name("sim2real-rds-export-kms-denied-")
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(rds, denied_task_id))
    error = _start_export_refusal(
        rds,
        ExportTaskIdentifier=denied_task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=denying_key_arn,
        S3Prefix="kms-denied-attempt",
    )
    assert error["Code"] == "KMSKeyNotAccessibleFault", (
        f"expected KMSKeyNotAccessibleFault for a key whose policy denies grant and describe, got {error!r}"
    )
    expected_message = f"The KMS key {denying_key_arn} doesn't exist or is disabled."
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )
    # Nothing else has written to this bucket yet, so any object at all means the
    # refused task leaked output.
    leaked = _list_objects(s3, bucket, prefix="")
    assert leaked == [], f"expected no S3 objects after a refused export, found {leaked!r}"

    # Positive control: same role/snapshot/bucket, using the key the role IS granted on ->
    # the export completes, with its objects visible at the destination (an independent
    # read, not the mutating call's own response).
    ok_task = _run_export_to_terminal(
        ctx,
        rds,
        snapshot_arn=snapshot_arn,
        bucket=bucket,
        role_arn=role_arn,
        kms_key_id=granted_key_arn,
        s3_prefix="kms-ok-attempt",
    )
    assert ok_task["Status"] == "COMPLETE", (
        f"positive-control export did not complete: status={ok_task['Status']} "
        f"cause={ok_task.get('FailureCause')}"
    )
    assert ok_task["PercentProgress"] == 100, (
        f"expected PercentProgress 100 at COMPLETE, got {ok_task['PercentProgress']!r}"
    )
    ok_objects = _list_objects(s3, bucket, prefix="kms-ok-attempt")
    assert ok_objects, "expected S3 objects under the positive-control export prefix"


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-rds-export-")
    if ctx.region == "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint for us-east-1.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        contents = page.get("Contents", [])
        if contents:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            )
    s3.delete_bucket(Bucket=bucket)


def _deny_grant_and_describe_policy(ctx) -> str:
    """A key policy that keeps the account's own administration of the key and denies
    kms:CreateGrant and kms:DescribeKey to every principal."""
    return json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AccountAdministration",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "DenyGrantAndDescribe",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    })


def _create_kms_key(ctx, kms, *, policy=None):
    kwargs = {"Policy": policy} if policy is not None else {}
    key = kms.create_key(
        Description="sim2real RDS snapshot export test key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "rds-s3-behavioral"}],
        **kwargs,
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_arn


def _create_export_role(ctx, iam, bucket, key_arn, *, s3_actions=None, extra_kms=True):
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
    role_name = ctx.unique_name("sim2real-rds-exp-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [
        {
            "Sid": "S3Access",
            "Effect": "Allow",
            "Action": s3_actions
            if s3_actions is not None
            else [
                "s3:PutObject*",
                "s3:ListBucket",
                "s3:GetObject*",
                "s3:DeleteObject*",
                "s3:GetBucketLocation",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }
    ]
    if extra_kms:
        statements.append(
            {
                "Sid": "KmsAccess",
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


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


def _create_snapshot(ctx, rds, subnet_group: str):
    instance_id = ctx.unique_name("sim2real-rds-exp-")
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2Real-" + uuid.uuid4().hex[:12],
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        PubliclyAccessible=False,
        DBSubnetGroupName=subnet_group,
        MultiAZ=False,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: _drop_db_instance(rds, instance_id))
    _wait_db_instance_available(rds, instance_id)

    snapshot_id = ctx.unique_name("sim2real-rds-exp-snap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snapshot_id,
        DBInstanceIdentifier=instance_id,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))
    snapshot = _wait_snapshot_available(rds, snapshot_id)
    return snapshot["DBSnapshotArn"]


def _wait_db_instance_available(rds, instance_id, timeout_s=2400.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=instance_id)
        status = resp["DBInstances"][0]["DBInstanceStatus"]
        if status == "available":
            return resp["DBInstances"][0]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(f"DB instance {instance_id} entered terminal status {status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"DB instance {instance_id} did not become available within {timeout_s}s (last={status})"
    )


def _wait_snapshot_available(rds, snapshot_id, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)
        snap = resp["DBSnapshots"][0]
        status = snap["Status"]
        if status == "available":
            return snap
        if status == "failed":
            raise AssertionError(f"snapshot {snapshot_id} failed")
        time.sleep(interval_s)
    raise AssertionError(
        f"snapshot {snapshot_id} did not become available within {timeout_s}s (last={status})"
    )


def _wait_export_task_terminal(rds, export_task_id, timeout_s=1800.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    task = None
    while time.monotonic() < deadline:
        resp = rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)
        task = resp["ExportTasks"][0]
        if task["Status"] in ("COMPLETE", "FAILED", "CANCELED"):
            return task
        time.sleep(interval_s)
    raise AssertionError(
        f"export task {export_task_id} did not reach a terminal status within {timeout_s}s "
        f"(last={task['Status'] if task else None})"
    )


def _start_export(rds, *, retry_codes, timeout_s=600.0, interval_s=15.0, **kwargs):
    """Starts an export task, retrying only while StartExportTask fails with one of
    `retry_codes`: a freshly created role/policy can take a short time to propagate (see
    https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency),
    and the snapshot stays locked by a prior export for a few minutes after that export is
    terminal. Any other refusal is raised at once."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in retry_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _start_export_refusal(rds, *, timeout_s=600.0, interval_s=15.0, **kwargs) -> dict:
    """The `Error` member of the StartExportTask refusal, waiting out only `_RETRY_CODES`
    (role/policy and bucket propagation); a call that is accepted fails the check."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = rds.start_export_task(**kwargs)
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] in _RETRY_CODES and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return exc.response["Error"]
        raise AssertionError(f"expected StartExportTask to be refused, but it was accepted: {result!r}")


def _run_export_to_terminal(ctx, rds, *, snapshot_arn, bucket, role_arn, kms_key_id, s3_prefix):
    """Starts an export task, which StartExportTask must accept, and returns its terminal
    describe_export_tasks record."""
    task_id = ctx.unique_name(f"sim2real-rds-export-{s3_prefix}-")
    _start_export(
        rds,
        retry_codes=_POSITIVE_RETRY_CODES,
        ExportTaskIdentifier=task_id,
        SourceArn=snapshot_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
        S3Prefix=s3_prefix,
    )
    ctx.on_cleanup(lambda: _cancel_export_task_quietly(rds, task_id))
    return _wait_export_task_terminal(rds, task_id)


def _cancel_export_task_quietly(rds, export_task_id):
    """Teardown: cancel the export if it is still running and wait until it is terminal, so
    the snapshot behind it can be deleted."""
    try:
        rds.cancel_export_task(ExportTaskIdentifier=export_task_id)
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidExportTaskStateFault", "ExportTaskNotFound"):
            raise
    if not rds.describe_export_tasks(ExportTaskIdentifier=export_task_id)["ExportTasks"]:
        return
    _wait_export_task_terminal(rds, export_task_id)


def _list_objects(s3, bucket, prefix):
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
