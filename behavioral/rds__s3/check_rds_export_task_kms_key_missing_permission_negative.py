"""rds-export-task-kms-key-missing-permission-negative."""
from __future__ import annotations

import json
import secrets
import time
from typing import Any

import botocore.exceptions

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-export-task-kms-key-missing-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["rds", "s3"]

_NET_TAGS = [{"Key": "sim2real", "Value": "rds-s3-behavioral"}]


@tags("axis:rejection", "cap:c2", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartExportTask with a KMS key whose policy denies kms:CreateGrant and kms:DescribeKey is rejected
    with KMSKeyNotAccessibleFault and writes nothing, while a permitted key exports the same snapshot
    to COMPLETE with objects."""
    bucket = _create_bucket(ctx)
    role_name, role_arn = _create_export_role(ctx, bucket)
    denied_key_id = _create_kms_key(ctx, role_arn, deny_grant_and_describe=True)
    ok_key_id = _create_kms_key(ctx, role_arn, deny_grant_and_describe=False)
    instance_id = _create_source_instance(ctx, _private_db_subnet_group(ctx))
    snapshot_arn = _create_snapshot(ctx, instance_id)
    s3 = ctx.client("s3")

    bad_task_id = ctx.unique_name("sim2real-rds-kmsdeny-bad-")
    bad_prefix = "kms-denied-attempt"
    error = _client_error(
        lambda: _start_export(
            ctx, bad_task_id, snapshot_arn, bucket, role_arn, denied_key_id, s3_prefix=bad_prefix
        )
    )
    assert error["Code"] == "KMSKeyNotAccessibleFault", (
        f"expected KMSKeyNotAccessibleFault, got {error['Code']}"
    )
    # RDS echoes the key reference as passed (here the key id) and words the denial as absence.
    expected_message = f"The KMS key {denied_key_id} doesn't exist or is disabled."
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )
    assert _list_all_keys(s3, bucket, prefix=bad_prefix) == [], (
        "no objects should have been written when the caller lacks KMS grant/describe permission"
    )

    good_task_id = ctx.unique_name("sim2real-rds-kmsdeny-good-")
    good_prefix = "kms-allowed-attempt"
    _start_export_with_retry(
        ctx,
        good_task_id,
        snapshot_arn,
        bucket,
        role_arn,
        ok_key_id,
        s3_prefix=good_prefix,
        export_only=["mysql"],
    )
    task = _wait_export_terminal(ctx, good_task_id)
    assert task["Status"] == "COMPLETE", (
        f"positive-control export did not complete: status={task['Status']} "
        f"cause={task.get('FailureCause')}"
    )
    assert _list_all_keys(s3, bucket, prefix=good_prefix), (
        "expected objects under the positive-control (accessible KMS key) export prefix"
    )


def _client_error(fn) -> dict:
    """The `Error` member of the ClientError `fn` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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
    name = ctx.unique_name("sim2real-rds-kmsdeny-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
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
    role_name = ctx.unique_name("sim2real-rds-kmsdeny-role-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_kms_key(ctx, role_arn, *, deny_grant_and_describe: bool) -> str:
    kms = ctx.client("kms")
    statements = [
        {
            "Sid": "EnableRootAccess",
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
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
    ]
    if deny_grant_and_describe:
        statements.append(
            {
                "Sid": "DenyGrantAndDescribe",
                "Effect": "Deny",
                "Principal": {"AWS": "*"},
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            }
        )
    policy = {"Version": "2012-10-17", "Statement": statements}
    # A role/caller ARN referenced as a Principal right after creation can be rejected by KMS
    # ("...one or more invalid principals") until IAM propagation catches up; bounded retry, not
    # a fixed sleep.
    deadline = time.monotonic() + 60
    while True:
        try:
            resp = kms.create_key(
                Description="sim2real rds->s3 kms-negative test key", Policy=json.dumps(policy)
            )
            break
        except botocore.exceptions.ClientError as err:
            if (
                err.response["Error"]["Code"] == "MalformedPolicyDocumentException"
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


def _create_source_instance(ctx, subnet_group: str) -> str:
    rds = ctx.client("rds")
    identifier = ctx.unique_name("sim2real-rds-kmsdeny-src-")
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
        Tags=_NET_TAGS,
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
    snap_id = ctx.unique_name("sim2real-rds-kmsdeny-snap-")
    rds.create_db_snapshot(DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=instance_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id))
    snap = _wait_for(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=900,
        interval_s=20,
        desc=f"snapshot {snap_id} available",
    )
    return snap["DBSnapshotArn"]


def _start_export(
    ctx, task_id, source_arn, bucket, role_arn, kms_key_id, s3_prefix=None, export_only=None
):
    rds = ctx.client("rds")
    kwargs: dict[str, Any] = dict(
        ExportTaskIdentifier=task_id,
        SourceArn=source_arn,
        S3BucketName=bucket,
        IamRoleArn=role_arn,
        KmsKeyId=kms_key_id,
    )
    if s3_prefix is not None:
        kwargs["S3Prefix"] = s3_prefix
    if export_only is not None:
        kwargs["ExportOnly"] = export_only
    return rds.start_export_task(**kwargs)


def _start_export_with_retry(
    ctx, task_id, source_arn, bucket, role_arn, kms_key_id, s3_prefix=None, export_only=None
):
    deadline = time.monotonic() + 120
    while True:
        try:
            return _start_export(
                ctx,
                task_id,
                source_arn,
                bucket,
                role_arn,
                kms_key_id,
                s3_prefix=s3_prefix,
                export_only=export_only,
            )
        except botocore.exceptions.ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "IamRoleMissingPermissions" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


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
