"""export-task-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags
import secrets

CHECK = "export-task-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartExportTask transitions STARTING/IN_PROGRESS visible via DescribeExportTasks; CancelExportTask stops it."""
    rds = ctx.client("rds")
    s3 = ctx.client("s3")
    kms = ctx.client("kms")
    ctx.client("iam")

    # The DB instance (~5-10 min to become available) is this check's dominant cost and has no
    # dependency on the S3 bucket / KMS key / IAM role below -- issue its creation FIRST so that
    # setup work (bucket/key/role, including the role's IAM-propagation sleep) overlaps with the
    # instance's provisioning instead of serializing strictly before it. This check has a bounded
    # overall runtime budget for heavy multi-resource RDS provisioning.
    sng = _subnet_group(ctx)
    inst_id = ctx.unique_name("sim2real-expsrc-")
    rds.create_db_instance(
        DBInstanceIdentifier=inst_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Aa1!" + secrets.token_urlsafe(18),
        AllocatedStorage=20,
        DBSubnetGroupName=sng,
        BackupRetentionPeriod=1,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_instance(rds, inst_id))

    bucket = ctx.unique_name("sim2real-exp-bkt-").lower()
    if ctx.region == "us-east-1":
        # S3 quirk, not a region pin: CreateBucket rejects an explicit LocationConstraint
        # for us-east-1 (its own name is the implicit default), so it must be omitted here.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key_id = kms.create_key(
        Description="sim2real rds export task key",
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    role_arn = _create_role(ctx, "export.rds.amazonaws.com", {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject*", "s3:GetObject*", "s3:ListBucket", "s3:DeleteObject*", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    })

    _wait_until(
        lambda: _describe_instance_tolerant(rds, inst_id),
        lambda i: i is not None and i["DBInstanceStatus"] == "available",
        timeout_s=1800, interval_s=20, desc="instance available",
    )

    snap_id = ctx.unique_name("sim2real-expsnap-")
    rds.create_db_snapshot(
        DBSnapshotIdentifier=snap_id, DBInstanceIdentifier=inst_id,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_snapshot(rds, snap_id))

    snap = _wait_until(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id)["DBSnapshots"][0],
        lambda s: s["Status"] == "available",
        timeout_s=1200, interval_s=20, desc="snapshot available",
    )

    task_id = ctx.unique_name("sim2real-export-")
    _start_export_with_retry(
        rds, ExportTaskIdentifier=task_id, SourceArn=snap["DBSnapshotArn"], S3BucketName=bucket,
        IamRoleArn=role_arn, KmsKeyId=key_id,
    )

    observed_statuses = set()

    def _probe():
        t = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
        observed_statuses.add(t["Status"])
        return t

    _wait_until(
        _probe,
        lambda t: t["Status"] in ("IN_PROGRESS", "COMPLETE", "FAILED"),
        timeout_s=1800, interval_s=20, desc="export task left STARTING",
    )
    assert observed_statuses & {"STARTING", "IN_PROGRESS", "COMPLETE"}, observed_statuses

    try:
        rds.cancel_export_task(ExportTaskIdentifier=task_id)
    except ClientError as e:
        # If the export already finished before we could cancel it, that's still a valid
        # terminal state for this fast, near-empty snapshot; nothing left to cancel.
        assert e.response["Error"]["Code"] == "InvalidExportTaskStateFault"
        message = e.response["Error"].get("Message")
        assert message == f"The export {task_id} can\u2019t be canceled.", (
            f"unexpected InvalidExportTaskStateFault message {message!r}"
        )
        final = rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]
        assert final["Status"] == "COMPLETE"
        return

    final = _wait_until(
        lambda: rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0],
        lambda t: t["Status"] in ("CANCELED", "COMPLETE", "FAILED"),
        timeout_s=300, interval_s=10, desc="export task canceled",
    )
    # An accepted CancelExportTask stops the export: it ends CANCELED, never COMPLETE.
    assert final["Status"] == "CANCELED", (
        f"expected an export whose cancel was accepted to end CANCELED, got {final['Status']!r}"
    )


def _wait_until(probe, predicate, timeout_s, interval_s=20, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last}")
        time.sleep(interval_s)


def _wait_gone(probe, not_found_codes, timeout_s, interval_s=20, desc="deletion"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as e:
            if e.response["Error"]["Code"] in not_found_codes:
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}")
        time.sleep(interval_s)


def _describe_instance_tolerant(rds, inst_id):
    # DescribeDBInstances can transiently raise DBInstanceNotFound for a brief window right
    # after CreateDBInstance returns, before the new instance's metadata has propagated to the
    # read path. Treat that as "not ready yet" rather than a real failure.
    try:
        return rds.describe_db_instances(DBInstanceIdentifier=inst_id)["DBInstances"][0]
    except ClientError as e:
        if e.response["Error"]["Code"] == "DBInstanceNotFound":
            return None
        raise


def _start_export_with_retry(rds, timeout_s=180, interval_s=15, **kwargs):
    # IAM/KMS permissions can lag briefly after role/key creation.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.start_export_task(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("InvalidParameterValue", "AccessDenied", "KMSAccessDeniedFault") \
                    or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _subnet_group(ctx, name_prefix="sim2real-sng-"):

    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to build a DB subnet group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not span enough AZs for a DB subnet group")
    name = ctx.unique_name(name_prefix)
    rds.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real behavioral check subnet group",
        SubnetIds=subnet_ids[:3],
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _create_role(ctx, service_principal, policy_document, role_name_prefix="sim2real-exprole-"):
    iam = ctx.client("iam")
    name = ctx.unique_name(role_name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": service_principal}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    pname = f"{name}-policy"
    iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(policy_document))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=pname))
    # No settle here: the caller's own dependent call (_start_export_with_retry) retries the
    # real IAM/KMS-propagation errors on a bounded deadline, and it isn't even issued until after
    # the DB instance and snapshot both finish provisioning (minutes away), by which point IAM
    # propagation has long since caught up.
    return role["Arn"]


def _empty_and_delete_bucket(s3, bucket):
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _delete_snapshot(rds, snap_id):
    try:
        rds.delete_db_snapshot(DBSnapshotIdentifier=snap_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBSnapshotNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_snapshots(DBSnapshotIdentifier=snap_id),
        {"DBSnapshotNotFound"}, timeout_s=300, interval_s=10, desc=f"snapshot {snap_id} deleted",
    )


def _delete_instance(rds, inst_id):
    try:
        rds.delete_db_instance(DBInstanceIdentifier=inst_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBInstanceNotFound":
            raise
        return
    _wait_gone(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=inst_id),
        {"DBInstanceNotFound"}, timeout_s=1200, interval_s=20, desc=f"instance {inst_id} deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
