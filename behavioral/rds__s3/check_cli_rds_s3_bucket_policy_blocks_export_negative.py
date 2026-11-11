"""cli-rds-s3-bucket-policy-blocks-export-negative."""
from __future__ import annotations

import json
import re
import subprocess
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-s3-bucket-policy-blocks-export-negative"
GROUP = "cli-snapshot-export"
SERVICES = ["rds", "s3"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket policy Deny of the export role makes start-export-task fail synchronously with
    IamRoleMissingPermissions, with no task and no objects under its prefix, while the same
    export to a bucket without the Deny completes and lands objects."""
    require_tools("aws")

    key_id, key_arn = _create_kms_key(ctx)
    denied_bucket, denied_arn = _create_export_bucket(ctx, "sim2real-rds-export-denied-")
    control_bucket, control_arn = _create_export_bucket(ctx, "sim2real-rds-export-ctrl-")

    role_arn = _create_export_role(ctx, [denied_arn, control_arn], key_arn)
    _deny_role_on_bucket(ctx, denied_bucket, denied_arn, role_arn)

    db_instance_id = ctx.unique_name("sim2real-rds-negpol-")
    _create_postgres_instance(ctx, db_instance_id)
    _wait_db_instance_available(ctx, db_instance_id)

    snapshot_id = ctx.unique_name("sim2real-snap-negpol-")
    snapshot_arn = _create_snapshot_and_wait(ctx, db_instance_id, snapshot_id)

    denied_task_id = ctx.unique_name("sim2real-export-denied-")
    control_task_id = ctx.unique_name("sim2real-export-ctrl-")

    # (a): the StartExportTask call itself is rejected -- RDS never gets as far as creating a
    # task, so there is no async FAILED status to poll for.
    error_code, error_message = _start_export_task_expect_rejection(
        ctx,
        export_task_id=denied_task_id,
        source_arn=snapshot_arn,
        bucket=denied_bucket,
        role_arn=role_arn,
        key_id=key_id,
    )
    assert error_code == "IamRoleMissingPermissions", (
        f"expected StartExportTask against the denied bucket to reject with "
        f"IamRoleMissingPermissions, got {error_code}"
    )
    # The denied S3 action named in the message varies between runs; the rest is stable.
    assert error_message.startswith(f"The IAM role {role_arn} isn't authorized to call s3:"), error_message
    assert error_message.endswith(f" on the S3 bucket {denied_bucket}."), error_message

    # (b): the task was never created, and nothing was ever written under its prefix.
    _assert_export_task_never_created(ctx, denied_task_id)
    denied_listing = _run_aws(
        ctx, "s3", "ls", f"s3://{denied_bucket}/{denied_task_id}/", "--recursive", check=False
    )
    assert denied_listing == "" or denied_listing == {}, (
        f"export delivered objects despite the bucket-policy Deny: {denied_listing}"
    )

    # (c) positive control: identical role/snapshot against a bucket without the deny
    # statement completes and lands real objects.
    _start_export_task_with_retry(
        ctx,
        export_task_id=control_task_id,
        source_arn=snapshot_arn,
        bucket=control_bucket,
        role_arn=role_arn,
        key_id=key_id,
    )
    control_task = _wait_export_task(ctx, control_task_id)
    assert control_task["Status"] == "COMPLETE", (
        f"control export ended in {control_task['Status']}: {control_task.get('FailureCause')}"
    )
    control_listing = _run_aws(
        ctx, "s3", "ls", f"s3://{control_bucket}/{control_task_id}/", "--recursive"
    )
    assert isinstance(control_listing, str) and control_listing.strip(), (
        f"positive control export produced no S3 objects: {control_listing!r}"
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
        ctx, ["aws", "--output", "json", "--no-cli-pager", *args], timeout_s=timeout_s, check=check
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_export_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    # us-east-1 is the one region where S3 CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket, f"arn:aws:s3:::{bucket}"


def _delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
    s3.delete_bucket(Bucket=bucket)


def _deny_role_on_bucket(ctx, bucket, bucket_arn, role_arn):
    s3 = ctx.client("s3")
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyExportRole",
                "Effect": "Deny",
                "Principal": {"AWS": role_arn},
                "Action": "s3:*",
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    _put_bucket_policy_with_retry(s3, bucket, policy)


def _put_bucket_policy_with_retry(s3, bucket, policy_doc, timeout_s=60.0):
    """Put a bucket policy naming a just-created role as Principal, retrying the transient
    MalformedPolicy ("Invalid principal in policy") until the role propagates through IAM."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy_doc))
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if (
                code == "MalformedPolicy"
                and "principal" in msg.lower()
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            raise


def _create_kms_key(ctx):
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description="sim2real behavioral rds export bucket-policy-negative key",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return key_id, key_arn


def _create_export_role(ctx, bucket_arns, key_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-exp-role-negpol-")
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
    policy_name = "s3-export-access"
    resources = []
    for bucket_arn in bucket_arns:
        resources.append(bucket_arn)
        resources.append(f"{bucket_arn}/*")
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
                "Resource": resources,
            },
            {
                "Effect": "Allow",
                "Action": ["kms:CreateGrant", "kms:DescribeKey"],
                "Resource": key_arn,
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_postgres_instance(ctx, db_instance_id):
    rds = ctx.client("rds")
    password = f"S2r{uuid.uuid4().hex[:12]}Aa1"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="behavadmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=db_instance_id, SkipFinalSnapshot=True)
    )
    return password


def _wait_db_instance_available(ctx, db_instance_id, timeout_s=1500.0, interval_s=20.0):
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)["DBInstances"][0]

    def done(inst):
        status = inst["DBInstanceStatus"]
        if status in ("failed", "incompatible-parameters", "incompatible-network"):
            raise AssertionError(f"DB instance {db_instance_id} entered status {status}")
        return status == "available"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _create_snapshot_and_wait(ctx, db_instance_id, snapshot_id, timeout_s=900.0, interval_s=15.0):
    rds = ctx.client("rds")
    rds.create_db_snapshot(DBInstanceIdentifier=db_instance_id, DBSnapshotIdentifier=snapshot_id)
    ctx.on_cleanup(lambda: rds.delete_db_snapshot(DBSnapshotIdentifier=snapshot_id))

    def probe():
        return rds.describe_db_snapshots(DBSnapshotIdentifier=snapshot_id)["DBSnapshots"][0]

    def done(snap):
        if snap["Status"] == "failed":
            raise AssertionError(f"snapshot {snapshot_id} failed")
        return snap["Status"] == "available"

    snap = _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)
    return snap["DBSnapshotArn"]


def _start_export_task_with_retry(
    ctx, *, export_task_id, source_arn, bucket, role_arn, key_id, timeout_s=90.0, interval_s=10.0
):
    """Run start-export-task via the CLI, retrying while IAM role propagation catches up. The role
    is valid for the account, so IamRoleNotFound here is transient propagation."""
    args = [
        "aws",
        "--output",
        "json",
        "--no-cli-pager",
        "rds",
        "start-export-task",
        "--export-task-identifier",
        export_task_id,
        "--source-arn",
        source_arn,
        "--s3-bucket-name",
        bucket,
        "--iam-role-arn",
        role_arn,
        "--kms-key-id",
        key_id,
    ]
    deadline = time.monotonic() + timeout_s
    last_stderr = ""
    while time.monotonic() < deadline:
        proc = _run_shell(ctx, args, check=False)
        if proc.returncode == 0:
            return json.loads(proc.stdout) if proc.stdout.strip() else {}
        last_stderr = proc.stderr
        if "IamRoleNotFound" not in proc.stderr and "IamRoleMissingPermissions" not in proc.stderr:
            raise AssertionError(f"start-export-task failed unexpectedly: {proc.stderr[-500:]}")
        time.sleep(interval_s)
    raise AssertionError(
        f"start-export-task kept failing on IAM propagation after {timeout_s}s: {last_stderr[-500:]}"
    )


def _wait_export_task(ctx, task_id, timeout_s=1800.0, interval_s=30.0):
    rds = ctx.client("rds")

    def probe():
        return rds.describe_export_tasks(ExportTaskIdentifier=task_id)["ExportTasks"][0]

    def done(task):
        return task["Status"] in ("COMPLETE", "FAILED", "CANCELED")

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


def _start_export_task_expect_rejection(
    ctx, *, export_task_id, source_arn, bucket, role_arn, key_id, timeout_s=90.0, interval_s=10.0
):
    """Call start-export-task against a bucket this role is denied on, retrying only the transient
    IamRoleNotFound of an unpropagated role; any other rejection (such as the Deny's
    IamRoleMissingPermissions) is returned immediately as (code, message)."""
    args = [
        "aws",
        "--output",
        "json",
        "--no-cli-pager",
        "rds",
        "start-export-task",
        "--export-task-identifier",
        export_task_id,
        "--source-arn",
        source_arn,
        "--s3-bucket-name",
        bucket,
        "--iam-role-arn",
        role_arn,
        "--kms-key-id",
        key_id,
    ]
    deadline = time.monotonic() + timeout_s
    while True:
        proc = _run_shell(ctx, args, check=False)
        if proc.returncode == 0:
            raise AssertionError(
                f"start-export-task unexpectedly succeeded against the denied bucket: {proc.stdout}"
            )
        code, message = _extract_error(proc.stderr)
        if code == "IamRoleNotFound" and time.monotonic() < deadline:
            time.sleep(interval_s)
            continue
        return code, message


def _extract_error(stderr: str) -> tuple[str, str]:
    match = re.search(r"An error occurred \((\w+)\) when calling the \w+ operation: (.*)", stderr)
    if not match:
        raise AssertionError(f"could not parse an AWS error from CLI stderr: {stderr[-500:]}")
    return match.group(1), match.group(2).strip()


def _assert_export_task_never_created(ctx, task_id):
    """Assert no export task exists: a non-matching --export-task-identifier filter returns rc=0
    with an empty ExportTasks list rather than raising ExportTaskNotFoundFault."""
    proc = _run_shell(
        ctx,
        [
            "aws",
            "--output",
            "json",
            "--no-cli-pager",
            "rds",
            "describe-export-tasks",
            "--export-task-identifier",
            task_id,
        ],
        check=False,
    )
    if proc.returncode != 0:
        assert "ExportTaskNotFoundFault" in proc.stderr, (
            f"unexpected error looking up an export task that was never created: {proc.stderr[-300:]}"
        )
        return
    tasks = json.loads(proc.stdout)["ExportTasks"] if proc.stdout.strip() else []
    assert tasks == [], (
        f"expected no export task to exist for a StartExportTask call that was rejected, found {tasks}"
    )


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
