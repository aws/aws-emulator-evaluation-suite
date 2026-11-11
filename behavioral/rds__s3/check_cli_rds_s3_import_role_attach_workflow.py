"""cli-rds-s3-import-role-attach-workflow."""
from __future__ import annotations

import json
import subprocess
import time

from botocore.exceptions import ClientError
import uuid

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-rds-s3-import-role-attach-workflow"
GROUP = "cli-s3-import-role"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An IAM role trusting rds.amazonaws.com with an S3 read policy, attached via aws rds
    add-role-to-db-instance --feature-name s3Import, shows up ACTIVE in the DB instance's
    AssociatedRoles as reported by describe-db-instances."""
    require_tools("aws")

    bucket, bucket_arn = _create_import_bucket(ctx)
    role_arn = _create_s3_import_role(ctx, bucket_arn)

    db_instance_id = ctx.unique_name("sim2real-rds-imp-")
    _create_postgres_instance(ctx, db_instance_id)
    _wait_db_instance_available(ctx, db_instance_id)

    _run_aws(
        ctx,
        "rds",
        "add-role-to-db-instance",
        "--db-instance-identifier",
        db_instance_id,
        "--feature-name",
        "s3Import",
        "--role-arn",
        role_arn,
    )
    ctx.on_cleanup(
        lambda: ctx.client("rds").remove_role_from_db_instance(
            DBInstanceIdentifier=db_instance_id, RoleArn=role_arn, FeatureName="s3Import"
        )
    )

    assoc = _wait_role_associated(ctx, db_instance_id, role_arn)
    assert assoc["Status"] == "ACTIVE", f"expected ACTIVE, got {assoc['Status']!r}: {assoc}"
    assert assoc["FeatureName"] == "s3Import", (
        f"expected feature-name s3Import, got {assoc['FeatureName']!r}"
    )
    assert assoc["RoleArn"] == role_arn, f"expected role {role_arn!r}, got {assoc['RoleArn']!r}"


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


def _create_import_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-rds-import-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    s3.put_object(Bucket=bucket, Key="seed/data.csv", Body=b"id,value\n1,hello\n2,world\n")
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


def _create_s3_import_role(ctx, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rds-s3import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_name = "s3-read-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "s3import",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
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


def _wait_role_associated(ctx, db_instance_id, role_arn, timeout_s=300.0, interval_s=10.0):
    rds = ctx.client("rds")

    def probe():
        inst = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)["DBInstances"][0]
        for assoc in inst.get("AssociatedRoles", []):
            if assoc.get("RoleArn") == role_arn:
                return assoc
        return None

    def done(assoc):
        if assoc is None:
            return False
        if assoc["Status"] == "INVALID":
            raise AssertionError(f"role association went INVALID: {assoc}")
        return assoc["Status"] == "ACTIVE"

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


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
