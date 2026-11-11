"""cli-rds-associate-role-s3-import-workflow."""
from __future__ import annotations

import json
import subprocess
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cli-rds-associate-role-s3-import-workflow"
GROUP = "sdk-cli-interop"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """`aws rds add-role-to-db-instance` performed via the CLI is visible through the SDK's
    describe_db_instances as a converged, ACTIVE AssociatedRoles entry -- the CLI and SDK
    observe the same underlying control-plane state."""
    from fidelity_tests_runner import require_tools

    require_tools("aws")

    bucket = _create_bucket(ctx)
    role_arn = _create_s3_role(ctx, bucket, ["s3:GetObject", "s3:ListBucket"])
    db_id = _create_postgres_instance(ctx)

    out = _run_aws(
        ctx,
        "rds",
        "add-role-to-db-instance",
        "--db-instance-identifier",
        db_id,
        "--feature-name",
        "s3Import",
        "--role-arn",
        role_arn,
    )
    assert out.strip() == "" or out.strip() == "{}", f"unexpected CLI output: {out!r}"

    def _cleanup():
        try:
            ctx.client("rds").remove_role_from_db_instance(
                DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Import"
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DBInstanceNotFound",
                "DBInstanceRoleNotFound",
            ):
                raise

    ctx.on_cleanup(_cleanup)

    role = _wait_role_active(ctx, db_id, role_arn, "s3Import")
    assert role["Status"] == "ACTIVE", f"expected ACTIVE, describe-db-instances reported {role['Status']!r}"
    assert role["RoleArn"] == role_arn, f"expected role {role_arn!r}, describe-db-instances reported {role['RoleArn']!r}"
    assert role["FeatureName"] == "s3Import", f"expected feature 's3Import', describe-db-instances reported {role['FeatureName']!r}"


def _run_aws(ctx, *args):
    cmd = ["aws", *args, "--region", ctx.region, "--output", "json"]
    result = subprocess.run(cmd, env=ctx.subprocess_env(), capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise AssertionError(f"aws CLI command failed: {' '.join(cmd)}\nstderr: {result.stderr}")
    return result.stdout


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0, desc="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{desc} not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rdss3-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_s3_role(ctx, bucket, actions, trust_service="rds.amazonaws.com"):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdss3-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": actions,
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _master_password():
    return "S2r" + uuid.uuid4().hex[:16] + "!Aa"


def _create_postgres_instance(ctx):
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rdss3-pg-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        MasterUsername="s2radmin",
        MasterUserPassword=_master_password(),
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        Tags=[{"Key": "sim2real", "Value": "rds-s3-behavioral"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0],
        lambda i: i["DBInstanceStatus"] == "available",
        timeout_s=1200,
        interval_s=30,
        desc="db instance available",
    )
    return db_id


def _wait_role_active(ctx, db_id, role_arn, feature_name, timeout_s=600):
    rds = ctx.client("rds")

    def _probe():
        roles = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0].get("AssociatedRoles", [])
        for r in roles:
            if r["RoleArn"] == role_arn and r["FeatureName"] == feature_name:
                return r
        return None

    def _done(r):
        if r is not None and r["Status"] == "INVALID":
            raise AssertionError(f"role association for {role_arn!r}/{feature_name!r} went INVALID: {r!r}")
        return r is not None and r["Status"] == "ACTIVE"

    return _poll_until(
        _probe,
        _done,
        timeout_s=timeout_s,
        interval_s=10,
        desc="role association status",
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
