"""rds-associate-iam-role-for-s3-import-positive."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "rds-associate-iam-role-for-s3-import-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance associates an S3-access IAM role with an RDS instance and the
    association converges to ACTIVE, enabling the s3Import feature for aws_s3 functions."""
    bucket = _create_bucket(ctx)
    role_arn = _create_s3_role(ctx, bucket, ["s3:GetObject", "s3:ListBucket"])
    db_id = _create_postgres_instance(ctx)

    role = _add_role_and_wait(ctx, db_id, role_arn, "s3Import")
    assert role["Status"] == "ACTIVE", f"expected ACTIVE, got {role['Status']}"
    assert role["RoleArn"] == role_arn
    assert role["FeatureName"] == "s3Import"

    rds = ctx.client("rds")
    inst = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    found = [r for r in inst.get("AssociatedRoles", []) if r["RoleArn"] == role_arn]
    assert len(found) == 1
    assert found[0]["Status"] == "ACTIVE"
    assert found[0]["FeatureName"] == "s3Import"


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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _add_role_with_retry(rds, db_id, role_arn, feature_name, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName=feature_name)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"AddRoleToDBInstance did not succeed within {timeout_s}s "
        f"(freshly-created IAM role/policy propagation, last error={last_exc!r})"
    )


def _add_role_and_wait(ctx, db_id, role_arn, feature_name, timeout_s=600):
    rds = ctx.client("rds")
    _add_role_with_retry(rds, db_id, role_arn, feature_name)

    def _cleanup():
        try:
            rds.remove_role_from_db_instance(DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName=feature_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DBInstanceNotFound",
                "DBInstanceRoleNotFound",
            ):
                raise

    ctx.on_cleanup(_cleanup)

    def _probe():
        roles = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0].get("AssociatedRoles", [])
        for r in roles:
            if r["RoleArn"] == role_arn and r["FeatureName"] == feature_name:
                return r
        return None

    return _poll_until(
        _probe,
        lambda r: r is not None and r["Status"] in ("ACTIVE", "INVALID"),
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
