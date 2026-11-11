"""rds-associate-iam-role-for-s3-export-positive."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError
from typing import Any

from behavioral_harness import tags

CHECK = "rds-associate-iam-role-for-s3-export-positive"
GROUP = "arn-resolution"
SERVICES = ["rds", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance(FeatureName=s3Export) associates the role and it surfaces in
    DescribeDBInstances AssociatedRoles with an ACTIVE status once RDS finishes processing it."""
    bucket = _create_bucket(ctx)
    role_arn = _create_iam_role(
        ctx,
        trust_principal="rds.amazonaws.com",
        policy_statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            }
        ],
        name_prefix="sim2real-rds-s3export-role-",
    )
    db_id, _arn = _create_db_instance(ctx)

    rds = ctx.client("rds")
    rds.add_role_to_db_instance(
        DBInstanceIdentifier=db_id, RoleArn=role_arn, FeatureName="s3Export"
    )

    entry = _poll_role_entry_active(ctx, db_id, role_arn, "s3Export", timeout_s=300.0)
    assert entry["RoleArn"] == role_arn, f"expected RoleArn={role_arn}, got {entry.get('RoleArn')!r}"
    assert entry["FeatureName"] == "s3Export", (
        f"expected FeatureName=s3Export, got {entry.get('FeatureName')!r}"
    )
    assert entry["Status"] == "ACTIVE", f"expected ACTIVE, got {entry['Status']!r}"

    # Independent re-read through a fresh describe_db_instances call: confirms the
    # association is stably visible (not a one-shot artifact of the polling read) and
    # that RDS has not fanned it out into duplicate entries.
    instance = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
    matches = [
        r
        for r in instance.get("AssociatedRoles", [])
        if r.get("RoleArn") == role_arn and r.get("FeatureName") == "s3Export"
    ]
    assert len(matches) == 1, (
        f"expected exactly one s3Export association for RoleArn={role_arn}, found {len(matches)}"
    )
    assert matches[0]["Status"] == "ACTIVE", (
        f"expected ACTIVE on independent re-read, got {matches[0].get('Status')!r}"
    )


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-rds-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "Name", "Value": name}]})
    return name


def _create_iam_role(
    ctx: Any, trust_principal: str, policy_statements: list[dict[str, Any]], name_prefix: str
) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(name_prefix)
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-policy"
    policy_doc = {"Version": "2012-10-17", "Statement": policy_statements}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_db_instance(ctx: Any) -> tuple[str, str]:
    rds = ctx.client("rds")
    db_id = ctx.unique_name("sim2real-rds-s3-")
    password = "Pg1" + secrets.token_hex(8) + "Aa"
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="pgadmin1",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        MultiAZ=False,
        BackupRetentionPeriod=0,
        StorageType="gp2",
        Tags=[{"Key": "Name", "Value": db_id}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(DBInstanceIdentifier=db_id, SkipFinalSnapshot=True))
    instance = _wait_db_available(ctx, db_id)
    return db_id, instance["DBInstanceArn"]


def _wait_db_available(ctx: Any, db_id: str, timeout_s: float = 1800.0, interval_s: float = 15.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instance = resp["DBInstances"][0]
        status = instance["DBInstanceStatus"]
        if status == "available":
            return instance
        if status in ("failed", "incompatible-restore", "incompatible-network"):
            raise AssertionError(f"DB instance entered unexpected status {status}")
        time.sleep(interval_s)
    raise AssertionError(f"DB instance {db_id} did not become available within {timeout_s}s")


def _find_role_entry(instance_desc: dict, role_arn: str, feature_name: str) -> dict | None:
    for entry in instance_desc.get("AssociatedRoles", []):
        if entry.get("RoleArn") == role_arn and entry.get("FeatureName") == feature_name:
            return entry
    return None


def _poll_role_entry_active(
    ctx: Any, db_id: str, role_arn: str, feature_name: str, timeout_s: float = 300.0, interval_s: float = 10.0
) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last: dict | None = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        entry = _find_role_entry(resp["DBInstances"][0], role_arn, feature_name)
        last = entry
        # ACTIVE and INVALID are RDS's only terminal states for a role/feature
        # association; stop on either rather than spinning to the deadline on a
        # deterministic rejection, and let the caller's own assertion fail on INVALID.
        if entry is not None and entry.get("Status") in ("ACTIVE", "INVALID"):
            return entry
        time.sleep(interval_s)
    raise AssertionError(
        f"role/feature association for RoleArn={role_arn} FeatureName={feature_name} "
        f"did not reach a terminal status within {timeout_s}s (last={last!r})"
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
